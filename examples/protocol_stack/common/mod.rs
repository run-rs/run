mod device;
mod socket_buffer;
mod assembler;
mod rand;
pub mod stack;

use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use arrayvec::ArrayVec;
pub use device::DpdkDevice;


pub trait Device {
  fn alloc(&mut self) -> Option<run_dpdk::Mbuf>;
  fn send(&mut self,pkt:run_dpdk::Mbuf) -> Option<run_dpdk::Mbuf>;
  fn recv(&mut self)->Option<run_dpdk::Mbuf>;
}

pub trait Batch {

  fn recv_batch<const N:usize>(&mut self,
                              batch:&mut arrayvec::ArrayVec<run_dpdk::Mbuf,N>);

  fn send_batch<const N:usize>(&mut self,
                              batch:&mut arrayvec::ArrayVec<run_dpdk::Mbuf,N>);

  fn alloc_batch<const N:usize>(&mut self,
                              batch:&mut arrayvec::ArrayVec<run_dpdk::Mbuf,N>);
}

pub trait Stack {
  fn is_close(&self)-> bool;

  fn on_recv(&mut self,pkt:run_dpdk::Mbuf,ts:smoltcp::time::Instant) 
        -> Option<run_dpdk::Mbuf>;
  
  fn has_data(&mut self,ts:smoltcp::time::Instant) -> bool;
  
  fn do_send(&mut self,mp:&mut run_dpdk::Mempool,ts:smoltcp::time::Instant,txq:&mut run_dpdk::TxQueue);
}


pub trait Producer {
  fn produce(&mut self,size:usize) -> Option<&[u8]>;
}

pub trait Consumer {
  fn consume(&mut self,size:usize) -> &mut [u8];
}

fn init_eal(port_id:u16,offload:OFFLOAD) -> bool {
  match run_dpdk::DpdkOption::new().init() {
    Err(err) => {
      log::log!(log::Level::Error,"EAL INIT {}",err);
      return false;
    },
    _ => ()
  };
  let nb_qs = 1;
  let mp_name = "mp";

  let mut mconf = run_dpdk::MempoolConf::default();
  mconf.nb_mbufs = 8192 * 4;
  mconf.per_core_caches = 256;
  mconf.socket_id = 0;

  let mut rxq_conf = run_dpdk::RxQueueConf::default();
  rxq_conf.mp_name = "mp".to_string();
  rxq_conf.nb_rx_desc = 1024;
  rxq_conf.socket_id = 0;
  
  let mut txq_conf = run_dpdk::TxQueueConf::default();
  txq_conf.nb_tx_desc = 1024;
  txq_conf.socket_id = 0;

  return init_port(port_id, nb_qs, mp_name, &mut mconf, &mut rxq_conf, &mut txq_conf,offload);
}

fn init_port(port_id: u16,
  nb_qs: u32,
  mp_name: &'static str,
  mpconf: &mut run_dpdk::MempoolConf,
  rxq_conf: &mut run_dpdk::RxQueueConf,
  txq_conf: &mut run_dpdk::TxQueueConf,
  offload: OFFLOAD) -> bool {
  
  let port_infos = run_dpdk::service().port_infos().unwrap();
  let port_info = &port_infos[port_id as usize];
  let socket_id = port_info.socket_id;


  let tso = offload == OFFLOAD::TSO;
  let lro = offload == OFFLOAD::LRO;
  let ipv4_csum = offload == OFFLOAD::TSO || 
                        offload == OFFLOAD::IPV4_CSUM || 
                        offload == OFFLOAD::IPV4_TCP_CSUM;
  let tcp_csum = offload == OFFLOAD::TSO ||
                       offload == OFFLOAD::IPV4_TCP_CSUM ||
                       offload == OFFLOAD::TCP_CSUM;
  
  mpconf.socket_id = socket_id;
  match run_dpdk::service().mempool_create(mp_name, mpconf) {
    Ok(_) => (),
    Err(err) => {
      log::log!(log::Level::Error,"failed to create mempool `{}` : {}",mp_name,err);
      return false;
    }
  };

  let mut pconf = run_dpdk::PortConf::from_port_info(port_info).unwrap();

  if tso {
    pconf.tx_offloads.enable_multi_segs();
    pconf.tx_offloads.enable_tcp_tso();
    pconf.rx_offloads.enable_scatter();
  }

  if lro {
    pconf.rx_offloads.enable_tcp_lro();
  }

  if ipv4_csum {
    pconf.tx_offloads.enable_ipv4_cksum();
    pconf.rx_offloads.enable_ipv4_cksum();
  }

  if tcp_csum {
    pconf.tx_offloads.enable_tcp_cksum();
    pconf.rx_offloads.enable_tcp_cksum();
  }

  rxq_conf.mp_name = mp_name.to_string();
  rxq_conf.socket_id = socket_id;
  txq_conf.socket_id = socket_id;

  let mut rxq_confs = Vec::new();
  let mut txq_confs = Vec::new();

  for _ in 0..nb_qs {
    rxq_confs.push(rxq_conf.clone());
    txq_confs.push(txq_conf.clone());
  }

  match run_dpdk::service()
            .port_configure(port_id, &pconf, &rxq_confs, &txq_confs) {
    Ok(_) =>(),
    Err(err) => {
      log::log!(log::Level::Error,"failed to configure port `{}` : {}",port_id,err);
      return false;
    }
  }

  println!("finish configuration p{}", port_id);
  true
}

#[derive(PartialEq, Eq)]
pub enum OFFLOAD {
  NONE,
  TSO,
  LRO,
  IPV4_CSUM,
  TCP_CSUM,
  IPV4_TCP_CSUM
}

pub fn poll<S:Stack>(run: Arc<AtomicBool>, port_id:u16,stack:&mut S,offload:OFFLOAD) {
  if !init_eal(port_id,offload) {
    run.store(false, std::sync::atomic::Ordering::Relaxed);
    return;
  }

  let mut rxq = run_dpdk::service().rx_queue(port_id, 0).unwrap();
  let mut txq = run_dpdk::service().tx_queue(port_id, 0).unwrap();
  let mut mp = run_dpdk::service().mempool("mp").unwrap();
  let mut batch:ArrayVec<Mbuf, 32> = ArrayVec::new();
  let mut rbatch:ArrayVec<Mbuf,64> = ArrayVec::new();
  

  while run.load(std::sync::atomic::Ordering::Relaxed) {
    let ts = smoltcp::time::Instant::now();
    rxq.rx(&mut batch);
    for mbuf in batch.drain(..) {
      log::log!(log::Level::Trace,"received a packet, diliver to stack");
      if let Some(resp) = stack.on_recv(mbuf, ts) {
        unsafe {
          rbatch.push_unchecked(resp);
        }
      }
    }
    while !rbatch.is_empty() {
      txq.tx(&mut rbatch);
    }

    if stack.has_data(ts) {
      stack.do_send(&mut mp, ts, &mut txq);
    }
  }
}

use run_dpdk::Mbuf;
pub use run_packet::ether::ETHER_HEADER_LEN;
pub use run_packet::ipv4::IPV4_HEADER_LEN;
pub use run_packet::tcp::TCP_HEADER_LEN;
pub use run_packet::ether::MacAddr;
pub use run_packet::ipv4::Ipv4Addr;