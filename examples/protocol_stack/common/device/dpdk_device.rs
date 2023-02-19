use super::super::{Device, Batch};
use arrayvec::{self, ArrayVec};
#[allow(unused_imports)]
use run_dpdk::*;

pub struct DpdkDevice {
  port_id:u16,
  rxq:run_dpdk::RxQueue,
  txq:run_dpdk::TxQueue,
  recv_batch:ArrayVec<Mbuf,32>,
  mempool:run_dpdk::Mempool,
}

impl Device for DpdkDevice {
  fn alloc(&mut self) -> Option<Mbuf> {
    self.mempool.try_alloc()
  }

  fn recv(&mut self)->Option<Mbuf> {
    if self.recv_batch.is_empty() {
      self.rxq.rx(&mut self.recv_batch);
      self.recv_batch.reverse();
    }
    self.recv_batch.pop()
  }

  fn send(&mut self,pkt:Mbuf) -> Option<Mbuf> {
    let mut batch = ArrayVec::<Mbuf,1>::new();
    batch.push(pkt);
    let n = self.txq.tx(&mut batch);
    log::log!(log::Level::Trace,"dpdk device: send {} packet",n);
    batch.pop()
  }
}

impl Batch for DpdkDevice {
  fn alloc_batch<const N:usize>(&mut self,batch:&mut arrayvec::ArrayVec<Mbuf,N>) {
    self.mempool.fill_batch(batch);
  }

  fn recv_batch<const N:usize>(&mut self,
                                    batch:&mut arrayvec::ArrayVec<Mbuf,N>) {
    self.rxq.rx(batch);
  }

  fn send_batch<const N:usize>(&mut self,
                                    batch:&mut arrayvec::ArrayVec<Mbuf,N>) {
    self.txq.tx(batch);
  }
}


impl DpdkDevice {
  pub fn new(port_id:u16) ->Option<DpdkDevice> {
    if !init_eal(port_id) {
      return None;
    }
    Some(
      DpdkDevice {
        port_id:port_id,
        rxq:service().rx_queue(port_id, 0).unwrap(),
        txq:service().tx_queue(port_id, 0).unwrap(),
        recv_batch:ArrayVec::new(),
        mempool:service().mempool("mp").unwrap(),
      }
    )
  }
}

impl Drop for DpdkDevice {
  fn drop(&mut self) {
    self.recv_batch.clear();
    unsafe{
      std::ptr::drop_in_place(&mut self.txq as *mut TxQueue);
      std::ptr::drop_in_place(&mut self.rxq as *mut RxQueue);
      std::ptr::drop_in_place(&mut self.mempool as *mut Mempool);
    }
    service().port_close(self.port_id).unwrap();
    println!("port closed");

    service().mempool_free("mp").unwrap();
    println!("mempool freed");

    service().service_close().unwrap();
    println!("dpdk service shutdown gracefully");
  }
}

fn init_eal(port_id:u16) -> bool {
  match run_dpdk::DpdkOption::new().enable_quiet().init() {
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

  return init_port(port_id, nb_qs, mp_name, &mut mconf, &mut rxq_conf, &mut txq_conf);
}

fn init_port(port_id: u16,
  nb_qs: u32,
  mp_name: &'static str,
  mpconf: &mut run_dpdk::MempoolConf,
  rxq_conf: &mut run_dpdk::RxQueueConf,
  txq_conf: &mut run_dpdk::TxQueueConf) -> bool {
  
  let port_infos = run_dpdk::service().port_infos().unwrap();
  let port_info = &port_infos[port_id as usize];
  let socket_id = port_info.socket_id;

  mpconf.socket_id = socket_id;
  match run_dpdk::service().mempool_create(mp_name, mpconf) {
    Ok(_) => (),
    Err(err) => {
      log::log!(log::Level::Error,"failed to create mempool `{}` : {}",mp_name,err);
      return false;
    }
  };

  let pconf = run_dpdk::PortConf::from_port_info(port_info).unwrap();

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


#[cfg(test)]
mod dpdk_device_test {
  use super::*;

  #[test]
  fn test_dpdk_device_build() {
    assert!(DpdkDeviceHelper::build(0).is_some());
  }
}
