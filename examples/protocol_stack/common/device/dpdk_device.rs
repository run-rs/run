use super::super::iface::{Device, Batch};
use arrayvec::{self, ArrayVec};
#[allow(unused_imports)]
use run_dpdk::*;

pub struct DpdkDevice {
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
    }
    self.recv_batch.swap_pop(0)
  }

  fn send(&mut self,pkt:Mbuf) -> Option<Mbuf> {
    let mut batch = ArrayVec::<Mbuf,1>::new();
    self.txq.tx(&mut batch);
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


pub struct DpdkDeviceHelper {
  
}

impl DpdkDeviceHelper {
  pub fn build(port_id:u16) -> Option<DpdkDevice> {
    if !run_dpdk::try_service().is_ok() {
      Self::init_eal();
    }
    let port_info = run_dpdk::service().port_infos().unwrap();
    if port_id as usize >= port_info.len() {
      return None;
    }
    let port = &port_info[port_id as usize];
    //let rx_pkt_len = port.max_rx_pktlen();
    let max_rx_qs = port.max_rx_queues();
    let max_tx_qs = port.max_tx_queues();
    let mut rxq= None;
    let mut txq= None;
    for i in 0..max_rx_qs {
      rxq = run_dpdk::service().rx_queue(port_id, i).ok();
      if rxq.is_some() {
        break;
      }
    }
    if rxq.is_none() {
      return None;
    }
    for i in 0..max_tx_qs {
      txq = run_dpdk::service().tx_queue(port_id, i).ok();
      if txq.is_some() {
        break;
      }
    }
    if txq.is_none() {
      return None;
    }
    return Some(DpdkDevice { 
                      rxq: rxq.unwrap(), 
                      txq: txq.unwrap(),
                      recv_batch: ArrayVec::new(),
                      mempool: run_dpdk::service().mempool("mp").unwrap()});
  }

  fn init_eal() {
    run_dpdk::DpdkOption::new().init().unwrap();
    let port_id = 0;
    let nb_qs = 16;
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

    Self::init_port(port_id, nb_qs, mp_name, &mut mconf, &mut rxq_conf, &mut txq_conf);
  }

  fn init_port(port_id: u16,
          nb_qs: u32,
          mp_name: &'static str,
          mpconf: &mut run_dpdk::MempoolConf,
          rxq_conf: &mut run_dpdk::RxQueueConf,
          txq_conf: &mut run_dpdk::TxQueueConf) {
    let port_infos = run_dpdk::service().port_infos().unwrap();
    let port_info = &port_infos[port_id as usize];
    let socket_id = port_info.socket_id;

    mpconf.socket_id = socket_id;
    run_dpdk::service().mempool_create(mp_name, mpconf).unwrap();

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

    run_dpdk::service()
             .port_configure(port_id, &pconf, &rxq_confs, &txq_confs)
              .unwrap();

    println!("finish configuration p{}", port_id);
  }
}


#[cfg(test)]
mod dpdk_device_test {
  use super::*;

  #[test]
  fn test_dpdk_device_build() {
    assert!(DpdkDeviceHelper::build(0).is_some());
  }
}