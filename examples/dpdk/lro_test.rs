use std::sync::{atomic::AtomicBool, atomic::Ordering, Arc};

use arrayvec::ArrayVec;
use ctrlc;
use run_dpdk::offload::*;
use run_dpdk::*;
use run_packet::ether::*;
use run_packet::ipv4::*;
use run_packet::tcp::*;
use run_packet::udp::*;
use run_packet::Buf;
use run_packet::CursorMut;

#[allow(dead_code)]
fn init_port(
  port_id: u16,
  nb_qs: u32,
  mp_name: &'static str,
  mpconf: &mut MempoolConf,
  rxq_conf: &mut RxQueueConf,
  txq_conf: &mut TxQueueConf,
) {
  let port_infos = service().port_infos().unwrap();
  let port_info = &port_infos[port_id as usize];
  let socket_id = port_info.socket_id;

  mpconf.socket_id = socket_id;
  service().mempool_create(mp_name, mpconf).unwrap();

  let mut pconf = PortConf::from_port_info(port_info).unwrap();
  // pconf.mtu = 9000;
  pconf.rx_offloads.enable_scatter();
  pconf.rx_offloads.enable_tcp_lro();
  pconf.rx_offloads.enable_tcp_cksum();
  pconf.rx_offloads.enable_ipv4_cksum();

  rxq_conf.mp_name = mp_name.to_string();
  rxq_conf.socket_id = socket_id;
  txq_conf.socket_id = socket_id;
  let mut rxq_confs = Vec::new();
  let mut txq_confs = Vec::new();
  for _ in 0..nb_qs {
    rxq_confs.push(rxq_conf.clone());
    txq_confs.push(txq_conf.clone());
  }

  service()
    .port_configure(port_id, &pconf, &rxq_confs, &txq_confs)
    .unwrap();

  println!("finish configuring p{}", port_id);
}

fn main() {
  DpdkOption::new().init().unwrap();

  let port_id = 0;
  let nb_qs = 1;
  let mp_name = "mp";
  let mut mpconf = MempoolConf::default();
  mpconf.nb_mbufs = 8192 * 4;
  mpconf.per_core_caches = 256;
  let mut rxq_conf = RxQueueConf::default();
  rxq_conf.nb_rx_desc = 1024;
  let mut txq_conf = TxQueueConf::default();
  txq_conf.nb_tx_desc = 1024;
  init_port(
    port_id,
    nb_qs,
    mp_name,
    &mut mpconf,
    &mut rxq_conf,
    &mut txq_conf,
  );

  let mut run: Arc<AtomicBool> = Arc::new(AtomicBool::new(true));
  let mut run_clone = run.clone();
  ctrlc::set_handler(move || {
    run_clone.store(false, Ordering::Relaxed);
  });
  while run.load(Ordering::Relaxed) {
    let mut rxq = service().rx_queue(port_id, 0).unwrap();
    let mut batch: ArrayVec<Mbuf, 32> = ArrayVec::new();
    rxq.rx(&mut batch);
    for mbuf in batch.iter_mut() {
      println!("packet len: {}", mbuf.len());
      let pbuf = Pbuf::new(mbuf);
      let ether = EtherPacket::parse(pbuf).unwrap();
      let ipv4 = Ipv4Packet::parse(ether.payload()).unwrap();
      println!("ipv4 dst {}", ipv4.dest_ip());
      println!("ipv4 src {}", ipv4.source_ip());
      if ipv4.protocol() != IpProtocol::TCP {
        continue;
      }
      let tcp = TcpPacket::parse(ipv4.payload()).unwrap();
      println!("tcp ack {}", tcp.ack_number());
      println!("tcp seq {}", tcp.seq_number());
    }
  }

  service().port_close(port_id).unwrap();
  println!("port closed");

  service().mempool_free(mp_name).unwrap();
  println!("mempool freed");

  service().service_close().unwrap();
  println!("dpdk service shutdown gracefully");
}
