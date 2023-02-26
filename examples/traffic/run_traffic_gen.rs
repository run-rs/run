use std::io::Write;
use std::sync::{atomic::AtomicBool, atomic::Ordering, Arc};
use std::time::Duration;

use arrayvec::ArrayVec;
use clap::Parser;
use ctrlc;
use run_dpdk::*;
use run_packet::ether::*;
use run_packet::ipv4::*;
use run_packet::udp::*;
use run_packet::Buf;
use run_packet::CursorMut;

const BATCHSIZE: usize = 64;

#[derive(Debug, Parser)]
pub struct Flags {
  #[clap(long = "size")]
  pub packet_size: usize,
  #[clap(long = "core")]
  pub core: u32,
}

fn init_port(
  port_id: u16,
  nb_qs: u32,
  start_core: u32,
  mp_name: &'static str,
  mpconf: &mut MempoolConf,
  rxq_conf: &mut RxQueueConf,
  txq_conf: &mut TxQueueConf,
) {
  let port_infos = service().port_infos().unwrap();
  let port_info = &port_infos[port_id as usize];
  let socket_id = port_info.socket_id;

  service()
    .lcores()
    .iter()
    .find(|lcore| {
      lcore.lcore_id >= start_core && lcore.lcore_id < start_core + nb_qs
    })
    .map(|lcore| {
      assert!(lcore.socket_id == socket_id, "core with invalid socket id");
    });

  mpconf.socket_id = socket_id;
  service().mempool_create(mp_name, mpconf).unwrap();

  let pconf = PortConf::from_port_info(port_info).unwrap();

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
  let args = Flags::parse();
  DpdkOption::new().init().unwrap();

  // ethernet frame size: 64 - 1514, where 4 bytes are check sum
  let total_header_len = ETHER_HEADER_LEN + IPV4_HEADER_LEN + UDP_HEADER_LEN; // 42
  let payload_len = args.packet_size - total_header_len; // min size: 60-4-total_header_len, max_size: 1514-4-total_header_len

  let p0_id = 0;
  let p0_nb_qs = args.core;
  let p0_start_core = 1;
  let mut p0_mpconf = MempoolConf::default();
  p0_mpconf.nb_mbufs = 8192 * 10;
  p0_mpconf.per_core_caches = 256;
  p0_mpconf.dataroom = MempoolConf::DATAROOM;
  let mut p0_rxq_conf = RxQueueConf::default();
  p0_rxq_conf.nb_rx_desc = 1024;
  let mut p0_txq_conf = TxQueueConf::default();
  p0_txq_conf.nb_tx_desc = 1024;

  init_port(
    p0_id,
    p0_nb_qs,
    p0_start_core,
    "p0_mp",
    &mut p0_mpconf,
    &mut p0_rxq_conf,
    &mut p0_txq_conf,
  );

  let run = Arc::new(AtomicBool::new(true));
  let run_clone = run.clone();
  ctrlc::set_handler(move || {
    run_clone.store(false, Ordering::Release);
  })
  .unwrap();

  let mut jhs = Vec::new();

  // launch p0 threads
  for qid in 0..p0_nb_qs {
    let run = run.clone();
    let jh = std::thread::spawn(move || {
      service().lcore_bind(p0_start_core + qid).unwrap();

      let mut txq = service().tx_queue(p0_id, qid as u16).unwrap();
      let mp = service().mempool("p0_mp").unwrap();

      let mut batch = ArrayVec::<_, BATCHSIZE>::new();

      let mut udp_hdr = UDP_HEADER_TEMPLATE;
      udp_hdr.set_source_port(60376);
      udp_hdr.set_dest_port(161);

      let mut ipv4_hdr = IPV4_HEADER_TEMPLATE;
      ipv4_hdr.set_ident(0x5c65);
      ipv4_hdr.clear_flags();
      ipv4_hdr.set_time_to_live(128);
      ipv4_hdr.set_source_ip(Ipv4Addr([192, 168, 29, 58]));
      ipv4_hdr.set_dest_ip(Ipv4Addr([192, 168, 12, 2]));
      ipv4_hdr.set_protocol(IpProtocol::UDP);

      let mut eth_hdr = ETHER_HEADER_TEMPLATE;
      eth_hdr.set_dest_mac(MacAddr([0x08, 0x68, 0x8d, 0x61, 0x69, 0x28]));
      eth_hdr.set_source_mac(MacAddr([0x00, 0x50, 0x56, 0xae, 0x76, 0xf5]));
      eth_hdr.set_ethertype(EtherType::IPV4);

      while run.load(Ordering::Acquire) {
        mp.fill_batch(&mut batch);
        for mbuf in batch.iter_mut() {
          unsafe { mbuf.extend(total_header_len + payload_len) };

          let mut pkt = CursorMut::new(mbuf.data_mut());
          pkt.advance(total_header_len);

          let udppkt = UdpPacket::prepend_header(pkt, &udp_hdr);

          let ippkt = Ipv4Packet::prepend_header(udppkt.release(), &ipv4_hdr);

          let _ = EtherPacket::prepend_header(ippkt.release(), &eth_hdr);
        }

        while batch.len() > 0 {
          let _sent = txq.tx(&mut batch);
        }
      }
    });
    jhs.push(jh);
  }

  let mut p0_old_stats = service().port_stats(p0_id).unwrap();

  let mut opt = std::fs::File::options();
  opt.append(true);
  opt.write(true);
  opt.create(true);

  let mut file = opt.open("./data/traffic_gen.csv").unwrap();

  file
    .write(
      format!(
        "generator,core number,packet size,throughput,packet per seconds\n"
      )
      .as_bytes(),
    )
    .unwrap();

  let mut max_secs = 10;
  while run.load(Ordering::Acquire) {
    std::thread::sleep(std::time::Duration::from_secs(1));
    if max_secs == 0 {
      run.store(false, Ordering::Relaxed);
      break;
    }
    max_secs -= 1;
    let p0_curr_stats = service().port_stats(p0_id).unwrap();

    file
      .write(
        format!(
          "RUN,{},{},{},{}\n",
          p0_nb_qs,
          payload_len + total_header_len,
          (p0_curr_stats.obytes() - p0_old_stats.obytes()) as f64 * 8.0
            / 1000000000.0,
          p0_curr_stats.opackets() - p0_old_stats.opackets(),
        )
        .as_bytes(),
      )
      .unwrap();

    p0_old_stats = p0_curr_stats;
  }

  for jh in jhs {
    jh.join().unwrap();
  }

  service().port_close(0).unwrap();
  println!("port 0/1 closed");

  service().mempool_free("p0_mp").unwrap();
  println!("mempool p0/p1 freed");

  service().service_close().unwrap();
  println!("dpdk service shutdown gracefully");
}
