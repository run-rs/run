use std::sync::{atomic::AtomicBool, atomic::Ordering, Arc};
use std::time::Duration;

use arrayvec::ArrayVec;
use ctrlc;
use run_dpdk::*;
use run_packet::ether::*;
use run_packet::ipv4::*;
use run_packet::tcp::{TCP_HEADER_LEN, TCP_HEADER_TEMPLATE};
use run_packet::tcp::TcpPacket;
use run_packet::udp::*;
use run_packet::Buf;
use run_packet::CursorMut;

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
    DpdkOption::new().init().unwrap();

    let port_id = 3;
    let nb_qs = 14;
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

    let start_core = 1;
    let socket_id = service().port_infos().unwrap()[port_id as usize].socket_id;
    service()
        .lcores()
        .iter()
        .find(|lcore| lcore.lcore_id >= start_core && lcore.lcore_id < start_core + nb_qs)
        .map(|lcore| {
            assert!(lcore.socket_id == socket_id, "core with invalid socket id");
        });

    let run = Arc::new(AtomicBool::new(true));
    let run_curr = run.clone();
    let run_clone = run.clone();
    ctrlc::set_handler(move || {
        run_clone.store(false, Ordering::Release);
    })
    .unwrap();

    let total_header_len = ETHER_HEADER_LEN + IPV4_HEADER_LEN + TCP_HEADER_LEN;
    let payload_len = 18;

    let mut adder = 0;
    let total_ips = 200;

    let mut jhs = Vec::new();
    for i in 0..nb_qs {
        let run = run.clone();
        let jh = std::thread::spawn(move || {
            service().lcore_bind(i + 1).unwrap();
            let mut txq = service().tx_queue(port_id, i as u16).unwrap();
            let mp = service().mempool(mp_name).unwrap();
            let mut batch = ArrayVec::<_, 64>::new();
            let mut seq_number = 0;
            while run.load(Ordering::Acquire) {
                std::thread::sleep(Duration::from_secs(1));
                mp.fill_batch(&mut batch);
                for mbuf in batch.iter_mut() {
                    unsafe { mbuf.extend(total_header_len + payload_len) };

                    let mut pkt = CursorMut::new(mbuf.data_mut());
                    pkt.advance(total_header_len);

                    let mut tcppkt = TcpPacket::prepend_header(pkt, &TCP_HEADER_TEMPLATE);
                    tcppkt.set_src_port(60376);
                    tcppkt.set_dst_port(161);
                    tcppkt.set_ack(true);
                    tcppkt.set_ack_number(1);
                    tcppkt.set_header_len_unchecked(TCP_HEADER_LEN as u8);
                    tcppkt.set_seq_number(seq_number);
                    seq_number += payload_len as u32;
                    
                    let mut ippkt =
                        Ipv4Packet::prepend_header(tcppkt.release(), &IPV4_HEADER_TEMPLATE);
                    ippkt.set_ident(0x5c65);
                    ippkt.set_protocol(IpProtocol::TCP);
                    ippkt.clear_flags();
                    ippkt.set_time_to_live(128);
                    ippkt.set_source_ip(Ipv4Addr([192, 168, 57, 10 + (adder % total_ips)]));
                    adder = adder.wrapping_add(1);
                    ippkt.set_dest_ip(Ipv4Addr([192, 168, 23, 2]));
                    ippkt.set_protocol(IpProtocol::UDP);
                    ippkt.adjust_checksum();

                    let mut ethpkt =
                    EtherPacket::prepend_header(ippkt.release(), &ETHER_HEADER_TEMPLATE);
                    ethpkt.set_dest_mac(MacAddr([0x08, 0x68, 0x8d, 0x61, 0x69, 0x28]));
                    ethpkt.set_source_mac(MacAddr([0x00, 0x50, 0x56, 0xae, 0x76, 0xf5]));
                    ethpkt.set_ethertype(EtherType::IPV4);
                }

                while batch.len() > 0 {
                    let _sent = txq.tx(&mut batch);
                }
            }
        });
        jhs.push(jh);
    }

    let mut old_stats = service().port_stats(port_id).unwrap();
    while run_curr.load(Ordering::Acquire) {
        std::thread::sleep(std::time::Duration::from_secs(1));
        let curr_stats = service().port_stats(port_id).unwrap();
        println!(
            "pkts per sec: {}, bytes per sec: {}, errors per sec: {}",
            curr_stats.opackets() - old_stats.opackets(),
            (curr_stats.obytes() - old_stats.obytes()) as f64 * 8.0 / 1000000000.0,
            curr_stats.oerrors() - old_stats.oerrors(),
        );

        old_stats = curr_stats;
    }

    for jh in jhs {
        jh.join().unwrap();
    }

    service().port_close(port_id).unwrap();
    println!("port closed");

    service().mempool_free(mp_name).unwrap();
    println!("mempool freed");

    service().service_close().unwrap();
    println!("dpdk service shutdown gracefully");
}
