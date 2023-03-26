use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicU64;
use std::time::Duration;

use byteorder::ByteOrder;
use byteorder::NetworkEndian;
use run_dpdk::MempoolConf;
use run_dpdk::PortConf;
use run_dpdk::RxQueueConf;
use run_dpdk::TxQueueConf;
use run_dpdk::offload::MbufTxOffload;
use run_dpdk::service;
use pcap::Capture;
use run_packet::Cursor;
use run_packet::CursorMut;
use run_packet::ether::ETHER_HEADER_LEN;
use run_packet::ether::EtherPacket;
use run_packet::ether::MacAddr;
use run_packet::ipv4::IpProtocol;
use run_packet::ipv4::Ipv4Addr;
use run_packet::ipv4::Ipv4Packet;
use arrayvec::ArrayVec;
use run_dpdk::Mbuf;
use run_packet::tcp::TcpPacket;
use run_packet::udp::UDP_HEADER_LEN;
use run_packet::udp::UdpPacket;


const PCAP_FILE:&str = "./traces/test.pcap";
const DEST_MAC:MacAddr = MacAddr([0x08, 0x68, 0x8d, 0x61, 0x69, 0x28]);
const DEST_IPA:Ipv4Addr = Ipv4Addr([192, 168, 23, 2]);
const DEST_IPB:Ipv4Addr = Ipv4Addr([192, 168, 24, 2]);
static RUN:AtomicBool =AtomicBool::new(true);

fn main() {
    env_logger::init();

    if run_dpdk::DpdkOption::new().init().is_err() {
        log::error!("failed to init eal");
    }
    let mut mpconf = MempoolConf::default();
    mpconf.nb_mbufs = 8192;
    mpconf.per_core_caches = 256;
    let mut rxq_conf = RxQueueConf::default();
    rxq_conf.nb_rx_desc = 256;
    let mut txq_conf = TxQueueConf::default();
    txq_conf.nb_tx_desc = 1024;

    init_port(0, 4, "rx_mp1", &mut mpconf, &mut rxq_conf, &mut txq_conf);
    init_port(3, 4, "rx_mp2", &mut mpconf, &mut rxq_conf, &mut txq_conf);

    mpconf.nb_mbufs = 8192 * 4;
    service().mempool_create("mp", &mpconf).unwrap();

    // prepare mbuf data
    let mut mbufs = Vec::new();
    let mp = service().mempool("mp").unwrap();
    let mut cap = Capture::from_file(PCAP_FILE).unwrap();
    loop {
        if let Ok(frame) = cap.next() {
            if let Some(mut mbuf) = mp.try_alloc() {
                if frame.header.len as usize > 1518 {
                    log::info!("exceed the 1518 bytes {}",frame.header.len);
                    continue;
                }
                // extend to 1518 bytes
                assert_eq!(frame.data.len(),frame.header.len as usize);
                mbuf.extend_from_slice(frame.data);
                let extend = mbuf.len();
                let cursor = CursorMut::new(mbuf.data_mut());
                if let Ok(eth) = EtherPacket::parse(cursor) {
                    if let Ok(mut ipv4) = Ipv4Packet::parse(eth.payload()) {
                        match ipv4.protocol() {
                            IpProtocol::TCP => {
                                if let Ok(mut tcp) = TcpPacket::parse(ipv4.payload()) {
                                    tcp.set_checksum(0);
                                } else {
                                    log::info!("malformed tcp packet");
                                    continue;
                                }
                            },
                            IpProtocol::UDP => {
                                if let Ok(mut udp) = UdpPacket::parse(ipv4.payload()) {
                                    udp.set_checksum(0);
                                } else {
                                    log::info!("malformed tcp packet");
                                    continue;
                                }
                            },
                            _ => continue,
                        }
                    } else {
                        log::info!("not a ipv4 packet, drop it");
                        continue;
                    }
                } else {
                    log::info!("not a ethernet packet, drop it");
                    continue;
                }
                mbufs.push(mbuf);
            } else {
                log::info!("no mbufs,break");
                break;
            }
        } else {
            log::info!("repeat capture from pacap files,have already {}",mbufs.len());
            cap = Capture::from_file(PCAP_FILE).unwrap();
        }
    }

    if mbufs.len() != mpconf.nb_mbufs as usize {
        log::error!("failed to init mbufs");
        return;
    }

    mbufs.clear();

    // launch send thread
    let mut jhs = Vec::new();
    let mut core = 1;
    for port_id in vec![0,3].drain(..) {
        for qid in 0..4 {
            let jh = std::thread::spawn(move || {
                send(port_id,qid,core);
            });
            core += 1;
            jhs.push(jh);
        }
    }

    ctrlc::set_handler(|| {
        RUN.store(false,std::sync::atomic::Ordering::Relaxed);
    }).unwrap();

    let mut port0_old_stats = service().port_stats(0).unwrap();;
    let mut port3_old_stats = service().port_stats(3).unwrap();;
    while RUN.load(std::sync::atomic::Ordering::Relaxed) {
        std::thread::sleep(Duration::from_secs(1));
        let port0_stats = service().port_stats(0).unwrap();
        let port3_stats = service().port_stats(3).unwrap();
        println!(
            "Port 0 total tx: {} pps, {} Gbps, {} misses/s",
            port0_stats.opackets() - port0_old_stats.opackets(),
            (port0_stats.obytes() - port0_old_stats.obytes()) as f64 * 8.0 / 1000000000.0,
            port0_stats.oerrors() - port0_old_stats.oerrors()
        );
        println!(
            "Port 3 total tx: {} pps, {} Gbps, {} misses/s",
            port3_stats.opackets() - port3_old_stats.opackets(),
            (port3_stats.obytes() - port3_old_stats.obytes()) as f64 * 8.0 / 1000000000.0,
            port3_stats.oerrors() - port3_old_stats.oerrors()
        );
        port0_old_stats = port0_stats;
        port3_old_stats = port3_stats;
    }
}

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


fn send(port_id:u16,qid:u16,core:u32) {
    let mut dst_ip = DEST_IPA;
    if port_id == 0 {
        dst_ip = DEST_IPB;
    }
    service().lcore_bind(core).unwrap();
    let mut batch:ArrayVec<Mbuf,64> = ArrayVec::new();
    let mut mp = service().mempool("mp").unwrap();
    let mut txq = service().tx_queue(port_id, qid).unwrap();
    let mut adder:u8 = 0;
    let total_ips = 200u8;
    while RUN.load(std::sync::atomic::Ordering::Relaxed) {
        mp.fill_batch(&mut batch);
        for mbuf in batch.iter_mut() {
            unsafe {
                mbuf.extend(256 as usize);
            }
            let cursor = CursorMut::new(mbuf.data_mut());
            let mut eth = EtherPacket::parse(cursor).unwrap();
            eth.set_dest_mac(DEST_MAC);
            //eth.set_source_mac(MacAddr([0x00, 0x50, 0x56, 0xae, 0x76, 0xf5]));
            let mut ipv4 = Ipv4Packet::parse_unchecked(eth.payload());
            ipv4.set_dest_ip(dst_ip);
            ipv4.set_packet_len_unchecked(256 - ETHER_HEADER_LEN as u16);
            // ipv4.set_source_ip(Ipv4Addr([
            //     192,
            //     168,
            //     57,
            //     10 + (adder % total_ips),
            // ]));
            // adder = adder.wrapping_add(1);
            let mut ol_flag = MbufTxOffload::ALL_DISABLED;
            ol_flag.enable_ip_cksum();
            ol_flag.set_l2_len(ETHER_HEADER_LEN as u64);
            ol_flag.set_l3_len(ipv4.header_len() as u64);
            match ipv4.protocol() {
                IpProtocol::TCP => {
                    let tcp = TcpPacket::parse(ipv4.payload()).unwrap();
                    ol_flag.set_l4_len(tcp.header_len() as u64);
                    ol_flag.enable_tcp_cksum();
                },
                IpProtocol::UDP => {
                    // let udp = UdpPacket::parse(ipv4.cursor_payload()).unwrap();
                    ol_flag.set_l4_len(UDP_HEADER_LEN as u64);
                    ol_flag.enable_udp_cksum();
                },
                _ => ()
            }

            mbuf.set_tx_offload(&ol_flag);
        }
        
        txq.tx(&mut batch);
        let mut retry = 100;
        while !batch.is_empty() && retry != 0 {
            txq.tx(&mut batch);
            retry -= 1;
        }
        batch.clear();
    }
}

