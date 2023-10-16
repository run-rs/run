use std::sync::{atomic::AtomicBool, atomic::Ordering, Arc};

use arrayvec::ArrayVec;
use ctrlc;

use run_dpdk::error::{Error, Result};
use run_dpdk::*;
use run_packet::ether::*;
use run_packet::ipv4::*;
use run_packet::tcp::*;
use run_packet::udp::*;

// The socket to work on
const WORKING_SOCKET: u32 = 0;
const THREAD_NUM: u32 = 1;
const START_CORE: usize = 1;

// dpdk batch size
const BATCH_SIZE: usize = 64;

// Basic configuration of the mempool
const MBUF_CACHE: u32 = 256;
const MBUF_NUM: u32 = MBUF_CACHE * 32 * THREAD_NUM;

const MP: &str = "wtf";

// Basic configuration of the port
const PORT_ID: u16 = 0;
const TXQ_DESC_NUM: u16 = 1024;
const RXQ_DESC_NUM: u16 = 1024;

fn entry_func() {
    // make sure that the rx and tx threads are on the correct cores
    let res = service()
        .lcores()
        .iter()
        .filter(|lcore| {
            lcore.lcore_id >= START_CORE as u32
                && lcore.lcore_id < START_CORE as u32 + THREAD_NUM as u32
        })
        .all(|lcore| lcore.socket_id == WORKING_SOCKET);
    assert!(res == true);

    let run = Arc::new(AtomicBool::new(true));
    let run_clone = run.clone();
    ctrlc::set_handler(move || {
        run_clone.store(false, Ordering::Release);
    })
    .unwrap();

    let mut jhs = Vec::new();

    for i in 0..THREAD_NUM as usize {
        let run_clone = run.clone();
        let jh = std::thread::spawn(move || {
            service().lcore_bind(i as u32 + START_CORE as u32).unwrap();

            let mut rxq = service().rx_queue(PORT_ID, i as u16).unwrap();
            let mut batch = ArrayVec::<_, BATCH_SIZE>::new();

            while run_clone.load(Ordering::Acquire) {
                rxq.rx(&mut batch);

                for mut mbuf in batch.drain(..) {
                    let mbuf_rx_ol = mbuf.rx_offload();
                    let mbuf_rx_rss = mbuf.rss();
                    let pkt_len = mbuf.len();
                    let nb_segs = mbuf.num_segs();

                    let buf = Pbuf::new(&mut mbuf);

                    let ethpkt = match EtherPacket::parse(buf) {
                        Err(_) => continue,
                        Ok(ethpkt) => ethpkt,
                    };

                    let ippkt = match Ipv4Packet::parse(ethpkt.payload()) {
                        Err(_) => continue,
                        Ok(ippkt) => ippkt,
                    };
                    let src_ip = ippkt.source_ip();
                    let dst_ip = ippkt.dest_ip();
                    let manual_ip_cksum_good = ippkt.verify_checksum();

                    let (manual_l4_cksum_good, sport, dport, protocol) = match ippkt.protocol() {
                        IpProtocol::TCP => {
                            let mut tcppkt = match TcpPacket::parse(ippkt.payload()) {
                                Err(_) => continue,
                                Ok(tcppkt) => tcppkt,
                            };

                            (
                                tcppkt.verify_ipv4_checksum(src_ip, dst_ip),
                                tcppkt.src_port(),
                                tcppkt.dst_port(),
                                IpProtocol::TCP,
                            )
                        }
                        IpProtocol::UDP => {
                            let mut udppkt = match UdpPacket::parse(ippkt.payload()) {
                                Err(_) => continue,
                                Ok(udppkt) => udppkt,
                            };

                            (
                                udppkt.verify_ipv4_checksum(src_ip, dst_ip),
                                udppkt.source_port(),
                                udppkt.dest_port(),
                                IpProtocol::UDP,
                            )
                        }
                        _ => continue,
                    };

                    println!("receiving {} packet with source IP {}, dest IP {}, source port {}, dest port {}, length {}, segs {}.", protocol, src_ip, dst_ip, sport, dport, pkt_len, nb_segs);
                    println!(
                        "ip checksum ok: offload {}, manual {}",
                        manual_ip_cksum_good,
                        mbuf_rx_ol.ip_cksum_good()
                    );
                    println!(
                        "l4 checksum ok: offload {}, manual {}",
                        manual_l4_cksum_good,
                        mbuf_rx_ol.l4_cksum_good()
                    );
                    println!(
                        "rss offload enabled {}, rss value {}",
                        mbuf_rx_ol.rss_hash(),
                        mbuf_rx_rss
                    );
                    for (idx, seg) in mbuf.seg_iter().enumerate() {
                        println!("The {}th segment is {} bytes", idx, seg.len());
                    }
                }
            }
        });
        jhs.push(jh);
    }

    while run.load(Ordering::Acquire) {
        std::thread::sleep(std::time::Duration::from_secs(1));
    }

    for jh in jhs {
        jh.join().unwrap();
    }
}

fn init_port(
    port_id: u16,
    nb_rx_queue: u16,
    nb_tx_queue: u16,
    nb_rx_desc: u16,
    mp_name: &str,
    nb_tx_desc: u16,
    socket_id: u32,
) -> Result<()> {
    // make sure that the port is on the correct socket
    let port_info = service().port_info(port_id)?;
    if port_info.socket_id != socket_id {
        return Err(Error::service_err("invalid socket id"));
    }

    // get the default port conf
    let mut port_conf = PortConf::from_port_info(&port_info)?;
    port_conf.mtu = 9000;
    port_conf.rx_offloads.enable_scatter();
    port_conf.tx_offloads.enable_multi_segs();

    // configure rxq
    let mut rxq_conf = RxQueueConf::default();
    rxq_conf.set_nb_rx_desc(nb_rx_desc);
    rxq_conf.set_socket_id(socket_id);
    rxq_conf.set_mp_name(mp_name);
    let rxq_confs: Vec<RxQueueConf> = (0..nb_rx_queue as usize)
        .map(|_| rxq_conf.clone())
        .collect();

    // configure txq
    let mut txq_conf = TxQueueConf::default();
    txq_conf.set_nb_tx_desc(nb_tx_desc);
    txq_conf.set_socket_id(socket_id);
    let txq_confs: Vec<TxQueueConf> = (0..nb_tx_queue as usize)
        .map(|_| txq_conf.clone())
        .collect();

    // create the port
    service().port_configure(port_id, &port_conf, &rxq_confs, &txq_confs)?;

    Ok(())
}

fn main() {
    DpdkOption::new().init().unwrap();

    // create mempool
    utils::init_mempool(MP, MBUF_NUM, MBUF_CACHE, WORKING_SOCKET).unwrap();

    // create the port
    init_port(
        PORT_ID,
        THREAD_NUM as u16,
        THREAD_NUM as u16,
        RXQ_DESC_NUM,
        MP,
        TXQ_DESC_NUM,
        WORKING_SOCKET,
    )
    .unwrap();

    entry_func();

    // shutdown the port
    service().port_close(PORT_ID).unwrap();

    // free the mempool
    service().mempool_free(MP).unwrap();

    // shutdown the DPDK service
    service().service_close().unwrap();

    println!("dpdk service shutdown gracefully");
}
