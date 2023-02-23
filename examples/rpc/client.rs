use std::{sync::{atomic::{AtomicBool, Ordering, AtomicU64}, Arc}, time::Duration};

use bytes::Buf;
use run_dpdk::{service};
use run_packet::{ipv4::{Ipv4Addr, IPV4_HEADER_LEN}, ether::{MacAddr}, udp::UDP_HEADER_LEN};

use crate::common::{
  nexus::Nexus,
  constant::*,
  msgbuffer::{RPC_HEADER_LEN, MsgBuffer}, rpc::Tag, time::{rdtsc, to_msec},
};

mod common;


const CLIENT_PORT:u16 = 9000;
const CLIENT_IPV4:Ipv4Addr = Ipv4Addr([192,168,22,2]);
const SERVER_IPV4:Ipv4Addr = Ipv4Addr([192,168,23,2]);
const CLIENT_MAC:MacAddr = MacAddr([0x10, 0x70, 0xfd, 0x15, 0x77, 0xbf]);
const SERVER_MAC:MacAddr = MacAddr([0x08, 0x68, 0x8d, 0x61, 0x69, 0x28]);
const SERVER_PORT:u16 = 9000;
const DPDK_PORT_ID:u16 = 0;

const RESP_SIZE:usize = 8000;

const MTU:usize = TTR_MAX_DATA_PER_PKT  + UDP_HEADER_LEN  +IPV4_HEADER_LEN + RPC_HEADER_LEN;

fn init_eal(port_id:u16) -> bool {
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
  
    let mut pconf = run_dpdk::PortConf::from_port_info(port_info).unwrap();
    pconf.rx_offloads.enable_ipv4_cksum();
    pconf.tx_offloads.enable_multi_segs();
    pconf.tx_offloads.enable_ipv4_cksum();
    pconf.mtu = MTU as u32;

  
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

fn main(){
    env_logger::init();
    let nexus=Nexus::new().unwrap();
    let freq_ghz=nexus.freq_ghz();

    init_eal(DPDK_PORT_ID);

    let mut rpc=nexus.create_rpc(
        true,
        0,
        service().tx_queue(DPDK_PORT_ID, 0).unwrap(),
        service().rx_queue(DPDK_PORT_ID, 0).unwrap(),
        service().mempool("mp").unwrap(),
        CLIENT_IPV4,
        CLIENT_PORT,
        CLIENT_MAC,
        SERVER_IPV4,
        SERVER_PORT,
        SERVER_MAC
    );

    rpc.create_session(true,0);

    let req=MsgBuffer::ALLOCA_MSG(64);
    let resp=MsgBuffer::ALLOCA_MSG(RESP_SIZE); // 8MB

    let run = Arc::new(AtomicBool::new(true));

    let ctrlc_run = run.clone();

    ctrlc::set_handler( move || {
        ctrlc_run.store(false,Ordering::Relaxed);
    }).unwrap();

    std::thread::spawn(move ||{
        let mut prev_bytes=0;
        let mut prev_calls=0;
        loop{
            std::thread::sleep(Duration::from_secs(1));
            let cur_bytes=RECEIVE_BYTES.load(Ordering::Relaxed);
            let diff_bytes=cur_bytes-prev_bytes;
            prev_bytes=cur_bytes;
            let cur_calls=FINISH_CALLS.load(Ordering::Relaxed);
            let diff_calls=cur_calls-prev_calls;
            prev_calls=cur_calls;

            println!("Troughput:{} bit/s",diff_bytes*8);
            println!("Finish calls: {} rpc/s",diff_calls);
            println!("latency: {} ms",to_msec(LATENCY.load(Ordering::Relaxed), freq_ghz));
        }
    });
    
    
    while run.load(std::sync::atomic::Ordering::Relaxed) {
        if REQUEST_ALLOW.load(Ordering::Relaxed) {
            rpc.enqueue_request(
                2, 
                req.clone(), 
                resp.clone(), 
                cont_func, 
                Tag::default()
            );
            REQUEST_ALLOW.store(false, Ordering::Relaxed);
            SEND_TSC.store(rdtsc(), Ordering::Relaxed);
        }
        rpc.run_event_loop_once();
    }

    service().port_close(DPDK_PORT_ID).unwrap();
    println!("port closed");

    service().mempool_free("mp").unwrap();
    println!("mempool freed");

    service().service_close().unwrap();
    println!("dpdk service shutdown gracefully");
}

static REQUEST_ALLOW:AtomicBool=AtomicBool::new(true);
static RECEIVE_BYTES:AtomicU64=AtomicU64::new(0);
static FINISH_CALLS:AtomicU64=AtomicU64::new(0);
static SEND_TSC:AtomicU64=AtomicU64::new(0);
static LATENCY:AtomicU64=AtomicU64::new(0);



fn cont_func(resp:MsgBuffer){
    let last_tsc=SEND_TSC.load(Ordering::Relaxed);
    LATENCY.store(rdtsc()-last_tsc, Ordering::Relaxed);
    REQUEST_ALLOW.store(true, Ordering::Relaxed);

    let num_pkts=resp.num_pkts();

    for i in 0.. num_pkts {
        let mut buf=resp.get_buf_n(i);
        RECEIVE_BYTES.fetch_add(buf.remaining() as u64, Ordering::Relaxed);

        while buf.has_remaining() {
            let size =buf.chunk().len();
            buf.advance(size);
        }
    }
    FINISH_CALLS.fetch_add(1, Ordering::Relaxed);
}



