use std::{sync::{atomic::{AtomicBool, Ordering}, Arc}};

use common::{rpc::ReqFunc};
use run_dpdk::{service};
use run_packet::{ipv4::{Ipv4Addr, IPV4_HEADER_LEN}, ether::{MacAddr}, Cursor, udp::UDP_HEADER_LEN};

use crate::common::{
  nexus::Nexus,
  rpc::ReqHandle,
  rpc::RpcContext,
  constant::*,
  msgbuffer::RPC_HEADER_LEN,
};

mod common;


const CLIENT_PORT:u16 = 9000;
const CLIENT_IPV4:Ipv4Addr = Ipv4Addr([192,168,22,2]);
const SERVER_IPV4:Ipv4Addr = Ipv4Addr([192,168,23,2]);
const CLIENT_MAC:MacAddr = MacAddr([0x08, 0x68, 0x8d, 0x61, 0x69, 0x28]);
const SERVER_MAC:MacAddr = MacAddr([0x10, 0x70, 0xfd, 0x15, 0x77, 0xc1]);
const SERVER_PORT:u16 = 9000;
const DPDK_PORT_ID:u16 = 0;

const RESP_SIZE:usize = 8000000;

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
    mconf.dataroom = 8196;
  
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
    pconf.rx_offloads.enable_scatter();
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
  env_logger::builder()
    // setting this to None disables the timestamp
    .format_timestamp(Some(env_logger::TimestampPrecision::Micros))
    .init();
  let mut nexus=Nexus::new().unwrap();

  init_eal(DPDK_PORT_ID);

  nexus.register_req_func(2, ReqFunc{req_func:req_func}).unwrap();

  let mut rpc=nexus.create_rpc(
      false,
      0,
      service().tx_queue(DPDK_PORT_ID, 0).unwrap(),
      service().rx_queue(DPDK_PORT_ID, 0).unwrap(),
      service().mempool("mp").unwrap(),
      SERVER_IPV4,
      SERVER_PORT,
      SERVER_MAC,
      CLIENT_IPV4,
      CLIENT_PORT,
      CLIENT_MAC
  );

  rpc.create_session(false,RESP_SIZE);

  let run = Arc::new(AtomicBool::new(true));
  let run_ctrlc = run.clone();

  ctrlc::set_handler( move || {
    run_ctrlc.store(false,Ordering::Relaxed);
  }).unwrap();


  while run.load(Ordering::Relaxed) {
    rpc.run_event_loop_once();
  }
}

fn req_func(req_handle:ReqHandle,_ctx:RpcContext){
    let mut resp=req_handle.get_resp_msgbuf();

    resp.resize_msg_buffer(RESP_SIZE);

    for pkt_idx in 0..resp.num_pkts() {
        let mut cursor=Cursor::new(&MSSEAGE.as_bytes()[0..TTR_MAX_DATA_PER_PKT]);
        resp.copy_data_from_buf(&mut cursor, pkt_idx);
    }


    /* let end = run_time::Instant::now() - run_time::Instant::now(); */
    /* println!("{}",end.as_nanos()); */
    //println!("ending processing");
}

static MSSEAGE:&'static str="Besides Rajya Sabha seats, the accused persons also promised to arrange governorship and chairmanship of different government organisations in lieu of bribes, they said.

    According to the first information report (FIR), filed on July 15 and reviewed by HT, those named include Kamalakar Premkumar Bandgar of Maharashtra’s Latur, Ravindra Vithal Naik of Karnataka’s Belgaum, and Delhi-NCR-based Mahendra Pal Arora, Abhishek Boora and Mohammed Aijaz Khan.
    
    The FIR alleged that Bandgar posed as a senior CBI officer and flaunted his connections with highly placed officials. He then asked Boora, Arora, Khan and Naik to bring any sort of work that he could fix in lieu of payment of huge illegal gratification.
    
    The accused, the CBI said, conspired with “the sole ulterior motive of cheating private persons by falsely assuring them for arrangement of seats in Rajya Sabha, appointment as governor, appointment as chairman in different government-run organisations under central government ministries and departments against huge pecuniary consideration”\
    Besides Rajya Sabha seats, the accused persons also promised to arrange governorship and chairmanship of different government organisations in lieu of bribes, they said.

    According to the first information report (FIR), filed on July 15 and reviewed by HT, those named include Kamalakar Premkumar Bandgar of Maharashtra’s Latur, Ravindra Vithal Naik of Karnataka’s Belgaum, and Delhi-NCR-based Mahendra Pal Arora, Abhishek Boora and Mohammed Aijaz Khan.
    
    The FIR alleged that Bandgar posed as a senior CBI officer and flaunted his connections with highly placed officials. He then asked Boora, Arora, Khan and Naik to bring any sort of work that he could fix in lieu of payment of huge illegal gratification.
    
    The accused, the CBI said, conspired with “the sole ulterior motive of cheating private persons by falsely assuring them for arrangement of seats in Rajya Sabha, appointment as governor, appointment as chairman in different government-run organisations under central government ministries and departments against huge pecuniary consideration”\
    Besides Rajya Sabha seats, the accused persons also promised to arrange governorship and chairmanship of different government organisations in lieu of bribes, they said.

    According to the first information report (FIR), filed on July 15 and reviewed by HT, those named include Kamalakar Premkumar Bandgar of Maharashtra’s Latur, Ravindra Vithal Naik of Karnataka’s Belgaum, and Delhi-NCR-based Mahendra Pal Arora, Abhishek Boora and Mohammed Aijaz Khan.
    
    The FIR alleged that Bandgar posed as a senior CBI officer and flaunted his connections with highly placed officials. He then asked Boora, Arora, Khan and Naik to bring any sort of work that he could fix in lieu of payment of huge illegal gratification.
    
    The accused, the CBI said, conspired with “the sole ulterior motive of cheating private persons by falsely assuring them for arrangement of seats in Rajya Sabha, appointment as governor, appointment as chairman in different government-run organisations under central government ministries and departments against huge pecuniary consideration”\
    Besides Rajya Sabha seats, the accused persons also promised to arrange governorship and chairmanship of different government organisations in lieu of bribes, they said.

    According to the first information report (FIR), filed on July 15 and reviewed by HT, those named include Kamalakar Premkumar Bandgar of Maharashtra’s Latur, Ravindra Vithal Naik of Karnataka’s Belgaum, and Delhi-NCR-based Mahendra Pal Arora, Abhishek Boora and Mohammed Aijaz Khan.
    
    The FIR alleged that Bandgar posed as a senior CBI officer and flaunted his connections with highly placed officials. He then asked Boora, Arora, Khan and Naik to bring any sort of work that he could fix in lieu of payment of huge illegal gratification.
    
    The accused, the CBI said, conspired with “the sole ulterior motive of cheating private persons by falsely assuring them for arrangement of seats in Rajya Sabha, appointment as governor, appointment as chairman in different government-run organisations under central government ministries and departments against huge pecuniary consideration”\
    Besides Rajya Sabha seats, the accused persons also promised to arrange governorship and chairmanship of different government organisations in lieu of bribes, they said.

    According to the first information report (FIR), filed on July 15 and reviewed by HT, those named include Kamalakar Premkumar Bandgar of Maharashtra’s Latur, Ravindra Vithal Naik of Karnataka’s Belgaum, and Delhi-NCR-based Mahendra Pal Arora, Abhishek Boora and Mohammed Aijaz Khan.
    
    The FIR alleged that Bandgar posed as a senior CBI officer and flaunted his connections with highly placed officials. He then asked Boora, Arora, Khan and Naik to bring any sort of work that he could fix in lieu of payment of huge illegal gratification.
    
    The accused, the CBI said, conspired with “the sole ulterior motive of cheating private persons by falsely assuring them for arrangement of seats in Rajya Sabha, appointment as governor, appointment as chairman in different government-run organisations under central government ministries and departments against huge pecuniary consideration”\
    Besides Rajya Sabha seats, the accused persons also promised to arrange governorship and chairmanship of different government organisations in lieu of bribes, they said.

    According to the first information report (FIR), filed on July 15 and reviewed by HT, those named include Kamalakar Premkumar Bandgar of Maharashtra’s Latur, Ravindra Vithal Naik of Karnataka’s Belgaum, and Delhi-NCR-based Mahendra Pal Arora, Abhishek Boora and Mohammed Aijaz Khan.
    
    The FIR alleged that Bandgar posed as a senior CBI officer and flaunted his connections with highly placed officials. He then asked Boora, Arora, Khan and Naik to bring any sort of work that he could fix in lieu of payment of huge illegal gratification.
    
    The accused, the CBI said, conspired with “the sole ulterior motive of cheating private persons by falsely assuring them for arrangement of seats in Rajya Sabha, appointment as governor, appointment as chairman in different government-run organisations under central government ministries and departments against huge pecuniary consideration”\
    Besides Rajya Sabha seats, the accused persons also promised to arrange governorship and chairmanship of different government organisations in lieu of bribes, they said.

    According to the first information report (FIR), filed on July 15 and reviewed by HT, those named include Kamalakar Premkumar Bandgar of Maharashtra’s Latur, Ravindra Vithal Naik of Karnataka’s Belgaum, and Delhi-NCR-based Mahendra Pal Arora, Abhishek Boora and Mohammed Aijaz Khan.
    
    The FIR alleged that Bandgar posed as a senior CBI officer and flaunted his connections with highly placed officials. He then asked Boora, Arora, Khan and Naik to bring any sort of work that he could fix in lieu of payment of huge illegal gratification.
    
    The accused, the CBI said, conspired with “the sole ulterior motive of cheating private persons by falsely assuring them for arrangement of seats in Rajya Sabha, appointment as governor, appointment as chairman in different government-run organisations under central government ministries and departments against huge pecuniary consideration”\
    Besides Rajya Sabha seats, the accused persons also promised to arrange governorship and chairmanship of different government organisations in lieu of bribes, they said.

    According to the first information report (FIR), filed on July 15 and reviewed by HT, those named include Kamalakar Premkumar Bandgar of Maharashtra’s Latur, Ravindra Vithal Naik of Karnataka’s Belgaum, and Delhi-NCR-based Mahendra Pal Arora, Abhishek Boora and Mohammed Aijaz Khan.
    
    The FIR alleged that Bandgar posed as a senior CBI officer and flaunted his connections with highly placed officials. He then asked Boora, Arora, Khan and Naik to bring any sort of work that he could fix in lieu of payment of huge illegal gratification.
    
    The accused, the CBI said, conspired with “the sole ulterior motive of cheating private persons by falsely assuring them for arrangement of seats in Rajya Sabha, appointment as governor, appointment as chairman in different government-run organisations under central government ministries and departments against huge pecuniary consideration”\
    Besides Rajya Sabha seats, the accused persons also promised to arrange governorship and chairmanship of different government organisations in lieu of bribes, they said.

    According to the first information report (FIR), filed on July 15 and reviewed by HT, those named include Kamalakar Premkumar Bandgar of Maharashtra’s Latur, Ravindra Vithal Naik of Karnataka’s Belgaum, and Delhi-NCR-based Mahendra Pal Arora, Abhishek Boora and Mohammed Aijaz Khan.
    
    The FIR alleged that Bandgar posed as a senior CBI officer and flaunted his connections with highly placed officials. He then asked Boora, Arora, Khan and Naik to bring any sort of work that he could fix in lieu of payment of huge illegal gratification.
    
    The accused, the CBI said, conspired with “the sole ulterior motive of cheating private persons by falsely assuring them for arrangement of seats in Rajya Sabha, appointment as governor, appointment as chairman in different government-run organisations under central government ministries and departments against huge pecuniary consideration”\
    Besides Rajya Sabha seats, the accused persons also promised to arrange governorship and chairmanship of different government organisations in lieu of bribes, they said.

    According to the first information report (FIR), filed on July 15 and reviewed by HT, those named include Kamalakar Premkumar Bandgar of Maharashtra’s Latur, Ravindra Vithal Naik of Karnataka’s Belgaum, and Delhi-NCR-based Mahendra Pal Arora, Abhishek Boora and Mohammed Aijaz Khan.
    
    The FIR alleged that Bandgar posed as a senior CBI officer and flaunted his connections with highly placed officials. He then asked Boora, Arora, Khan and Naik to bring any sort of work that he could fix in lieu of payment of huge illegal gratification.
    
    The accused, the CBI said, conspired with “the sole ulterior motive of cheating private persons by falsely assuring them for arrangement of seats in Rajya Sabha, appointment as governor, appointment as chairman in different government-run organisations under central government ministries and departments against huge pecuniary consideration”\
    Besides Rajya Sabha seats, the accused persons also promised to arrange governorship and chairmanship of different government organisations in lieu of bribes, they said.

    According to the first information report (FIR), filed on July 15 and reviewed by HT, those named include Kamalakar Premkumar Bandgar of Maharashtra’s Latur, Ravindra Vithal Naik of Karnataka’s Belgaum, and Delhi-NCR-based Mahendra Pal Arora, Abhishek Boora and Mohammed Aijaz Khan.
    
    The FIR alleged that Bandgar posed as a senior CBI officer and flaunted his connections with highly placed officials. He then asked Boora, Arora, Khan and Naik to bring any sort of work that he could fix in lieu of payment of huge illegal gratification.
    
    The accused, the CBI said, conspired with “the sole ulterior motive of cheating private persons by falsely assuring them for arrangement of seats in Rajya Sabha, appointment as governor, appointment as chairman in different government-run organisations under central government ministries and departments against huge pecuniary consideration”\
    Besides Rajya Sabha seats, the accused persons also promised to arrange governorship and chairmanship of different government organisations in lieu of bribes, they said.

    According to the first information report (FIR), filed on July 15 and reviewed by HT, those named include Kamalakar Premkumar Bandgar of Maharashtra’s Latur, Ravindra Vithal Naik of Karnataka’s Belgaum, and Delhi-NCR-based Mahendra Pal Arora, Abhishek Boora and Mohammed Aijaz Khan.
    
    The FIR alleged that Bandgar posed as a senior CBI officer and flaunted his connections with highly placed officials. He then asked Boora, Arora, Khan and Naik to bring any sort of work that he could fix in lieu of payment of huge illegal gratification.
    
    The accused, the CBI said, conspired with “the sole ulterior motive of cheating private persons by falsely assuring them for arrangement of seats in Rajya Sabha, appointment as governor, appointment as chairman in different government-run organisations under central government ministries and departments against huge pecuniary consideration”\
    Besides Rajya Sabha seats, the accused persons also promised to arrange governorship and chairmanship of different government organisations in lieu of bribes, they said.

    According to the first information report (FIR), filed on July 15 and reviewed by HT, those named include Kamalakar Premkumar Bandgar of Maharashtra’s Latur, Ravindra Vithal Naik of Karnataka’s Belgaum, and Delhi-NCR-based Mahendra Pal Arora, Abhishek Boora and Mohammed Aijaz Khan.
    
    The FIR alleged that Bandgar posed as a senior CBI officer and flaunted his connections with highly placed officials. He then asked Boora, Arora, Khan and Naik to bring any sort of work that he could fix in lieu of payment of huge illegal gratification.
    
    The accused, the CBI said, conspired with “the sole ulterior motive of cheating private persons by falsely assuring them for arrangement of seats in Rajya Sabha, appointment as governor, appointment as chairman in different government-run organisations under central government ministries and departments against huge pecuniary consideration”\
    Besides Rajya Sabha seats, the accused persons also promised to arrange governorship and chairmanship of different government organisations in lieu of bribes, they said.

    According to the first information report (FIR), filed on July 15 and reviewed by HT, those named include Kamalakar Premkumar Bandgar of Maharashtra’s Latur, Ravindra Vithal Naik of Karnataka’s Belgaum, and Delhi-NCR-based Mahendra Pal Arora, Abhishek Boora and Mohammed Aijaz Khan.
    
    The FIR alleged that Bandgar posed as a senior CBI officer and flaunted his connections with highly placed officials. He then asked Boora, Arora, Khan and Naik to bring any sort of work that he could fix in lieu of payment of huge illegal gratification.
    
    The accused, the CBI said, conspired with “the sole ulterior motive of cheating private persons by falsely assuring them for arrangement of seats in Rajya Sabha, appointment as governor, appointment as chairman in different government-run organisations under central government ministries and departments against huge pecuniary consideration”\
    Besides Rajya Sabha seats, the accused persons also promised to arrange governorship and chairmanship of different government organisations in lieu of bribes, they said.

    According to the first information report (FIR), filed on July 15 and reviewed by HT, those named include Kamalakar Premkumar Bandgar of Maharashtra’s Latur, Ravindra Vithal Naik of Karnataka’s Belgaum, and Delhi-NCR-based Mahendra Pal Arora, Abhishek Boora and Mohammed Aijaz Khan.
    
    The FIR alleged that Bandgar posed as a senior CBI officer and flaunted his connections with highly placed officials. He then asked Boora, Arora, Khan and Naik to bring any sort of work that he could fix in lieu of payment of huge illegal gratification.
    
    The accused, the CBI said, conspired with “the sole ulterior motive of cheating private persons by falsely assuring them for arrangement of seats in Rajya Sabha, appointment as governor, appointment as chairman in different government-run organisations under central government ministries and departments against huge pecuniary consideration”\
    Besides Rajya Sabha seats, the accused persons also promised to arrange governorship and chairmanship of different government organisations in lieu of bribes, they said.

    According to the first information report (FIR), filed on July 15 and reviewed by HT, those named include Kamalakar Premkumar Bandgar of Maharashtra’s Latur, Ravindra Vithal Naik of Karnataka’s Belgaum, and Delhi-NCR-based Mahendra Pal Arora, Abhishek Boora and Mohammed Aijaz Khan.
    
    The FIR alleged that Bandgar posed as a senior CBI officer and flaunted his connections with highly placed officials. He then asked Boora, Arora, Khan and Naik to bring any sort of work that he could fix in lieu of payment of huge illegal gratification.
    
    The accused, the CBI said, conspired with “the sole ulterior motive of cheating private persons by falsely assuring them for arrangement of seats in Rajya Sabha, appointment as governor, appointment as chairman in different government-run organisations under central government ministries and departments against huge pecuniary consideration”\
    Besides Rajya Sabha seats, the accused persons also promised to arrange governorship and chairmanship of different government organisations in lieu of bribes, they said.

    According to the first information report (FIR), filed on July 15 and reviewed by HT, those named include Kamalakar Premkumar Bandgar of Maharashtra’s Latur, Ravindra Vithal Naik of Karnataka’s Belgaum, and Delhi-NCR-based Mahendra Pal Arora, Abhishek Boora and Mohammed Aijaz Khan.
    
    The FIR alleged that Bandgar posed as a senior CBI officer and flaunted his connections with highly placed officials. He then asked Boora, Arora, Khan and Naik to bring any sort of work that he could fix in lieu of payment of huge illegal gratification.
    
    The accused, the CBI said, conspired with “the sole ulterior motive of cheating private persons by falsely assuring them for arrangement of seats in Rajya Sabha, appointment as governor, appointment as chairman in different government-run organisations under central government ministries and departments against huge pecuniary consideration”\
    Besides Rajya Sabha seats, the accused persons also promised to arrange governorship and chairmanship of different government organisations in lieu of bribes, they said.

    According to the first information report (FIR), filed on July 15 and reviewed by HT, those named include Kamalakar Premkumar Bandgar of Maharashtra’s Latur, Ravindra Vithal Naik of Karnataka’s Belgaum, and Delhi-NCR-based Mahendra Pal Arora, Abhishek Boora and Mohammed Aijaz Khan.
    
    The FIR alleged that Bandgar posed as a senior CBI officer and flaunted his connections with highly placed officials. He then asked Boora, Arora, Khan and Naik to bring any sort of work that he could fix in lieu of payment of huge illegal gratification.
    
    The accused, the CBI said, conspired with “the sole ulterior motive of cheating private persons by falsely assuring them for arrangement of seats in Rajya Sabha, appointment as governor, appointment as chairman in different government-run organisations under central government ministries and departments against huge pecuniary consideration”\
    Besides Rajya Sabha seats, the accused persons also promised to arrange governorship and chairmanship of different government organisations in lieu of bribes, they said.

    According to the first information report (FIR), filed on July 15 and reviewed by HT, those named include Kamalakar Premkumar Bandgar of Maharashtra’s Latur, Ravindra Vithal Naik of Karnataka’s Belgaum, and Delhi-NCR-based Mahendra Pal Arora, Abhishek Boora and Mohammed Aijaz Khan.
    
    The FIR alleged that Bandgar posed as a senior CBI officer and flaunted his connections with highly placed officials. He then asked Boora, Arora, Khan and Naik to bring any sort of work that he could fix in lieu of payment of huge illegal gratification.
    
    The accused, the CBI said, conspired with “the sole ulterior motive of cheating private persons by falsely assuring them for arrangement of seats in Rajya Sabha, appointment as governor, appointment as chairman in different government-run organisations under central government ministries and departments against huge pecuniary consideration”\
    Besides Rajya Sabha seats, the accused persons also promised to arrange governorship and chairmanship of different government organisations in lieu of bribes, they said.

    According to the first information report (FIR), filed on July 15 and reviewed by HT, those named include Kamalakar Premkumar Bandgar of Maharashtra’s Latur, Ravindra Vithal Naik of Karnataka’s Belgaum, and Delhi-NCR-based Mahendra Pal Arora, Abhishek Boora and Mohammed Aijaz Khan.
    
    The FIR alleged that Bandgar posed as a senior CBI officer and flaunted his connections with highly placed officials. He then asked Boora, Arora, Khan and Naik to bring any sort of work that he could fix in lieu of payment of huge illegal gratification.
    
    The accused, the CBI said, conspired with “the sole ulterior motive of cheating private persons by falsely assuring them for arrangement of seats in Rajya Sabha, appointment as governor, appointment as chairman in different government-run organisations under central government ministries and departments against huge pecuniary consideration”\
    Besides Rajya Sabha seats, the accused persons also promised to arrange governorship and chairmanship of different government organisations in lieu of bribes, they said.

    According to the first information report (FIR), filed on July 15 and reviewed by HT, those named include Kamalakar Premkumar Bandgar of Maharashtra’s Latur, Ravindra Vithal Naik of Karnataka’s Belgaum, and Delhi-NCR-based Mahendra Pal Arora, Abhishek Boora and Mohammed Aijaz Khan.
    
    The FIR alleged that Bandgar posed as a senior CBI officer and flaunted his connections with highly placed officials. He then asked Boora, Arora, Khan and Naik to bring any sort of work that he could fix in lieu of payment of huge illegal gratification.
    
    The accused, the CBI said, conspired with “the sole ulterior motive of cheating private persons by falsely assuring them for arrangement of seats in Rajya Sabha, appointment as governor, appointment as chairman in different government-run organisations under central government ministries and departments against huge pecuniary consideration”\
    Besides Rajya Sabha seats, the accused persons also promised to arrange governorship and chairmanship of different government organisations in lieu of bribes, they said.

    According to the first information report (FIR), filed on July 15 and reviewed by HT, those named include Kamalakar Premkumar Bandgar of Maharashtra’s Latur, Ravindra Vithal Naik of Karnataka’s Belgaum, and Delhi-NCR-based Mahendra Pal Arora, Abhishek Boora and Mohammed Aijaz Khan.
    
    The FIR alleged that Bandgar posed as a senior CBI officer and flaunted his connections with highly placed officials. He then asked Boora, Arora, Khan and Naik to bring any sort of work that he could fix in lieu of payment of huge illegal gratification.
    
    The accused, the CBI said, conspired with “the sole ulterior motive of cheating private persons by falsely assuring them for arrangement of seats in Rajya Sabha, appointment as governor, appointment as chairman in different government-run organisations under central government ministries and departments against huge pecuniary consideration”\
    Besides Rajya Sabha seats, the accused persons also promised to arrange governorship and chairmanship of different government organisations in lieu of bribes, they said.

    According to the first information report (FIR), filed on July 15 and reviewed by HT, those named include Kamalakar Premkumar Bandgar of Maharashtra’s Latur, Ravindra Vithal Naik of Karnataka’s Belgaum, and Delhi-NCR-based Mahendra Pal Arora, Abhishek Boora and Mohammed Aijaz Khan.
    
    The FIR alleged that Bandgar posed as a senior CBI officer and flaunted his connections with highly placed officials. He then asked Boora, Arora, Khan and Naik to bring any sort of work that he could fix in lieu of payment of huge illegal gratification.
    
    The accused, the CBI said, conspired with “the sole ulterior motive of cheating private persons by falsely assuring them for arrangement of seats in Rajya Sabha, appointment as governor, appointment as chairman in different government-run organisations under central government ministries and departments against huge pecuniary consideration”\
    Besides Rajya Sabha seats, the accused persons also promised to arrange governorship and chairmanship of different government organisations in lieu of bribes, they said.

    According to the first information report (FIR), filed on July 15 and reviewed by HT, those named include Kamalakar Premkumar Bandgar of Maharashtra’s Latur, Ravindra Vithal Naik of Karnataka’s Belgaum, and Delhi-NCR-based Mahendra Pal Arora, Abhishek Boora and Mohammed Aijaz Khan.
    
    The FIR alleged that Bandgar posed as a senior CBI officer and flaunted his connections with highly placed officials. He then asked Boora, Arora, Khan and Naik to bring any sort of work that he could fix in lieu of payment of huge illegal gratification.
    
    The accused, the CBI said, conspired with “the sole ulterior motive of cheating private persons by falsely assuring them for arrangement of seats in Rajya Sabha, appointment as governor, appointment as chairman in different government-run organisations under central government ministries and departments against huge pecuniary consideration”\
    Besides Rajya Sabha seats, the accused persons also promised to arrange governorship and chairmanship of different government organisations in lieu of bribes, they said.

    According to the first information report (FIR), filed on July 15 and reviewed by HT, those named include Kamalakar Premkumar Bandgar of Maharashtra’s Latur, Ravindra Vithal Naik of Karnataka’s Belgaum, and Delhi-NCR-based Mahendra Pal Arora, Abhishek Boora and Mohammed Aijaz Khan.
    
    The FIR alleged that Bandgar posed as a senior CBI officer and flaunted his connections with highly placed officials. He then asked Boora, Arora, Khan and Naik to bring any sort of work that he could fix in lieu of payment of huge illegal gratification.
    
    The accused, the CBI said, conspired with “the sole ulterior motive of cheating private persons by falsely assuring them for arrangement of seats in Rajya Sabha, appointment as governor, appointment as chairman in different government-run organisations under central government ministries and departments against huge pecuniary consideration”\
    Besides Rajya Sabha seats, the accused persons also promised to arrange governorship and chairmanship of different government organisations in lieu of bribes, they said.

    According to the first information report (FIR), filed on July 15 and reviewed by HT, those named include Kamalakar Premkumar Bandgar of Maharashtra’s Latur, Ravindra Vithal Naik of Karnataka’s Belgaum, and Delhi-NCR-based Mahendra Pal Arora, Abhishek Boora and Mohammed Aijaz Khan.
    
    The FIR alleged that Bandgar posed as a senior CBI officer and flaunted his connections with highly placed officials. He then asked Boora, Arora, Khan and Naik to bring any sort of work that he could fix in lieu of payment of huge illegal gratification.
    
    The accused, the CBI said, conspired with “the sole ulterior motive of cheating private persons by falsely assuring them for arrangement of seats in Rajya Sabha, appointment as governor, appointment as chairman in different government-run organisations under central government ministries and departments against huge pecuniary consideration”\
    Besides Rajya Sabha seats, the accused persons also promised to arrange governorship and chairmanship of different government organisations in lieu of bribes, they said.

    According to the first information report (FIR), filed on July 15 and reviewed by HT, those named include Kamalakar Premkumar Bandgar of Maharashtra’s Latur, Ravindra Vithal Naik of Karnataka’s Belgaum, and Delhi-NCR-based Mahendra Pal Arora, Abhishek Boora and Mohammed Aijaz Khan.
    
    The FIR alleged that Bandgar posed as a senior CBI officer and flaunted his connections with highly placed officials. He then asked Boora, Arora, Khan and Naik to bring any sort of work that he could fix in lieu of payment of huge illegal gratification.
    
    The accused, the CBI said, conspired with “the sole ulterior motive of cheating private persons by falsely assuring them for arrangement of seats in Rajya Sabha, appointment as governor, appointment as chairman in different government-run organisations under central government ministries and departments against huge pecuniary consideration”\
    Besides Rajya Sabha seats, the accused persons also promised to arrange governorship and chairmanship of different government organisations in lieu of bribes, they said.

    According to the first information report (FIR), filed on July 15 and reviewed by HT, those named include Kamalakar Premkumar Bandgar of Maharashtra’s Latur, Ravindra Vithal Naik of Karnataka’s Belgaum, and Delhi-NCR-based Mahendra Pal Arora, Abhishek Boora and Mohammed Aijaz Khan.
    
    The FIR alleged that Bandgar posed as a senior CBI officer and flaunted his connections with highly placed officials. He then asked Boora, Arora, Khan and Naik to bring any sort of work that he could fix in lieu of payment of huge illegal gratification.
    
    The accused, the CBI said, conspired with “the sole ulterior motive of cheating private persons by falsely assuring them for arrangement of seats in Rajya Sabha, appointment as governor, appointment as chairman in different government-run organisations under central government ministries and departments against huge pecuniary consideration”\
    Besides Rajya Sabha seats, the accused persons also promised to arrange governorship and chairmanship of different government organisations in lieu of bribes, they said.

    According to the first information report (FIR), filed on July 15 and reviewed by HT, those named include Kamalakar Premkumar Bandgar of Maharashtra’s Latur, Ravindra Vithal Naik of Karnataka’s Belgaum, and Delhi-NCR-based Mahendra Pal Arora, Abhishek Boora and Mohammed Aijaz Khan.
    
    The FIR alleged that Bandgar posed as a senior CBI officer and flaunted his connections with highly placed officials. He then asked Boora, Arora, Khan and Naik to bring any sort of work that he could fix in lieu of payment of huge illegal gratification.
    
    The accused, the CBI said, conspired with “the sole ulterior motive of cheating private persons by falsely assuring them for arrangement of seats in Rajya Sabha, appointment as governor, appointment as chairman in different government-run organisations under central government ministries and departments against huge pecuniary consideration”\
    Besides Rajya Sabha seats, the accused persons also promised to arrange governorship and chairmanship of different government organisations in lieu of bribes, they said.

    According to the first information report (FIR), filed on July 15 and reviewed by HT, those named include Kamalakar Premkumar Bandgar of Maharashtra’s Latur, Ravindra Vithal Naik of Karnataka’s Belgaum, and Delhi-NCR-based Mahendra Pal Arora, Abhishek Boora and Mohammed Aijaz Khan.
    
    The FIR alleged that Bandgar posed as a senior CBI officer and flaunted his connections with highly placed officials. He then asked Boora, Arora, Khan and Naik to bring any sort of work that he could fix in lieu of payment of huge illegal gratification.
    
    The accused, the CBI said, conspired with “the sole ulterior motive of cheating private persons by falsely assuring them for arrangement of seats in Rajya Sabha, appointment as governor, appointment as chairman in different government-run organisations under central government ministries and departments against huge pecuniary consideration”\
    Besides Rajya Sabha seats, the accused persons also promised to arrange governorship and chairmanship of different government organisations in lieu of bribes, they said.

    According to the first information report (FIR), filed on July 15 and reviewed by HT, those named include Kamalakar Premkumar Bandgar of Maharashtra’s Latur, Ravindra Vithal Naik of Karnataka’s Belgaum, and Delhi-NCR-based Mahendra Pal Arora, Abhishek Boora and Mohammed Aijaz Khan.
    
    The FIR alleged that Bandgar posed as a senior CBI officer and flaunted his connections with highly placed officials. He then asked Boora, Arora, Khan and Naik to bring any sort of work that he could fix in lieu of payment of huge illegal gratification.
    
    The accused, the CBI said, conspired with “the sole ulterior motive of cheating private persons by falsely assuring them for arrangement of seats in Rajya Sabha, appointment as governor, appointment as chairman in different government-run organisations under central government ministries and departments against huge pecuniary consideration”\
    Besides Rajya Sabha seats, the accused persons also promised to arrange governorship and chairmanship of different government organisations in lieu of bribes, they said.

    According to the first information report (FIR), filed on July 15 and reviewed by HT, those named include Kamalakar Premkumar Bandgar of Maharashtra’s Latur, Ravindra Vithal Naik of Karnataka’s Belgaum, and Delhi-NCR-based Mahendra Pal Arora, Abhishek Boora and Mohammed Aijaz Khan.
    
    The FIR alleged that Bandgar posed as a senior CBI officer and flaunted his connections with highly placed officials. He then asked Boora, Arora, Khan and Naik to bring any sort of work that he could fix in lieu of payment of huge illegal gratification.
    
    The accused, the CBI said, conspired with “the sole ulterior motive of cheating private persons by falsely assuring them for arrangement of seats in Rajya Sabha, appointment as governor, appointment as chairman in different government-run organisations under central government ministries and departments against huge pecuniary consideration”\
    Besides Rajya Sabha seats, the accused persons also promised to arrange governorship and chairmanship of different government organisations in lieu of bribes, they said.

    According to the first information report (FIR), filed on July 15 and reviewed by HT, those named include Kamalakar Premkumar Bandgar of Maharashtra’s Latur, Ravindra Vithal Naik of Karnataka’s Belgaum, and Delhi-NCR-based Mahendra Pal Arora, Abhishek Boora and Mohammed Aijaz Khan.
    
    The FIR alleged that Bandgar posed as a senior CBI officer and flaunted his connections with highly placed officials. He then asked Boora, Arora, Khan and Naik to bring any sort of work that he could fix in lieu of payment of huge illegal gratification.
    
    The accused, the CBI said, conspired with “the sole ulterior motive of cheating private persons by falsely assuring them for arrangement of seats in Rajya Sabha, appointment as governor, appointment as chairman in different government-run organisations under central government ministries and departments against huge pecuniary consideration”\
    Besides Rajya Sabha seats, the accused persons also promised to arrange governorship and chairmanship of different government organisations in lieu of bribes, they said.

    According to the first information report (FIR), filed on July 15 and reviewed by HT, those named include Kamalakar Premkumar Bandgar of Maharashtra’s Latur, Ravindra Vithal Naik of Karnataka’s Belgaum, and Delhi-NCR-based Mahendra Pal Arora, Abhishek Boora and Mohammed Aijaz Khan.
    
    The FIR alleged that Bandgar posed as a senior CBI officer and flaunted his connections with highly placed officials. He then asked Boora, Arora, Khan and Naik to bring any sort of work that he could fix in lieu of payment of huge illegal gratification.
    
    The accused, the CBI said, conspired with “the sole ulterior motive of cheating private persons by falsely assuring them for arrangement of seats in Rajya Sabha, appointment as governor, appointment as chairman in different government-run organisations under central government ministries and departments against huge pecuniary consideration”\
    Besides Rajya Sabha seats, the accused persons also promised to arrange governorship and chairmanship of different government organisations in lieu of bribes, they said.

    According to the first information report (FIR), filed on July 15 and reviewed by HT, those named include Kamalakar Premkumar Bandgar of Maharashtra’s Latur, Ravindra Vithal Naik of Karnataka’s Belgaum, and Delhi-NCR-based Mahendra Pal Arora, Abhishek Boora and Mohammed Aijaz Khan.
    
    The FIR alleged that Bandgar posed as a senior CBI officer and flaunted his connections with highly placed officials. He then asked Boora, Arora, Khan and Naik to bring any sort of work that he could fix in lieu of payment of huge illegal gratification.
    
    The accused, the CBI said, conspired with “the sole ulterior motive of cheating private persons by falsely assuring them for arrangement of seats in Rajya Sabha, appointment as governor, appointment as chairman in different government-run organisations under central government ministries and departments against huge pecuniary consideration”\
    ";




