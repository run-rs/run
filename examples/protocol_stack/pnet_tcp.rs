mod common;

use std::{sync::{Arc, atomic::{AtomicBool, AtomicI64}}, time::Duration, io::Write, str::FromStr};

use arrayvec::ArrayVec;
use clap::Parser;

use common::{stack::{RouterInfo, tcp::{TcpRepr, TcpControl, TcpSeqNumber}}, Producer};

use pnet::packet::{ipv4::*, MutablePacket, Packet};
use pnet::packet::tcp::*;
use pnet::packet::ethernet::*;
use run_packet::Buf;

#[derive(Parser)]
struct Flags {
  #[clap(short, long, default_value_t = 10)]
  pub period:u32,
  #[clap(short, long)]
  pub client:bool,
  #[clap(short,long="buf-size")]
  pub buffer:u32,
  #[clap(long="mtu",default_value_t=1518)]
  pub mtu:usize
}

struct Sender {
  pub sent_bytes:Arc<AtomicI64>,
  pub data:Vec<u8>,
}

impl Sender {
  pub fn new(size:usize) -> Self {
    Sender {
      sent_bytes: Arc::new(AtomicI64::new(0)),
      data: vec![0;size],
    }
  }
}

impl common::Producer for Sender {
  fn produce(&mut self,size:usize) -> Option<&[u8]> {
    //self.write_at %= self.len;
    //let remaining_len = self.len - self.write_at;
    //let sent_util = std::cmp::min(remaining_len,size) + self.write_at;
    self.sent_bytes.fetch_add((size) as i64, std::sync::atomic::Ordering::Relaxed);
    //log::log!(log::Level::Trace,"Sender: produce {} bytes",size);
    return Some(&self.data[..size]);
  }
}


struct Receiver {
  pub recv_bytes:Arc<AtomicI64>,
  pub buffer: Vec<u8>,
}

impl Receiver {
  pub fn new(size:usize) -> Self {
    Receiver { 
      recv_bytes: Arc::new(AtomicI64::new(0)), 
      buffer: vec![0;size] }
  }
}

impl common::Consumer for Receiver {
  fn consume(&mut self,size:usize) -> &mut [u8] {
    assert!(self.buffer.len() > size);
    //log::log!(log::Level::Trace,"Receiver: consume {} bytes",size);
    self.recv_bytes.fetch_add(size as i64, std::sync::atomic::Ordering::Relaxed);
    return &mut self.buffer[..size];
  }
}

struct SendNothing {
  pub sent_bytes:Arc<AtomicI64>
}

impl SendNothing {
  pub fn new() -> Self {
    SendNothing { 
      sent_bytes:  Arc::new(AtomicI64::new(0))
    }
  }
}

impl Producer for SendNothing {
  fn produce(&mut self,size:usize) -> Option<&[u8]> {
      return Some(&[])
  }
}

pub struct PnetTcpPacketProcesser {
  
}

impl common::stack::tcp::PacketProcesser for PnetTcpPacketProcesser {
  fn build(&mut self,mbuf:&mut run_dpdk::Mbuf,
          repr:&common::stack::tcp::TcpRepr,
          router_info:&common::stack::RouterInfo) {
    
    let mut header_len = common::TCP_HEADER_LEN;
    if repr.max_seg_size.is_some() {
      header_len += 4;
    }
    if repr.window_scale.is_some() {
      header_len += 3;
    }
    if repr.sack_permitted {
      header_len += 2;
    }
    let sack_range_len:usize = repr.sack_ranges
                             .iter()
                             .map(|o| o.map(|_| 8).unwrap_or(0))
                             .sum();
    if sack_range_len >0 {
      header_len += sack_range_len + 2;
    }
    if header_len % 4 != 0 {
      header_len += 4 - header_len % 4;
    }

    let total_header_overhead = header_len + common::ETHER_HEADER_LEN + common::IPV4_HEADER_LEN;
    let payload_len = mbuf.len();
    unsafe { mbuf.extend_front(total_header_overhead) };
//    println!("mbuf length: header {} + payload {}",total_header_overhead,payload_len);    
    let mut epkt = pnet::packet::ethernet::MutableEthernetPacket::new(mbuf.data_mut()).unwrap();
    epkt.set_destination(router_info.dest_mac.0.into());
    epkt.set_source(router_info.src_mac.0.into());
    epkt.set_ethertype(EtherTypes::Ipv4);
    
//    println!("ethernet packet payload length:{}",epkt.payload().len());

    let mut ipv4_pkt = MutableIpv4Packet::new(epkt.payload_mut()).unwrap();
    ipv4_pkt.set_version(4);
    ipv4_pkt.set_header_length(5);
//    println!("ipv4 packet header length:{}",ipv4_pkt.get_header_length());
    ipv4_pkt.set_dscp(0);
    ipv4_pkt.set_ecn(0);
    ipv4_pkt.set_total_length((common::IPV4_HEADER_LEN + header_len + payload_len) as u16);
//    println!("ipv4 packet total length: {}",ipv4_pkt.get_total_length());
    ipv4_pkt.set_identification(0x5c65);
    // ipv4_pkt.clear_flags();
    ipv4_pkt.set_flags(0);
    ipv4_pkt.set_fragment_offset(0);
    ipv4_pkt.set_ttl(64);
    ipv4_pkt.set_next_level_protocol(pnet::packet::ip::IpNextHeaderProtocols::Tcp);
    ipv4_pkt.set_source(router_info.src_ipv4.0.into());
//    assert_eq!(ipv4_pkt.get_source().octets(),router_info.src_ipv4.0);
    ipv4_pkt.set_destination(router_info.dest_ipv4.0.into());
    ipv4_pkt.set_checksum(0);
    let checksum = pnet::packet::ipv4::checksum(&ipv4_pkt.to_immutable());
    ipv4_pkt.set_checksum(checksum);
    
//    println!("ipv4 packet payload length:{}",ipv4_pkt.payload().len());

    let mut tcp_pkt = MutableTcpPacket::new(ipv4_pkt.payload_mut()).unwrap();
    tcp_pkt.set_destination(router_info.dest_port);
    tcp_pkt.set_source(router_info.src_port);
    tcp_pkt.set_data_offset(((header_len + 3) / 4) as u8);
    tcp_pkt.set_sequence(repr.seq_number.0 as u32);
    tcp_pkt.set_urgent_ptr(0);
    tcp_pkt.set_checksum(0);        
    let ack = repr.ack_number.unwrap_or_default().0 as u32;
    tcp_pkt.set_acknowledgement(ack);
    tcp_pkt.set_window(repr.window_len);
    let mut flags = 0; 
    match repr.ctrl {
      common::stack::tcp::TcpControl::None => (),
      common::stack::tcp::TcpControl::Psh => flags |= TcpFlags::PSH,
      common::stack::tcp::TcpControl::Syn => flags |= TcpFlags::SYN,
      common::stack::tcp::TcpControl::Fin => flags |= TcpFlags::FIN,
      common::stack::tcp::TcpControl::Rst => flags |= TcpFlags::RST,
    }
    if repr.ack_number.is_some() {
      flags |= TcpFlags::ACK;
    }
    tcp_pkt.set_flags(flags);
    
    {
      let mut options = tcp_pkt.get_options_raw_mut();
      if let Some(value) = repr.max_seg_size {
        let tmp = options;
        options = run_packet::tcp::TcpOption::MaxSegmentSize(value).build(tmp);
      }
      if let Some(value) = repr.window_scale {
        let tmp = options;
        options = run_packet::tcp::TcpOption::WindowScale(value).build(tmp);
      }
      if repr.sack_permitted {
        let tmp = options;
        options = run_packet::tcp::TcpOption::SackPermitted.build(tmp);
      } else if repr.ack_number.is_some() 
        && repr.sack_ranges.iter().any(|s| s.is_some()) {
        let tmp = options;
        options = run_packet::tcp::TcpOption::SackRange(repr.sack_ranges).build(tmp);
      }

      if !options.is_empty() {
        run_packet::tcp::TcpOption::EndOfList.build(options);
      }
    }
  
    let checksum = ipv4_checksum(&tcp_pkt.to_immutable(), 
                                &router_info.src_ipv4.0.into(),
                            &router_info.dest_ipv4.0.into());
    
    tcp_pkt.set_checksum(checksum);
    /*println!("Send a packet: ");
    println!("  ack number:{}",tcp_pkt.get_acknowledgement());
    println!("  seq number:{}",tcp_pkt.get_sequence());
    println!("  payload length:{}",tcp_pkt.payload().len());
    println!("  flags:{}",{
      let mut s = String::new();
      if (flags&TcpFlags::ACK) != 0 {
        s.push_str("ACK ");
      }
      if (flags&TcpFlags::SYN) !=0 {
        s.push_str("SYN ")
      }
      if (flags&TcpFlags::FIN) !=0 {
        s.push_str("FIN ")
      }
      s
    });*/

//    println!("tcp packet header length: {} {}",header_len,tcp_pkt.get_data_offset() * 4);
//    println!("tcp packet payload length: {}",tcp_pkt.payload().len());
//    {
      //println!("Send a packet: ");
  //    let pbuf = run_dpdk::Pbuf::new(mbuf);
    //  let ethpkt = run_packet::ether::EtherPacket::parse(pbuf).unwrap();
//      println!("  dest mac:{}",ethpkt.dest_mac());
//      println!("  src mac:{}",ethpkt.source_mac());
//      println!("  ethernet type: {}",match ethpkt.ethertype() {
//        run_packet::ether::EtherType::IPV4 => "ipv4",
//        _ => "unkown",
//      });
      //let payload = ethpkt.payload();
      //println!("  ethernet payload length: {}",payload.remaining());
      //assert_eq!(ethpkt.ethertype(),run_packet::ether::EtherType::IPV4);
      //let ipv4pkt = /*match run_packet::ipv4::Ipv4Packet::parse(payload) {
        //Ok(v) => v,
        //Err(_) => {
          //println!("bad ipv4 packet");
          //return;
        //}
      //};*///run_packet::ipv4::Ipv4Packet::parse_unchecked(payload);
     // println!("  src ipv4: {}",ipv4pkt.source_ip());
     // println!("  dest ipv4: {}",ipv4pkt.dest_ip());
     // println!("  protocol:{}",ipv4pkt.protocol());
      //println!("  ipv4 header len:{}",ipv4pkt.header_len());
      //println!("  ipv4 packet len:{}",ipv4pkt.packet_len());
      //println!("  ipv4 checksum: {}",{if ipv4pkt.verify_checksum() {
        //ipv4pkt.checksum().to_string()
      //} else {
       // String::from_str("Bad").unwrap()
      //}});
      //let tcppkt = run_packet::tcp::TcpPacket::parse(ipv4pkt.payload()).unwrap();
      //println!("  src port:{}",tcppkt.src_port());
      //println!("  dest port:{}",tcppkt.dst_port());
      //println!("  header len:{}",tcppkt.header_len());
      //println!("  ack number:{}",tcppkt.ack_number());
      //println!("  window len:{}",tcppkt.window_size());
      //println!("  seq number:{}",tcppkt.seq_number());
    //}

  }

  fn parse(&mut self,mbuf:&mut run_dpdk::Mbuf) 
          -> Option<(common::stack::tcp::TcpRepr,
                     common::stack::RouterInfo,usize)> {
    let mut route_info:RouterInfo = RouterInfo::default();
    let mut tcprepr:TcpRepr = TcpRepr::default();
    
    let eth_pkt = EthernetPacket::new(mbuf.data())?;
    if eth_pkt.get_ethertype() != EtherTypes::Ipv4 {
      return None;
    }
    route_info.dest_mac = common::MacAddr(eth_pkt.get_destination().octets());
    route_info.src_mac = common::MacAddr(eth_pkt.get_source().octets());

    let ip_pkt = Ipv4Packet::new(eth_pkt.payload())?;
    let checksum = ip_pkt.get_checksum();
    if pnet::packet::ipv4::checksum(&ip_pkt) != checksum {
      return None;
    }
    route_info.dest_ipv4 = common::Ipv4Addr(ip_pkt.get_destination().octets());
    route_info.src_ipv4 = common::Ipv4Addr(ip_pkt.get_source().octets());

    let total_packet_len = ip_pkt.get_total_length() + common::ETHER_HEADER_LEN as u16;    

    let tcp_pkt = TcpPacket::new(ip_pkt.payload())?;
    let checksum = tcp_pkt.get_checksum();
    if pnet::packet::tcp
        ::ipv4_checksum(&tcp_pkt, 
                        &route_info.src_ipv4.0.into(),
                   &route_info.dest_ipv4.0.into()) != checksum {
      return None;
    }

    route_info.dest_port = tcp_pkt.get_destination();
    route_info.src_port = tcp_pkt.get_source();
    
    let payload_offset = common::ETHER_HEADER_LEN 
                              + common::IPV4_HEADER_LEN 
                              + (tcp_pkt.get_data_offset() * 4) as usize;
    let flags = tcp_pkt.get_flags();
    let syn = TcpFlags::SYN & flags != 0;
    let fin = TcpFlags::FIN & flags != 0;
    let psh = TcpFlags::PSH & flags != 0;
    let rst = TcpFlags::RST & flags != 0;
    let ack = TcpFlags::ACK & flags != 0;
    tcprepr.ctrl = match (syn,fin,rst,psh) {
      (false, false, false, false) => TcpControl::None,
      (false, false, false, true) => TcpControl::Psh,
      (true, false, false, _) => TcpControl::Syn,
      (false, true, false, _) => TcpControl::Fin,
      (false, false, true, _) => TcpControl::Rst,
      _ => return None,
    };

    tcprepr.ack_number = if ack {
      Some(TcpSeqNumber(tcp_pkt.get_acknowledgement() as i32))
    } else {
      None
    };
    
    tcprepr.seq_number = TcpSeqNumber(tcp_pkt.get_sequence() as i32);
    tcprepr.window_len = tcp_pkt.get_window();
    tcprepr.max_seg_size = None;
    tcprepr.window_scale = None;
    tcprepr.sack_permitted = false;
    tcprepr.sack_ranges = [None,None,None];

    
    let mut options = tcp_pkt.get_options_raw();
    while !options.is_empty() {
      let (next_options, option) = run_packet::tcp::TcpOption::parse(options).ok()?;
      match option {
        run_packet::tcp::TcpOption::EndOfList => break,
        run_packet::tcp::TcpOption::NoOperation => (),
        run_packet::tcp::TcpOption::MaxSegmentSize(value) => tcprepr.max_seg_size = Some(value),
        run_packet::tcp::TcpOption::WindowScale(value) => {
            // RFC 1323: Thus, the shift count must be limited to 14 (which allows windows
            // of 2**30 = 1 Gbyte). If a Window Scale option is received with a shift.cnt
            // value exceeding 14, the TCP should log the error but use 14 instead of the
            // specified value.
            tcprepr.window_scale = if value > 14 {
                Some(14)
            } else {
                Some(value)
            };
        }
        run_packet::tcp::TcpOption::SackPermitted => tcprepr.sack_permitted = true,
        run_packet::tcp::TcpOption::SackRange(slice) => tcprepr.sack_ranges = slice,
        _ => (),
      }
      options = next_options;
    }
    /*println!("received a tcp packet:");
    println!("  ack: {}",match tcprepr.ack_number {
      Some(v) => v.0.to_string(),
      _ => String::from_str("None").unwrap(),
    });
    println!("  seq number: {}",tcprepr.seq_number.0 as u32);
    println!("  window size: {}",tcprepr.window_len);
    println!("  header len: {}",tcp_pkt.get_data_offset());
    println!("  payload len: {}",tcp_pkt.payload().len());
    println!("  mbuf data:{}",mbuf.len());
    println!("  total header:{}",tcp_pkt.get_data_offset() as usize *4 as usize + common::IPV4_HEADER_LEN + common::ETHER_HEADER_LEN);
    println!("  flags:{}",{
      let mut s = String::new();
      if (flags&TcpFlags::ACK) != 0 {
        s.push_str("ACK ");
      }
      if (flags&TcpFlags::SYN) !=0 {
        s.push_str("SYN ")
      }
      if (flags&TcpFlags::FIN) !=0 {
        s.push_str("FIN ")
      }
      s
    });*/

    mbuf.truncate(total_packet_len as usize);
    Some((tcprepr,route_info,payload_offset))
  }
}

fn server_start(args:&Flags) {
  let sender = SendNothing::new();
  let recver = Receiver::new(args.buffer as usize);

  let sent_bytes = sender.sent_bytes.clone();
  let recv_bytes = recver.recv_bytes.clone();
  
  let run = Arc::new(AtomicBool::new(true));
  let run_clone = run.clone();
  let run_ctrlc = run.clone();
  let mut max_secs = args.period;

  ctrlc::set_handler(move || {
    run_ctrlc.store(false, std::sync::atomic::Ordering::Relaxed);
  })
  .unwrap();

  let jh = std::thread::spawn(move || {
    let mut last_sent_bytes = 0;
    let mut last_recv_bytes = 0;
    let mut file = match std::fs::File::create("./data/pnet_tcp.csv") {
      Ok(f) => f,
      Err(err) => {
        log::log!(log::Level::Error,"can not open `./data/pnet_tcp.csv`. \
                please launch at top workspace. : {}",err);
        run_clone.store(false, std::sync::atomic::Ordering::Relaxed);
        return;
      }
    };
    match file.write_all(b"rx bps(Gbps),tx bps(Gbps)\n") {
      Err(err) => {
        log::log!(log::Level::Error,"failed to write : {}",err);
        run_clone.store(false, std::sync::atomic::Ordering::Relaxed);
        return;
      },
      _ => (),
    };
    while run_clone.load(std::sync::atomic::Ordering::Relaxed) {
      if max_secs == 0 {
        break;
      }
      std::thread::sleep(Duration::from_secs(1));
      // write to csv file
      let sent_total = sent_bytes.load(std::sync::atomic::Ordering::Relaxed);
      let recv_total = recv_bytes.load(std::sync::atomic::Ordering::Relaxed);
      let sent_diff = sent_total - last_sent_bytes;
      let recv_diff = recv_total - last_recv_bytes;
      last_recv_bytes = recv_total;
      last_sent_bytes = sent_total;

      assert!(sent_diff >= 0 );
      assert!(recv_diff >= 0 );

      let tx_bps = (sent_diff as f64) * 8.0 / 1000000000.0;
      let rx_bps = (recv_diff as f64) * 8.0 / 1000000000.0;

      match file.write_all(format!("{},{}\n",rx_bps,tx_bps).as_bytes()) {
        Ok(_) => (),
        Err(err) => {
          log::log!(log::Level::Error,"failed to write : {}",err);
          break;
        }
      }
      max_secs -= 1;
    }
    run_clone.store(false, std::sync::atomic::Ordering::Relaxed);
  });


  let processer = PnetTcpPacketProcesser{};
  let mut device = common::DpdkDevice::new(SERVER_PORT_ID).unwrap();
  let mut stack = common::stack::tcp::TcpStack::new(
    sender, recver, 
    processer, 
    args.buffer as usize, 
    64);
  
  stack.set_mtu(args.mtu);
  stack.bind(SERVER_LOCAL_IPV4, SERVER_PORT, SERVER_LOCAL_MAC);
  stack.listen(SERVER_REMOTE_IPV4, CLIENT_PORT, SERVER_REMOTE_MAC);
  common::poll(run,&mut device, &mut stack);
  jh.join().unwrap();
}

fn client_start(args:&Flags) {
  let sender = Sender::new(args.buffer as usize);
  let recver = Receiver::new(64);

  let sent_bytes = sender.sent_bytes.clone();
  let recv_bytes = recver.recv_bytes.clone();
  
  let run = Arc::new(AtomicBool::new(true));
  let run_clone = run.clone();
  let run_ctrlc = run.clone();
  let mut max_secs = args.period;

  ctrlc::set_handler(move || {
    run_ctrlc.store(false, std::sync::atomic::Ordering::Relaxed);
  })
  .unwrap();
  let mtu = args.mtu;
  let jh = std::thread::spawn(move || {
    let mut last_sent_bytes = 0;
    let mut last_recv_bytes = 0;
    let mut file = match std::fs::File::create("./data/pnet_tcp.csv") {
      Ok(f) => f,
      Err(err) => {
        log::log!(log::Level::Error,"can not open `./data/pnet_tcp.csv`. \
                please launch at top workspace. : {}",err);
        run_clone.store(false, std::sync::atomic::Ordering::Relaxed);
        return;
      }
    };
    match file.write_all(b"mtu,tx bps(Gbps)\n") {
      Err(err) => {
        log::log!(log::Level::Error,"failed to write : {}",err);
        run_clone.store(false, std::sync::atomic::Ordering::Relaxed);
        return;
      },
      _ => (),
    };
    while run_clone.load(std::sync::atomic::Ordering::Relaxed) {
      if max_secs == 0 {
        break;
      }
      std::thread::sleep(Duration::from_secs(1));
      // write to csv file
      let sent_total = sent_bytes.load(std::sync::atomic::Ordering::Relaxed);
      let recv_total = recv_bytes.load(std::sync::atomic::Ordering::Relaxed);
      let sent_diff = sent_total - last_sent_bytes;
      let recv_diff = recv_total - last_recv_bytes;
      last_recv_bytes = recv_total;
      last_sent_bytes = sent_total;

      assert!(sent_diff >= 0 );
      assert!(recv_diff >= 0 );

      let tx_bps = (sent_diff as f64) * 8.0 / 1000000000.0;
      let rx_bps = (recv_diff as f64) * 8.0 / 1000000000.0;

      match file.write_all(format!("{},{}\n",mtu,tx_bps).as_bytes()) {
        Ok(_) => (),
        Err(err) => {
          log::log!(log::Level::Error,"failed to write : {}",err);
          break;
        }
      }
      max_secs -= 1;
    }
    run_clone.store(false, std::sync::atomic::Ordering::Relaxed);
  });

  let processer = PnetTcpPacketProcesser{};
  let mut device = common::DpdkDevice::new(CLIENT_PORT_ID).unwrap();
  let mut stack = common::stack::tcp::TcpStack::new(
    sender, recver, 
    processer, 
    64, 
    args.buffer as usize);
  
  stack.set_mtu(mtu);
  stack.bind(CLINET_LOCAL_IPV4, CLIENT_PORT, CLIENT_LOCAL_MAC);
  stack.connect(CLIENT_REMOTE_IPV4, SERVER_PORT, CLIENT_REMOTE_MAC);
  common::poll(run,&mut device, &mut stack);

  jh.join().unwrap();
}

const CLIENT_PORT_ID:u16 = 3;
const CLIENT_PORT:u16 = 9000;
const CLINET_LOCAL_IPV4:common::Ipv4Addr = common::Ipv4Addr([192,168,22,2]);
const CLIENT_REMOTE_IPV4:common::Ipv4Addr = common::Ipv4Addr([192,168,23,2]);
const CLIENT_LOCAL_MAC:common::MacAddr = common::MacAddr([0x10, 0x70, 0xfd, 0x15, 0x77, 0xbf]);
const CLIENT_REMOTE_MAC:common::MacAddr = common::MacAddr([0x08, 0x68, 0x8d, 0x61, 0x69, 0x28]);

const SERVER_PORT_ID:u16 = 0;
const SERVER_PORT:u16 = 9000;
const SERVER_LOCAL_IPV4:common::Ipv4Addr = common::Ipv4Addr([192,168,23,2]);
const SERVER_REMOTE_IPV4:common::Ipv4Addr = common::Ipv4Addr([192,168,22,2]);
const SERVER_LOCAL_MAC:common::MacAddr = common::MacAddr([0x10, 0x70, 0xfd, 0x15, 0x77, 0xc1]);
const SERVER_REMOTE_MAC:common::MacAddr = common::MacAddr([0x08, 0x68, 0x8d, 0x61, 0x69, 0x28]);

fn main() {
  env_logger::init();
  let args = Flags::parse();
  if !args.client {
    println!("start server");
    server_start(&args);
  } else {
    println!("start client");
    client_start(&args);
  }
}