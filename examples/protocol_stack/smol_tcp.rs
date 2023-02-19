mod common;

use std::{sync::{Arc, atomic::{AtomicBool, AtomicI64}}, time::Duration, io::Write, str::FromStr};

use clap::Parser;

use common::{stack::{RouterInfo, tcp::{TcpRepr, TcpControl, TcpSeqNumber}}, Producer};

use smoltcp::wire::*;
use smoltcp::wire::EthernetAddress;

#[derive(Parser)]
struct Flags {
  #[clap(short, long, default_value_t = 10)]
  pub period:u32,
  #[clap(short, long)]
  pub client:bool,
  #[clap(short,long="buf-size")]
  pub buffer:u32,
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

pub struct SmolTcpPacketProcesser {
  
}

impl common::stack::tcp::PacketProcesser for SmolTcpPacketProcesser {
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
    
    let mut epkt =  smoltcp::wire::EthernetFrame::new_unchecked(mbuf.data_mut()); 
    epkt.set_dst_addr(EthernetAddress(router_info.dest_mac.0));
    epkt.set_src_addr(EthernetAddress(router_info.src_mac.0));
    epkt.set_ethertype(EthernetProtocol::Ipv4);

    let mut ipv4_pkt =  Ipv4Packet::new_unchecked(epkt.payload_mut());
    ipv4_pkt.set_version(4);
    ipv4_pkt.set_header_len(common::IPV4_HEADER_LEN as u8);
    ipv4_pkt.set_dscp(0);
    ipv4_pkt.set_ecn(0);
    ipv4_pkt.set_total_len((common::IPV4_HEADER_LEN + header_len + payload_len) as u16);
    ipv4_pkt.set_ident(0x5c65);
    ipv4_pkt.clear_flags();
    ipv4_pkt.set_frag_offset(0);
    ipv4_pkt.set_hop_limit(64);
    ipv4_pkt.set_protocol(IpProtocol::Tcp);
    ipv4_pkt.set_src_addr(Ipv4Address(router_info.src_ipv4.0));
    ipv4_pkt.set_dst_addr(Ipv4Address(router_info.dest_ipv4.0));
    ipv4_pkt.fill_checksum();
    
    let mut tcp_pkt = TcpPacket::new_unchecked(ipv4_pkt.payload_mut());
    tcp_pkt.set_dst_port(router_info.dest_port);
    tcp_pkt.set_src_port(router_info.src_port);
    tcp_pkt.set_header_len(header_len as u8);
    tcp_pkt.set_seq_number(smoltcp::wire::TcpSeqNumber(repr.seq_number.0));
    tcp_pkt.set_urg(false);
    tcp_pkt.set_checksum(0);        
    tcp_pkt.set_ack_number(smoltcp::wire::TcpSeqNumber(repr.ack_number.unwrap_or_default().0));
    tcp_pkt.set_window_len(repr.window_len);
    match repr.ctrl {
      common::stack::tcp::TcpControl::None => (),
      common::stack::tcp::TcpControl::Psh => tcp_pkt.set_psh(true),
      common::stack::tcp::TcpControl::Syn => tcp_pkt.set_syn(true),
      common::stack::tcp::TcpControl::Fin => tcp_pkt.set_fin(true),
      common::stack::tcp::TcpControl::Rst => tcp_pkt.set_rst(true),
    }
    
    tcp_pkt.set_ack(repr.ack_number.is_some());
    
    {
      let mut options = tcp_pkt.options_mut();
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
    tcp_pkt.fill_checksum(&Ipv4Address(router_info.src_ipv4.0).into(),
                    &Ipv4Address(router_info.dest_ipv4.0).into());
    println!("-------Send Packet------");
    println!("{}",repr);
    println!("  total packet len:{}",total_header_overhead + tcp_pkt.payload_mut().len());    
  }

  fn parse(&mut self,mbuf:&mut run_dpdk::Mbuf) 
          -> Option<(common::stack::tcp::TcpRepr,
                     common::stack::RouterInfo,usize)> {
    let mut route_info:RouterInfo = RouterInfo::default();
    let mut tcprepr:TcpRepr = TcpRepr::default();
    let epkt = EthernetFrame::new_checked(mbuf.data()).ok()?; 
    if epkt.ethertype() != EthernetProtocol::Ipv4 {
      return None;
    }
    route_info.dest_mac = common::MacAddr(epkt.dst_addr().0);
    route_info.src_mac = common::MacAddr(epkt.src_addr().0);

    let ip_pkt = Ipv4Packet::new_checked(epkt.payload()).ok()?;
    if !ip_pkt.verify_checksum() {
        return None;
    }
    
    route_info.dest_ipv4 = common::Ipv4Addr(ip_pkt.dst_addr().0);
    route_info.src_ipv4 = common::Ipv4Addr(ip_pkt.src_addr().0);

    let total_packet_len = ip_pkt.total_len() + common::ETHER_HEADER_LEN as u16;    

    let tcp_pkt = TcpPacket::new_checked(ip_pkt.payload()).ok()?;
    if !tcp_pkt.verify_checksum(&Ipv4Address(route_info.dest_ipv4.0).into(), 
                        &Ipv4Address(route_info.src_ipv4.0).into()) {
        return None;
    }
    route_info.dest_port = tcp_pkt.dst_port();
    route_info.src_port = tcp_pkt.src_port();
    
    let payload_offset = common::ETHER_HEADER_LEN 
                              + common::IPV4_HEADER_LEN 
                              + tcp_pkt.header_len() as usize;
    
    tcprepr.ctrl = match (tcp_pkt.syn(),tcp_pkt.fin(),tcp_pkt.rst(),tcp_pkt.psh()) {
      (false, false, false, false) => TcpControl::None,
      (false, false, false, true) => TcpControl::Psh,
      (true, false, false, _) => TcpControl::Syn,
      (false, true, false, _) => TcpControl::Fin,
      (false, false, true, _) => TcpControl::Rst,
      _ => return None,
    };

    tcprepr.ack_number = if tcp_pkt.ack() {
      Some(common::stack::tcp::TcpSeqNumber(tcp_pkt.ack_number().0))
    } else {
      None
    };
    
    tcprepr.seq_number = common::stack::tcp::TcpSeqNumber(tcp_pkt.seq_number().0);
    tcprepr.window_len = tcp_pkt.window_len();
    tcprepr.max_seg_size = None;
    tcprepr.window_scale = None;
    tcprepr.sack_permitted = false;
    tcprepr.sack_ranges = [None,None,None];

    
    let mut options = tcp_pkt.options();
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

    println!("----Recevied a pakcet-----");
    println!("{}",tcprepr);
    println!("  packet len:{}",total_packet_len);
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
    let mut file = match std::fs::File::create("./data/smol_tcp.csv") {
      Ok(f) => f,
      Err(err) => {
        log::log!(log::Level::Error,"can not open `./data/smol_tcp.csv`. \
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


  let processer = SmolTcpPacketProcesser{};
  let mut device = common::DpdkDevice::new(SERVER_PORT_ID).unwrap();
  let mut stack = common::stack::tcp::TcpStack::new(
    sender, recver, 
    processer, 
    args.buffer as usize, 
    64);
  
  stack.set_mtu(1518);
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

  let jh = std::thread::spawn(move || {
    let mut last_sent_bytes = 0;
    let mut last_recv_bytes = 0;
    let mut file = match std::fs::File::create("./data/smol_tcp.csv") {
      Ok(f) => f,
      Err(err) => {
        log::log!(log::Level::Error,"can not open `./data/smol_tcp.csv`. \
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

  let processer = SmolTcpPacketProcesser{};
  let mut device = common::DpdkDevice::new(CLIENT_PORT_ID).unwrap();
  let mut stack = common::stack::tcp::TcpStack::new(
    sender, recver, 
    processer, 
    64, 
    args.buffer as usize);
  
  stack.set_mtu(1518);
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