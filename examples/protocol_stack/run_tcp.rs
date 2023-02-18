mod common;

use std::{str::FromStr};

use clap::Parser;

use common::stack::{RouterInfo, tcp::{TcpRepr, TcpControl, TcpSeqNumber, self}};
use run_dpdk::Pbuf;
use run_packet::{tcp::{TcpHeader,TcpPacket, TcpOption}, ipv4::{Ipv4Packet, IpProtocol, IPV4_HEADER_TEMPLATE, IPV4_HEADER_LEN, Ipv4Addr}, ether::{EtherPacket, MacAddr, EtherType, ETHER_HEADER_TEMPLATE, ETHER_HEADER_LEN}, PktMut, Buf};


#[derive(Parser)]
struct Flags {
  /* #[clap(long = "rx_buf_size",default_value_t = 8192)]
  pub rx_buffer:u32,
  #[clap(long = "tx_buf_size",default_value_t = 8192)]
  pub tx_buffer:u32,
  #[clap(long = "bind", required = true)]
  pub bind:String,
  #[clap(long = "connect")]
  pub connect:Option<String>,
  #[clap(long = "mac",required = true)]
  pub mac:String */

  #[clap(short, long)]
  pub client:bool
}

struct Sender {
  pub sent_bytes:u64,
  pub data:String,
  write_at:usize,
  len: usize,
}

impl Sender {
  pub fn new() -> Self {
    let data = String::from_str(
      "We launched ChatGPT as a research preview so we could \
      learn more about the system’s strengths and weaknesses \
      and gather user feedback to help us improve upon its \
      limitations. Since then, millions of people have given \
      us feedback, we’ve made several important updates and \
      we’ve seen users find value across a range of \
      professional use-cases, including drafting & \
      editing content, brainstorming ideas, programming help, \
      and learning new topics
      We launched ChatGPT as a research preview so we could \
      learn more about the system’s strengths and weaknesses \
      and gather user feedback to help us improve upon its \
      limitations. Since then, millions of people have given \
      us feedback, we’ve made several important updates and \
      we’ve seen users find value across a range of \
      professional use-cases, including drafting & \
      editing content, brainstorming ideas, programming help, \
      and learning new topics
      We launched ChatGPT as a research preview so we could \
      learn more about the system’s strengths and weaknesses \
      and gather user feedback to help us improve upon its \
      limitations. Since then, millions of people have given \
      us feedback, we’ve made several important updates and \
      we’ve seen users find value across a range of \
      professional use-cases, including drafting & \
      editing content, brainstorming ideas, programming help, \
      and learning new topics
      We launched ChatGPT as a research preview so we could \
      learn more about the system’s strengths and weaknesses \
      and gather user feedback to help us improve upon its \
      limitations. Since then, millions of people have given \
      us feedback, we’ve made several important updates and \
      we’ve seen users find value across a range of \
      professional use-cases, including drafting & \
      editing content, brainstorming ideas, programming help, \
      and learning new topics
      We launched ChatGPT as a research preview so we could \
      learn more about the system’s strengths and weaknesses \
      and gather user feedback to help us improve upon its \
      limitations. Since then, millions of people have given \
      us feedback, we’ve made several important updates and \
      we’ve seen users find value across a range of \
      professional use-cases, including drafting & \
      editing content, brainstorming ideas, programming help, \
      and learning new topics
      We launched ChatGPT as a research preview so we could \
      learn more about the system’s strengths and weaknesses \
      and gather user feedback to help us improve upon its \
      limitations. Since then, millions of people have given \
      us feedback, we’ve made several important updates and \
      we’ve seen users find value across a range of \
      professional use-cases, including drafting & \
      editing content, brainstorming ideas, programming help, \
      and learning new topics
      We launched ChatGPT as a research preview so we could \
      learn more about the system’s strengths and weaknesses \
      and gather user feedback to help us improve upon its \
      limitations. Since then, millions of people have given \
      us feedback, we’ve made several important updates and \
      we’ve seen users find value across a range of \
      professional use-cases, including drafting & \
      editing content, brainstorming ideas, programming help, \
      and learning new topics
      We launched ChatGPT as a research preview so we could \
      learn more about the system’s strengths and weaknesses \
      and gather user feedback to help us improve upon its \
      limitations. Since then, millions of people have given \
      us feedback, we’ve made several important updates and \
      we’ve seen users find value across a range of \
      professional use-cases, including drafting & \
      editing content, brainstorming ideas, programming help, \
      and learning new topics
      We launched ChatGPT as a research preview so we could \
      learn more about the system’s strengths and weaknesses \
      and gather user feedback to help us improve upon its \
      limitations. Since then, millions of people have given \
      us feedback, we’ve made several important updates and \
      we’ve seen users find value across a range of \
      professional use-cases, including drafting & \
      editing content, brainstorming ideas, programming help, \
      and learning new topics
      We launched ChatGPT as a research preview so we could \
      learn more about the system’s strengths and weaknesses \
      and gather user feedback to help us improve upon its \
      limitations. Since then, millions of people have given \
      us feedback, we’ve made several important updates and \
      we’ve seen users find value across a range of \
      professional use-cases, including drafting & \
      editing content, brainstorming ideas, programming help, \
      and learning new topics
      We launched ChatGPT as a research preview so we could \
      learn more about the system’s strengths and weaknesses \
      and gather user feedback to help us improve upon its \
      limitations. Since then, millions of people have given \
      us feedback, we’ve made several important updates and \
      we’ve seen users find value across a range of \
      professional use-cases, including drafting & \
      editing content, brainstorming ideas, programming help, \
      and learning new topics
      We launched ChatGPT as a research preview so we could \
      learn more about the system’s strengths and weaknesses \
      and gather user feedback to help us improve upon its \
      limitations. Since then, millions of people have given \
      us feedback, we’ve made several important updates and \
      we’ve seen users find value across a range of \
      professional use-cases, including drafting & \
      editing content, brainstorming ideas, programming help, \
      and learning new topics
      We launched ChatGPT as a research preview so we could \
      learn more about the system’s strengths and weaknesses \
      and gather user feedback to help us improve upon its \
      limitations. Since then, millions of people have given \
      us feedback, we’ve made several important updates and \
      we’ve seen users find value across a range of \
      professional use-cases, including drafting & \
      editing content, brainstorming ideas, programming help, \
      and learning new topics
      We launched ChatGPT as a research preview so we could \
      learn more about the system’s strengths and weaknesses \
      and gather user feedback to help us improve upon its \
      limitations. Since then, millions of people have given \
      us feedback, we’ve made several important updates and \
      we’ve seen users find value across a range of \
      professional use-cases, including drafting & \
      editing content, brainstorming ideas, programming help, \
      and learning new topics
      We launched ChatGPT as a research preview so we could \
      learn more about the system’s strengths and weaknesses \
      and gather user feedback to help us improve upon its \
      limitations. Since then, millions of people have given \
      us feedback, we’ve made several important updates and \
      we’ve seen users find value across a range of \
      professional use-cases, including drafting & \
      editing content, brainstorming ideas, programming help, \
      and learning new topics
      We launched ChatGPT as a research preview so we could \
      learn more about the system’s strengths and weaknesses \
      and gather user feedback to help us improve upon its \
      limitations. Since then, millions of people have given \
      us feedback, we’ve made several important updates and \
      we’ve seen users find value across a range of \
      professional use-cases, including drafting & \
      editing content, brainstorming ideas, programming help, \
      and learning new topics
      We launched ChatGPT as a research preview so we could \
      learn more about the system’s strengths and weaknesses \
      and gather user feedback to help us improve upon its \
      limitations. Since then, millions of people have given \
      us feedback, we’ve made several important updates and \
      we’ve seen users find value across a range of \
      professional use-cases, including drafting & \
      editing content, brainstorming ideas, programming help, \
      and learning new topics
      We launched ChatGPT as a research preview so we could \
      learn more about the system’s strengths and weaknesses \
      and gather user feedback to help us improve upon its \
      limitations. Since then, millions of people have given \
      us feedback, we’ve made several important updates and \
      we’ve seen users find value across a range of \
      professional use-cases, including drafting & \
      editing content, brainstorming ideas, programming help, \
      and learning new topics
      We launched ChatGPT as a research preview so we could \
      learn more about the system’s strengths and weaknesses \
      and gather user feedback to help us improve upon its \
      limitations. Since then, millions of people have given \
      us feedback, we’ve made several important updates and \
      we’ve seen users find value across a range of \
      professional use-cases, including drafting & \
      editing content, brainstorming ideas, programming help, \
      and learning new topics
      We launched ChatGPT as a research preview so we could \
      learn more about the system’s strengths and weaknesses \
      and gather user feedback to help us improve upon its \
      limitations. Since then, millions of people have given \
      us feedback, we’ve made several important updates and \
      we’ve seen users find value across a range of \
      professional use-cases, including drafting & \
      editing content, brainstorming ideas, programming help, \
      and learning new topics
      We launched ChatGPT as a research preview so we could \
      learn more about the system’s strengths and weaknesses \
      and gather user feedback to help us improve upon its \
      limitations. Since then, millions of people have given \
      us feedback, we’ve made several important updates and \
      we’ve seen users find value across a range of \
      professional use-cases, including drafting & \
      editing content, brainstorming ideas, programming help, \
      and learning new topics
      We launched ChatGPT as a research preview so we could \
      learn more about the system’s strengths and weaknesses \
      and gather user feedback to help us improve upon its \
      limitations. Since then, millions of people have given \
      us feedback, we’ve made several important updates and \
      we’ve seen users find value across a range of \
      professional use-cases, including drafting & \
      editing content, brainstorming ideas, programming help, \
      and learning new topics
      We launched ChatGPT as a research preview so we could \
      learn more about the system’s strengths and weaknesses \
      and gather user feedback to help us improve upon its \
      limitations. Since then, millions of people have given \
      us feedback, we’ve made several important updates and \
      we’ve seen users find value across a range of \
      professional use-cases, including drafting & \
      editing content, brainstorming ideas, programming help, \
      and learning new topics
      We launched ChatGPT as a research preview so we could \
      learn more about the system’s strengths and weaknesses \
      and gather user feedback to help us improve upon its \
      limitations. Since then, millions of people have given \
      us feedback, we’ve made several important updates and \
      we’ve seen users find value across a range of \
      professional use-cases, including drafting & \
      editing content, brainstorming ideas, programming help, \
      and learning new topics
      We launched ChatGPT as a research preview so we could \
      learn more about the system’s strengths and weaknesses \
      and gather user feedback to help us improve upon its \
      limitations. Since then, millions of people have given \
      us feedback, we’ve made several important updates and \
      we’ve seen users find value across a range of \
      professional use-cases, including drafting & \
      editing content, brainstorming ideas, programming help, \
      and learning new topics").unwrap();
    let len = data.len();
    Sender {
      sent_bytes: 0,
      data: data,
      write_at:0,
      len: len
    }
  }
}

impl common::Producer for Sender {
  fn produce(&mut self,size:usize) -> Option<&[u8]> {
    let max_sent_bytes = 400000000000; // 400Gb 
    if self.sent_bytes > max_sent_bytes {
      return None;
    }
    self.write_at %= self.len;
    let remaining_len = self.len - self.write_at;
    let sent_util = std::cmp::min(remaining_len,size) + self.write_at;
    self.sent_bytes += (sent_util - self.write_at) as u64;
    log::log!(log::Level::Trace,"Sender: produce {} bytes",sent_util - self.write_at);
    return Some(&self.data.as_bytes()[self.write_at..sent_util]);
  }
}


struct Receiver {
  pub recv_bytes:u64,
  pub buffer: Vec<u8>,
}

impl Receiver {
  pub fn new(size:usize) -> Self {
    Receiver { 
      recv_bytes: 0, 
      buffer: vec![0;size] }
  }
}

impl common::Consumer for Receiver {
  fn consume(&mut self,size:usize) -> &mut [u8] {
    assert!(self.buffer.len() > size);
    log::log!(log::Level::Trace,"Receiver: consume {} bytes",size);
    self.recv_bytes += size as u64;
    return &mut self.buffer[..size];
  }
}


pub struct RunTcpPacketProcesser {
  
}

impl common::stack::tcp::PacketProcesser for RunTcpPacketProcesser{
  fn build(&mut self,mbuf:&mut run_dpdk::Mbuf,
          repr:&common::stack::tcp::TcpRepr,
          router_info:&common::stack::RouterInfo) {
    //println!("mbuf headroom: {}",mbuf.front_capacity());
    // build tcp packet
    let mut tcpheader = run_packet::tcp::TCP_HEADER_TEMPLATE;
    let mut header_len = run_packet::tcp::TCP_HEADER_LEN;
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

    let total_header_overhead = header_len + ETHER_HEADER_LEN + IPV4_HEADER_LEN;
    unsafe { mbuf.extend_front(total_header_overhead) };
    let mut pbuf = run_dpdk::Pbuf::new(mbuf);
    pbuf.advance(total_header_overhead);
    
    println!("pbuf chunk headroom {}",pbuf.chunk_headroom());
    println!("pbuf data room {}",pbuf.remaining());

    tcpheader.set_header_len(header_len as u8);
    let mut tcppkt = TcpPacket::prepend_header(pbuf, &tcpheader);
    tcppkt.set_src_port(router_info.src_port);
    tcppkt.set_dst_port(router_info.dest_port);
    tcppkt.set_seq_number(repr.seq_number.0 as u32);
    let ack = repr.ack_number.unwrap_or_default().0 as u32;
    tcppkt.set_ack_number(ack);
    tcppkt.set_window_size(repr.window_len);
    match repr.ctrl {
      common::stack::tcp::TcpControl::None => (),
      common::stack::tcp::TcpControl::Psh => tcppkt.set_psh(true),
      common::stack::tcp::TcpControl::Syn => tcppkt.set_syn(true),
      common::stack::tcp::TcpControl::Fin => tcppkt.set_fin(true),
      common::stack::tcp::TcpControl::Rst => tcppkt.set_rst(true),
    }
    tcppkt.set_ack(repr.ack_number.is_some());
    {
      let mut options = tcppkt.option_bytes_mut();
      if let Some(value) = repr.max_seg_size {
        let tmp = options;
        options = TcpOption::MaxSegmentSize(value).build(tmp);
      }
      if let Some(value) = repr.window_scale {
        let tmp = options;
        options = TcpOption::WindowScale(value).build(tmp);
      }
      if repr.sack_permitted {
        let tmp = options;
        options = TcpOption::SackPermitted.build(tmp);
      } else if repr.ack_number.is_some() 
        && repr.sack_ranges.iter().any(|s| s.is_some()) {
        let tmp = options;
        options = TcpOption::SackRange(repr.sack_ranges).build(tmp);
      }

      if !options.is_empty() {
        TcpOption::EndOfList.build(options);
      }
    }

    tcppkt.adjust_ipv4_checksum(router_info.src_ipv4, router_info.dest_ipv4);

    // build ip packet
    let mut ippkt = Ipv4Packet::prepend_header(tcppkt.release(), &IPV4_HEADER_TEMPLATE);
    ippkt.set_time_to_live(64);
    ippkt.set_protocol(IpProtocol::TCP);
    ippkt.set_dest_ip(router_info.dest_ipv4);
    ippkt.set_source_ip(router_info.src_ipv4);
    ippkt.set_ident(0x5c65);
    ippkt.adjust_checksum();

    // build ethernet packet
    let mut ethpkt = EtherPacket::prepend_header(ippkt.release(), &ETHER_HEADER_TEMPLATE);
    ethpkt.set_dest_mac(router_info.dest_mac);
    ethpkt.set_source_mac(router_info.src_mac);
    ethpkt.set_ethertype(EtherType::IPV4);
  }

  fn parse(&mut self,mbuf:&mut run_dpdk::Mbuf) 
          -> Option<(common::stack::tcp::TcpRepr,
                     common::stack::RouterInfo,usize)> {
    let mut route_info:RouterInfo = RouterInfo::default();
    let mut tcprepr:TcpRepr = TcpRepr::default();
    let pbuf = Pbuf::new(mbuf);
    let ethpkt = EtherPacket::parse(pbuf).ok()?;
    if ethpkt.ethertype() != EtherType::IPV4 {
      return None;
    }
    route_info.dest_mac = ethpkt.dest_mac();
    route_info.src_mac = ethpkt.source_mac();
    let ippkt = Ipv4Packet::parse(ethpkt.payload()).ok()?;
    if ippkt.protocol() != IpProtocol::TCP {
      return None;
    }
    route_info.src_ipv4 = ippkt.source_ip();
    route_info.dest_ipv4 = ippkt.dest_ip();

    let tcppkt = TcpPacket::parse(ippkt.payload()).ok()?;
    route_info.dest_port = tcppkt.dst_port();
    route_info.src_port = tcppkt.src_port();

    let payload_offset = ETHER_HEADER_LEN + IPV4_HEADER_LEN + tcppkt.header_len() as usize;
    tcprepr.ctrl = match (tcppkt.syn(), tcppkt.fin(), tcppkt.rst(), tcppkt.psh()) {
      (false, false, false, false) => TcpControl::None,
      (false, false, false, true) => TcpControl::Psh,
      (true, false, false, _) => TcpControl::Syn,
      (false, true, false, _) => TcpControl::Fin,
      (false, false, true, _) => TcpControl::Rst,
      _ => return None,
    };
    tcprepr.ack_number = match tcppkt.ack() {
      true => Some(TcpSeqNumber(tcppkt.ack_number() as i32)),
      false => None,
    };

    tcprepr.max_seg_size = None;
    tcprepr.window_scale = None;
    tcprepr.sack_permitted = false;
    tcprepr.sack_ranges = [None,None,None];

    let mut options = tcppkt.option_bytes();
    while !options.is_empty() {
      let (next_options, option) = TcpOption::parse(options).ok()?;
      match option {
        TcpOption::EndOfList => break,
        TcpOption::NoOperation => (),
        TcpOption::MaxSegmentSize(value) => tcprepr.max_seg_size = Some(value),
        TcpOption::WindowScale(value) => {
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
        TcpOption::SackPermitted => tcprepr.sack_permitted = true,
        TcpOption::SackRange(slice) => tcprepr.sack_ranges = slice,
        _ => (),
      }
      options = next_options;
    }

    Some((tcprepr,route_info,payload_offset))
  }
}

fn server_start(args:&Flags) {
  let sender = Sender::new();
  let recver = Receiver::new(9000);
  let processer = RunTcpPacketProcesser{};
  let mut device = common::DpdkDeviceHelper::build(SERVER_PORT_ID).unwrap();
  let mut stack = common::stack::tcp::TcpStack::new(
    sender, recver, 
    processer, 
    9000, 
    9000);
  
  stack.set_mtu(1518);
  stack.bind(SERVER_LOCAL_IPV4, SERVER_PORT, SERVER_LOCAL_MAC);
  stack.listen(SERVER_REMOTE_IPV4, CLIENT_PORT, SERVER_REMOTE_MAC);
  common::poll(&mut device, &mut stack)
}

fn client_start(args:&Flags) {
  let sender = Sender::new();
  let recver = Receiver::new(9000);
  let processer = RunTcpPacketProcesser{};
  let mut device = common::DpdkDeviceHelper::build(CLIENT_PORT_ID).unwrap();
  let mut stack = common::stack::tcp::TcpStack::new(
    sender, recver, 
    processer, 
    9000, 
    9000);
  
  stack.set_mtu(1518);
  stack.bind(CLINET_LOCAL_IPV4, CLIENT_PORT, CLIENT_LOCAL_MAC);
  stack.connect(CLIENT_REMOTE_IPV4, SERVER_PORT, CLIENT_REMOTE_MAC);
  common::poll(&mut device, &mut stack)
}

const CLIENT_PORT_ID:u16 = 3;
const CLIENT_PORT:u16 = 9000;
const CLINET_LOCAL_IPV4:Ipv4Addr = Ipv4Addr([192,168,22,2]);
const CLIENT_REMOTE_IPV4:Ipv4Addr = Ipv4Addr([192,168,23,2]);
const CLIENT_LOCAL_MAC:MacAddr = MacAddr([0x10, 0x70, 0xfd, 0x15, 0x77, 0xbf]);
const CLIENT_REMOTE_MAC:MacAddr = MacAddr([0x08, 0x68, 0x8d, 0x61, 0x69, 0x28]);

const SERVER_PORT_ID:u16 = 0;
const SERVER_PORT:u16 = 9000;
const SERVER_LOCAL_IPV4:Ipv4Addr = Ipv4Addr([192,168,23,2]);
const SERVER_REMOTE_IPV4:Ipv4Addr = Ipv4Addr([192,168,22,2]);
const SERVER_LOCAL_MAC:MacAddr = MacAddr([0x10, 0x70, 0xfd, 0x15, 0x77, 0xc1]);
const SERVER_REMOTE_MAC:MacAddr = MacAddr([0x08, 0x68, 0x8d, 0x61, 0x69, 0x28]);

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