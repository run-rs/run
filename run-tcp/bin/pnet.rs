use std::{
  io::Write,
  sync::{
    atomic::{AtomicBool, AtomicI64},
    Arc,
  },
  time::Duration,
};

use clap::Parser;

use run_tcp::{
    TcpControl, TcpRepr, TcpSeqNumber,
    RouterInfo,
  Producer,
};

use pnet::packet::ethernet::*;
use pnet::packet::tcp::*;
use pnet::packet::{ipv4::*, MutablePacket, Packet};
use run_packet::{
  ether::{MacAddr, ETHER_HEADER_LEN},
  ipv4::{Ipv4Addr, IPV4_HEADER_LEN},
};

#[derive(Parser)]
struct Flags {
  #[clap(short, long, default_value_t = 10)]
  pub period: u32,
  #[clap(short, long)]
  pub client: bool,
  #[clap(short, long = "buf-size")]
  pub buffer: u32,
  #[clap(long = "mtu", default_value_t = 1518)]
  pub mtu: usize,
}

struct Sender {
  pub sent_bytes: Arc<AtomicI64>,
  pub data: Vec<u8>,
}

impl Sender {
  pub fn new(size: usize) -> Self {
    Sender {
      sent_bytes: Arc::new(AtomicI64::new(0)),
      data: vec![0; size],
    }
  }
}

impl run_tcp::Producer for Sender {
  fn produce(&mut self, size: usize) -> Option<&[u8]> {
    self
      .sent_bytes
      .fetch_add((size) as i64, std::sync::atomic::Ordering::Relaxed);
    return Some(&self.data[..size]);
  }
}

struct Receiver {
  pub recv_bytes: Arc<AtomicI64>,
  pub buffer: Vec<u8>,
}

impl Receiver {
  pub fn new(size: usize) -> Self {
    Receiver {
      recv_bytes: Arc::new(AtomicI64::new(0)),
      buffer: vec![0; size],
    }
  }
}

impl run_tcp::Consumer for Receiver {
  fn consume(&mut self, size: usize) -> &mut [u8] {
    assert!(self.buffer.len() > size);
    self
      .recv_bytes
      .fetch_add(size as i64, std::sync::atomic::Ordering::Relaxed);
    return &mut self.buffer[..size];
  }
}

struct SendNothing {}

impl SendNothing {
  pub fn new() -> Self {
    SendNothing {}
  }
}

impl Producer for SendNothing {
  fn produce(&mut self, _: usize) -> Option<&[u8]> {
    return Some(&[]);
  }
}

pub struct PnetTcpPacketProcesser {}

impl run_tcp::Packet for PnetTcpPacketProcesser {
  fn build(
    &mut self,
    mbuf: &mut run_dpdk::Mbuf,
    repr: &TcpRepr,
    router_info: &RouterInfo,
  ) {
    let mut header_len = run_tcp::TCP_HEADER_LEN;
    if repr.max_seg_size.is_some() {
      header_len += 4;
    }
    if repr.window_scale.is_some() {
      header_len += 3;
    }
    if repr.sack_permitted {
      header_len += 2;
    }
    let sack_range_len: usize = repr
      .sack_ranges
      .iter()
      .map(|o| o.map(|_| 8).unwrap_or(0))
      .sum();
    if sack_range_len > 0 {
      header_len += sack_range_len + 2;
    }
    if header_len % 4 != 0 {
      header_len += 4 - header_len % 4;
    }

    let total_header_overhead =
      header_len + run_tcp::ETHER_HEADER_LEN + run_tcp::IPV4_HEADER_LEN;
    let payload_len = mbuf.len();
    unsafe { mbuf.extend_front(total_header_overhead) };
    let mut epkt =
      pnet::packet::ethernet::MutableEthernetPacket::new(mbuf.data_mut())
        .unwrap();
    epkt.set_destination(router_info.dest_mac.0.into());
    epkt.set_source(router_info.src_mac.0.into());
    epkt.set_ethertype(EtherTypes::Ipv4);
    let mut ipv4_pkt = MutableIpv4Packet::new(epkt.payload_mut()).unwrap();
    ipv4_pkt.set_version(4);
    ipv4_pkt.set_header_length(5);
    ipv4_pkt.set_dscp(0);
    ipv4_pkt.set_ecn(0);
    ipv4_pkt.set_total_length(
      (run_tcp::IPV4_HEADER_LEN + header_len + payload_len) as u16,
    );
    ipv4_pkt.set_identification(0x5c65);
    ipv4_pkt.set_flags(0);
    ipv4_pkt.set_fragment_offset(0);
    ipv4_pkt.set_ttl(64);
    ipv4_pkt
      .set_next_level_protocol(pnet::packet::ip::IpNextHeaderProtocols::Tcp);
    ipv4_pkt.set_source(router_info.src_ipv4.0.into());
    ipv4_pkt.set_destination(router_info.dest_ipv4.0.into());
    ipv4_pkt.set_checksum(0);
    let checksum = pnet::packet::ipv4::checksum(&ipv4_pkt.to_immutable());
    ipv4_pkt.set_checksum(checksum);

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
      TcpControl::None => (),
      TcpControl::Psh => flags |= TcpFlags::PSH,
      TcpControl::Syn => flags |= TcpFlags::SYN,
      TcpControl::Fin => flags |= TcpFlags::FIN,
      TcpControl::Rst => flags |= TcpFlags::RST,
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
        && repr.sack_ranges.iter().any(|s| s.is_some())
      {
        let tmp = options;
        options =
          run_packet::tcp::TcpOption::SackRange(repr.sack_ranges).build(tmp);
      }

      if !options.is_empty() {
        run_packet::tcp::TcpOption::EndOfList.build(options);
      }
    }
    let checksum = ipv4_checksum(
      &tcp_pkt.to_immutable(),
      &router_info.src_ipv4.0.into(),
      &router_info.dest_ipv4.0.into(),
    );

    tcp_pkt.set_checksum(checksum);
  }

  fn parse(
    &mut self,
    mbuf: &mut run_dpdk::Mbuf,
  ) -> Option<(
    TcpRepr,
    RouterInfo,
    usize,
  )> {
    let mut route_info: RouterInfo = RouterInfo::default();
    let mut tcprepr: TcpRepr = TcpRepr::default();

    let eth_pkt = EthernetPacket::new(mbuf.data())?;
    route_info.dest_mac = run_tcp::MacAddr(eth_pkt.get_destination().octets());
    route_info.src_mac = run_tcp::MacAddr(eth_pkt.get_source().octets());
    let ip_pkt = Ipv4Packet::new(eth_pkt.payload())?;
    let checksum = ip_pkt.get_checksum();
    if pnet::packet::ipv4::checksum(&ip_pkt) != checksum {
      return None;
    }
    route_info.dest_ipv4 = run_tcp::Ipv4Addr(ip_pkt.get_destination().octets());
    route_info.src_ipv4 = run_tcp::Ipv4Addr(ip_pkt.get_source().octets());
    let total_packet_len =
      ip_pkt.get_total_length() + run_tcp::ETHER_HEADER_LEN as u16;
    let tcp_pkt = TcpPacket::new(ip_pkt.payload())?;
    let checksum = tcp_pkt.get_checksum();
    if pnet::packet::tcp::ipv4_checksum(
      &tcp_pkt,
      &route_info.src_ipv4.0.into(),
      &route_info.dest_ipv4.0.into(),
    ) != checksum
    {
      return None;
    }

    route_info.dest_port = tcp_pkt.get_destination();
    route_info.src_port = tcp_pkt.get_source();

    let payload_offset = run_tcp::ETHER_HEADER_LEN
      + run_tcp::IPV4_HEADER_LEN
      + (tcp_pkt.get_data_offset() * 4) as usize;
    let flags = tcp_pkt.get_flags();
    let syn = TcpFlags::SYN & flags != 0;
    let fin = TcpFlags::FIN & flags != 0;
    let psh = TcpFlags::PSH & flags != 0;
    let rst = TcpFlags::RST & flags != 0;
    let ack = TcpFlags::ACK & flags != 0;
    tcprepr.ctrl = match (syn, fin, rst, psh) {
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
    tcprepr.sack_ranges = [None, None, None];

    let mut options = tcp_pkt.get_options_raw();
    while !options.is_empty() {
      let (next_options, option) =
        run_packet::tcp::TcpOption::parse(options).ok()?;
      match option {
        run_packet::tcp::TcpOption::EndOfList => break,
        run_packet::tcp::TcpOption::NoOperation => (),
        run_packet::tcp::TcpOption::MaxSegmentSize(value) => {
          tcprepr.max_seg_size = Some(value)
        }
        run_packet::tcp::TcpOption::WindowScale(value) => {
          tcprepr.window_scale =
            if value > 14 { Some(14) } else { Some(value) };
        }
        run_packet::tcp::TcpOption::SackPermitted => {
          tcprepr.sack_permitted = true
        }
        run_packet::tcp::TcpOption::SackRange(slice) => {
          tcprepr.sack_ranges = slice
        }
        _ => (),
      }
      options = next_options;
    }

    mbuf.truncate(total_packet_len as usize);
    Some((tcprepr, route_info, payload_offset))
  }
}

fn server_start(args: &Flags) {
  let sender = SendNothing::new();
  let recver = Receiver::new(args.buffer as usize);
  let run = Arc::new(AtomicBool::new(true));
  let run_clone = run.clone();
  let run_ctrlc = run.clone();
  let mtu = args.mtu;
  ctrlc::set_handler(move || {
    run_ctrlc.store(false, std::sync::atomic::Ordering::Relaxed);
  })
  .unwrap();

  let jh = std::thread::spawn(move || {
    let mut max_secs = 1000;
    while run_clone.load(std::sync::atomic::Ordering::Relaxed) {
      if max_secs == 0 {
        break;
      }
      std::thread::sleep(Duration::from_secs(1));
      max_secs -= 1;
    }
    run_clone.store(false, std::sync::atomic::Ordering::Relaxed);
  });

  let processer = PnetTcpPacketProcesser {};
  let mut stack = run_tcp::TcpStack::new(
    sender,
    recver,
    processer,
    args.buffer as usize,
    64,
  );

  stack.set_mss(mtu - ETHER_HEADER_LEN - IPV4_HEADER_LEN - 60);
  stack.bind(SERVER_LOCAL_IPV4, SERVER_PORT, SERVER_LOCAL_MAC);
  stack.listen(SERVER_REMOTE_IPV4, CLIENT_PORT, SERVER_REMOTE_MAC);
  run_tcp::poll(run, 0, &mut stack, run_tcp::OFFLOAD::IPV4_TCP_CSUM);
  jh.join().unwrap();
}

fn client_start(args: &Flags) {
  let sender = Sender::new(args.buffer as usize);
  let recver = Receiver::new(64);

  let sent_bytes = sender.sent_bytes.clone();

  let run = Arc::new(AtomicBool::new(true));
  let run_clone = run.clone();
  let run_ctrlc = run.clone();
  let mtu = args.mtu;
  ctrlc::set_handler(move || {
    run_ctrlc.store(false, std::sync::atomic::Ordering::Relaxed);
  })
  .unwrap();
  let jh = std::thread::spawn(move || {
    let mut last_sent_bytes = 0;
    let mut opt = std::fs::File::options();
    opt.append(true);
    opt.write(true);
    opt.create(true);
    let mut file = match opt.open("./data/tcp.csv") {
      Ok(f) => f,
      Err(err) => {
        log::log!(
          log::Level::Error,
          "can not open `./data/tcp.csv`. \
                please launch at top workspace. : {}",
          err
        );
        run_clone.store(false, std::sync::atomic::Ordering::Relaxed);
        return;
      }
    };
    match file.write_all(b"frameworkd,mtu,throughput\n") {
      Err(err) => {
        log::log!(log::Level::Error, "failed to write : {}", err);
        run_clone.store(false, std::sync::atomic::Ordering::Relaxed);
        return;
      }
      _ => (),
    };
    // wait for connection
    std::thread::sleep(Duration::from_secs(5));
    sent_bytes.store(0, std::sync::atomic::Ordering::Relaxed);
    let mut max_secs = 60;
    while run_clone.load(std::sync::atomic::Ordering::Relaxed) {
      if max_secs == 0 {
        break;
      }
      std::thread::sleep(Duration::from_secs(1));
      // write to csv file
      let sent_total = sent_bytes.load(std::sync::atomic::Ordering::Relaxed);
      let sent_diff = sent_total - last_sent_bytes;
      last_sent_bytes = sent_total;

      assert!(sent_diff >= 0);

      let tx_bps = (sent_diff as f64) * 8.0 / 1000000000.0;
      match file.write_all(format!("Pnet,{},{}\n", mtu, tx_bps).as_bytes()) {
        Ok(_) => (),
        Err(err) => {
          log::log!(log::Level::Error, "failed to write : {}", err);
          break;
        }
      }
      max_secs -= 1;
    }
    run_clone.store(false, std::sync::atomic::Ordering::Relaxed);
  });

  let processer = PnetTcpPacketProcesser {};
  let mut stack = run_tcp::TcpStack::new(
    sender,
    recver,
    processer,
    64,
    args.buffer as usize,
  );

  stack.set_mss(mtu - ETHER_HEADER_LEN - IPV4_HEADER_LEN - 60);
  stack.bind(CLINET_LOCAL_IPV4, CLIENT_PORT, CLIENT_LOCAL_MAC);
  stack.connect(CLIENT_REMOTE_IPV4, SERVER_PORT, CLIENT_REMOTE_MAC);
  run_tcp::poll(run, 3, &mut stack, run_tcp::OFFLOAD::IPV4_TCP_CSUM);

  jh.join().unwrap();
}

const CLIENT_PORT: u16 = 9000;
const CLINET_LOCAL_IPV4: Ipv4Addr = Ipv4Addr([192, 168, 22, 2]);
const CLIENT_REMOTE_IPV4: Ipv4Addr = Ipv4Addr([192, 168, 23, 2]);
const CLIENT_LOCAL_MAC: MacAddr = MacAddr([0x10, 0x70, 0xfd, 0x15, 0x77, 0xbf]);
const CLIENT_REMOTE_MAC: MacAddr =
  MacAddr([0x08, 0x68, 0x8d, 0x61, 0x69, 0x28]);

const SERVER_PORT: u16 = 9000;
const SERVER_LOCAL_IPV4: Ipv4Addr = Ipv4Addr([192, 168, 23, 2]);
const SERVER_REMOTE_IPV4: Ipv4Addr = Ipv4Addr([192, 168, 22, 2]);
const SERVER_LOCAL_MAC: MacAddr = MacAddr([0x10, 0x70, 0xfd, 0x15, 0x77, 0xc1]);
const SERVER_REMOTE_MAC: MacAddr =
  MacAddr([0x08, 0x68, 0x8d, 0x61, 0x69, 0x28]);

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
