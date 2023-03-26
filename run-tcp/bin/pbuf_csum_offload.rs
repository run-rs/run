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
  Producer, Packet, TcpStack
};
use run_dpdk::Pbuf;
use run_packet::{
  ether::{
    EtherPacket, EtherType, MacAddr, ETHER_HEADER_LEN, ETHER_HEADER_TEMPLATE,
  },
  ipv4::{
    IpProtocol, Ipv4Addr, Ipv4Packet, IPV4_HEADER_LEN, IPV4_HEADER_TEMPLATE,
  },
  tcp::{TcpOption, TcpPacket},
  Buf,
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
    //log::log!(log::Level::Trace,"Receiver: consume {} bytes",size);
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

pub struct RunTcpPacketProcesser {}

impl Packet for RunTcpPacketProcesser {
  fn build(
    &mut self,
    mbuf: &mut run_dpdk::Mbuf,
    repr: &TcpRepr,
    router_info: &RouterInfo,
  ) {
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

    let total_header_overhead = header_len + ETHER_HEADER_LEN + IPV4_HEADER_LEN;
    unsafe { mbuf.extend_front(total_header_overhead) };
    let mut pbuf = run_dpdk::Pbuf::new(mbuf);
    pbuf.advance(total_header_overhead);

    tcpheader.set_header_len(header_len as u8);
    let mut tcppkt = TcpPacket::prepend_header(pbuf, &tcpheader);
    tcppkt.set_src_port(router_info.src_port);
    tcppkt.set_dst_port(router_info.dest_port);
    tcppkt.set_seq_number(repr.seq_number.0 as u32);
    let ack = repr.ack_number.unwrap_or_default().0 as u32;
    tcppkt.set_ack_number(ack);
    tcppkt.set_window_size(repr.window_len);
    match repr.ctrl {
      TcpControl::None => (),
      TcpControl::Psh => tcppkt.set_psh(true),
      TcpControl::Syn => tcppkt.set_syn(true),
      TcpControl::Fin => tcppkt.set_fin(true),
      TcpControl::Rst => tcppkt.set_rst(true),
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
        && repr.sack_ranges.iter().any(|s| s.is_some())
      {
        let tmp = options;
        options = TcpOption::SackRange(repr.sack_ranges).build(tmp);
      }

      if !options.is_empty() {
        TcpOption::EndOfList.build(options);
      }
    }

    let mut ippkt =
      Ipv4Packet::prepend_header(tcppkt.release(), &IPV4_HEADER_TEMPLATE);
    ippkt.set_time_to_live(64);
    ippkt.set_protocol(IpProtocol::TCP);
    ippkt.set_dest_ip(router_info.dest_ipv4);
    ippkt.set_source_ip(router_info.src_ipv4);
    ippkt.set_ident(0x5c65);

    let mut ethpkt =
      EtherPacket::prepend_header(ippkt.release(), &ETHER_HEADER_TEMPLATE);
    ethpkt.set_dest_mac(router_info.dest_mac);
    ethpkt.set_source_mac(router_info.src_mac);
    ethpkt.set_ethertype(EtherType::IPV4);

    let mut of_flag = run_dpdk::offload::MbufTxOffload::ALL_DISABLED;
    of_flag.enable_ip_cksum();
    of_flag.enable_tcp_cksum();
    of_flag.set_l2_len(ETHER_HEADER_LEN as u64);
    of_flag.set_l3_len(IPV4_HEADER_LEN as u64);
    of_flag.set_l4_len(header_len as u64);
    mbuf.set_tx_offload(&of_flag);
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

    let pbuf = Pbuf::new(mbuf);
    let ethpkt = EtherPacket::parse(pbuf).ok()?;
    route_info.dest_mac = ethpkt.dest_mac();
    route_info.src_mac = ethpkt.source_mac();
    let ippkt = Ipv4Packet::parse(ethpkt.payload()).ok()?;
    route_info.src_ipv4 = ippkt.source_ip();
    route_info.dest_ipv4 = ippkt.dest_ip();
    let tcppkt = TcpPacket::parse(ippkt.payload()).ok()?;
    route_info.dest_port = tcppkt.dst_port();
    route_info.src_port = tcppkt.src_port();
    let payload_offset =
      ETHER_HEADER_LEN + IPV4_HEADER_LEN + tcppkt.header_len() as usize;
    tcprepr.ctrl =
      match (tcppkt.syn(), tcppkt.fin(), tcppkt.rst(), tcppkt.psh()) {
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
    tcprepr.seq_number = TcpSeqNumber(tcppkt.seq_number() as i32);
    tcprepr.window_len = tcppkt.window_size();
    tcprepr.max_seg_size = None;
    tcprepr.window_scale = None;
    tcprepr.sack_permitted = false;
    tcprepr.sack_ranges = [None, None, None];

    let mut options = tcppkt.option_bytes();
    while !options.is_empty() {
      let (next_options, option) = TcpOption::parse(options).ok()?;
      match option {
        TcpOption::EndOfList => break,
        TcpOption::NoOperation => (),
        TcpOption::MaxSegmentSize(value) => tcprepr.max_seg_size = Some(value),
        TcpOption::WindowScale(value) => {
          tcprepr.window_scale =
            if value > 14 { Some(14) } else { Some(value) };
        }
        TcpOption::SackPermitted => tcprepr.sack_permitted = true,
        TcpOption::SackRange(slice) => tcprepr.sack_ranges = slice,
        _ => (),
      }
      options = next_options;
    }
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

  let processer = RunTcpPacketProcesser {};
  let mut stack = TcpStack::new(
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
    let mut file = match opt.open("./data/tcp_csum.csv") {
      Ok(f) => f,
      Err(err) => {
        log::log!(
          log::Level::Error,
          "can not open `./data/tcp_csum.csv`. \
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
    let mut max_secs = 600;
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
      match file.write_all(format!("Pbuf,{},{}\n", mtu, tx_bps).as_bytes()) {
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

  let processer = RunTcpPacketProcesser {};
  let mut stack = TcpStack::new(
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
  #[cfg(feature = "enable_csum_offload")]
  println!("enable csum offload");
  let args = Flags::parse();
  if !args.client {
    println!("start server");
    server_start(&args);
  } else {
    println!("start client");
    client_start(&args);
  }
}