use run_dpdk::Mbuf;
use run_packet::ether::ETHER_HEADER_LEN;
use run_packet::ipv4::IPV4_HEADER_LEN;
use run_packet::ipv4::Ipv4Addr;
use run_packet::ether::MacAddr;
use run_packet::tcp::TCP_HEADER_LEN;
use run_time::Instant;
use std::time::Duration;

use crate::common::Assembler;
use crate::common::Rand;
use crate::common::Stack;
use crate::common::proto::ACK_DELAY_DEFAULT;
use crate::common::proto::Consumer;
use crate::common::proto::Producer;
use crate::common::proto::RouterInfo;
use crate::common::proto::TcpControl;
use crate::common::proto::TcpRepr;
use crate::common::proto::TcpSeqNumber;
use crate::common::proto::TcpState;
use crate::common::proto::AckDelayTimer;
use crate::common::proto::DEFAULT_MSS;
use crate::common::proto::RttEstimator;
use crate::common::proto::Timer;
use crate::common::socket_buffer::SocketBuffer;

#[derive(Debug)]
pub struct TcpStack<P,C,PACKETBUILDER,PACKETPARSER>
where
  P: Producer,
  C: Consumer,
  PACKETBUILDER: Fn(&mut Mbuf,&TcpRepr,&RouterInfo),
  PACKETPARSER: Fn(&Mbuf) ->Option<(TcpRepr,RouterInfo,&[u8])>, 
{
  local_mac:MacAddr,
  local_port:u16,
  local_ipv4:Ipv4Addr,
  remote_mac:MacAddr,
  remote_port:u16,
  remote_ipv4:Ipv4Addr,
  mtu:usize,
  producer:P,
  consumer:C,
  builder:PACKETBUILDER,
  parser:PACKETPARSER,

  state: TcpState,
  timer: Timer,
  rx_buffer:SocketBuffer,
  tx_buffer:SocketBuffer,
  rtte: RttEstimator,
  assembler:Assembler,
  rx_fin_received:bool,
  timeout:Option<Duration>,
  keep_alive:Option<Duration>,
  hop_limit:Option<u8>,
  local_seq_no: TcpSeqNumber,
  remote_seq_no: TcpSeqNumber,
  remote_last_seq: TcpSeqNumber,
  remote_last_ack: Option<TcpSeqNumber>,
  remote_last_win: u16,
  remote_win_shift:u8,
  remote_win_len:usize,
  remote_win_scale:Option<u8>,
  remote_has_sack:bool,
  remote_mss:usize,
  remote_last_ts:Option<Instant>,
  local_rx_last_seq: Option<TcpSeqNumber>,
  local_rx_last_ack: Option<TcpSeqNumber>,
  local_rx_dup_acks:u8,
  ack_delay: Option<Duration>,
  ack_delay_timer:AckDelayTimer,
  challenge_ack_timer: Instant,
  nagle: bool,
  rand: Rand,
}

impl <P,C,PACKETBUILDER,PACKETPARSER> TcpStack<P,C,PACKETBUILDER,PACKETPARSER> 
where 
  P: Producer,
  C: Consumer,
  PACKETBUILDER: Fn(&mut Mbuf,&TcpRepr,&RouterInfo),
  PACKETPARSER: Fn(&Mbuf) ->Option<(TcpRepr,RouterInfo,&[u8])>,
{
  pub fn new(p:P,
          c:C,
          builder:PACKETBUILDER,
          parser:PACKETPARSER,
          rx_buffer_size:usize,
          tx_buffer_size:usize) -> Self {
    if rx_buffer_size > (1 << 30) {
      panic!("receiving buffer too large, cannot exceed 1 GiB");
    }
    let rx_cap_log2 = std::mem::size_of::<usize>() * 8 - rx_buffer_size.leading_zeros() as usize;
    TcpStack {
      local_mac:MacAddr::default(),
      local_port:0,
      local_ipv4:Ipv4Addr::default(),
      remote_mac:MacAddr::default(),
      remote_port:0,
      remote_ipv4:Ipv4Addr::default(),
      mtu:1515,
      producer:p,
      consumer:c,
      builder:builder,
      parser:parser,

      state: TcpState::Closed,
      timer: Timer::new(),
      tx_buffer:SocketBuffer::new(tx_buffer_size),
      rx_buffer:SocketBuffer::new(rx_buffer_size),
      rtte: RttEstimator::default(),
      assembler: Assembler::new(rx_buffer_size),
      rx_fin_received:false,
      timeout:None,
      keep_alive:None,
      hop_limit:None,
      local_seq_no: TcpSeqNumber::default(),
      remote_seq_no: TcpSeqNumber::default(),
      remote_last_seq: TcpSeqNumber::default(),
      remote_last_ack: None,
      remote_last_win: 0,
      remote_win_len: 0,
      remote_win_shift: rx_cap_log2.saturating_sub(16) as u8,
      remote_win_scale: None,
      remote_has_sack: false,
      remote_mss: DEFAULT_MSS,
      remote_last_ts: None,
      local_rx_last_ack: None,
      local_rx_last_seq: None,
      local_rx_dup_acks:0,
      ack_delay: Some(ACK_DELAY_DEFAULT),
      ack_delay_timer: AckDelayTimer::Idle,
      challenge_ack_timer: Instant::from_secs(0),
      nagle:true,
      rand:Rand::new(Instant::now().raw()),
    }
  }

  pub fn set_mtu(&mut self,mtu:usize) {
    self.mtu = mtu;
  }

  pub fn bind(&mut self,ipv4:Ipv4Addr,port:u16,mac:MacAddr) {
    self.local_ipv4 = ipv4;
    self.local_mac = mac;
    self.local_port = port;
  }

  pub fn listen(&mut self,ipv4:Ipv4Addr,port:u16,mac:MacAddr) {
    self.remote_ipv4 = ipv4;
    self.remote_mac = mac;
    self.remote_port = port;
    self.set_state(TcpState::Listen);
  }

  pub fn connect(&mut self,ipv4:Ipv4Addr,port:u16,mac:MacAddr) {
    self.remote_ipv4 = ipv4;
    self.remote_mac = mac;
    self.remote_port = port;
    self.set_state(TcpState::SynSent);
  }
}

impl <P,C,PACKETBUILDER,PACKETPARSER> TcpStack<P,C,PACKETBUILDER,PACKETPARSER> 
where 
  P: Producer,
  C: Consumer,
  PACKETBUILDER: Fn(&mut Mbuf,&TcpRepr,&RouterInfo),
  PACKETPARSER: Fn(&Mbuf) ->Option<(TcpRepr,RouterInfo,&[u8])>,
{
  fn set_state(&mut self,state:TcpState) {
    log::log!(log::Level::Trace,"tcp state {} => {}",self.state,state);
    self.state = state;
  }

  fn random_seq_no(&mut self) -> TcpSeqNumber {
    TcpSeqNumber(self.rand.rand_u32() as i32)
  }

  fn close(&mut self) {
    match self.state {
      TcpState::Listen => self.set_state(TcpState::Closed),
      TcpState::SynSent => self.set_state(TcpState::Closed),
      TcpState::SynReceived | TcpState::Established => self.set_state(TcpState::FinWait1),
      TcpState::CloseWait => self.set_state(TcpState::LastAck),
      TcpState::FinWait1
            | TcpState::FinWait2
            | TcpState::Closing
            | TcpState::TimeWait
            | TcpState::LastAck
            | TcpState::Closed => (),
    }
  }

  fn reset(&mut self) {
    let rx_cap_log2 =
            std::mem::size_of::<usize>() * 8 - self.rx_buffer.cap().leading_zeros() as usize;
    self.state = TcpState::Closed;
    self.timer = Timer::new();
    self.rtte = RttEstimator::default();
    self.assembler = Assembler::new(self.rx_buffer.cap());
    self.tx_buffer.clear();
    self.rx_buffer.clear();
    self.rx_fin_received = false;
    self.local_ipv4 = Ipv4Addr::default();
    self.remote_ipv4 = Ipv4Addr::default();
    self.local_port = 0;
    self.remote_port = 0;
    self.local_seq_no = TcpSeqNumber::default();
    self.remote_seq_no = TcpSeqNumber::default();
    self.remote_last_seq = TcpSeqNumber::default();
    self.remote_last_ack = None;
    self.remote_last_win = 0;
    self.remote_win_len = 0;
    self.remote_win_scale = None;
    self.remote_win_shift = rx_cap_log2.saturating_sub(16) as u8;
    self.remote_mss = DEFAULT_MSS;
    self.remote_last_ts = None;
    self.ack_delay_timer = AckDelayTimer::Idle;
    self.challenge_ack_timer = Instant::from_secs(0);
  }

  fn pull_data_from_producer(&mut self) {
    let max_pull_size = self.tx_buffer.window_size();
    if let Some(data) = self.producer.produce(max_pull_size) {
      assert!(data.len() <= max_pull_size);
      assert_eq!(self.tx_buffer.enqueue_slice(data),data.len());
    } else {
      self.close();
    }
  }

  fn push_data_to_consumer(&mut self) {
    let max_push_size = self.rx_buffer.len();
    let data = self.consumer.consume(max_push_size);
    self.rx_buffer.dequeue_slice(data);
  }

  fn timed_out(&self,ts:Instant) -> bool {
    match (self.remote_last_ts,self.timeout) {
      (Some(remote_last_ts),Some(timeout)) => {
        ts >= remote_last_ts + timeout
      },
      _ => false
    }
  }

  fn ack_to_transmit(&self) -> bool {
    if let Some(remote_last_ack) = self.remote_last_ack {
      remote_last_ack < self.remote_seq_no + self.rx_buffer.len()
    } else {
      false
    }  
  }
  
  fn delayed_ack_expired(&self, timestamp: Instant) -> bool {
    match self.ack_delay_timer {
      AckDelayTimer::Idle => true,
      AckDelayTimer::Waiting(t) => t <= timestamp,
      AckDelayTimer::Immediate => true,
    }
  }

  fn scaled_window(&self) -> u16 {
    std::cmp::min(
      self.rx_buffer.window_size() >> self.remote_win_shift as usize,
      (1 << 16) - 1
    ) as u16
  }

  fn window_to_udpate(&self) -> bool {
    match self.state {
      TcpState::SynSent
      | TcpState::SynReceived
      | TcpState::Established
      | TcpState::FinWait1
      | TcpState::FinWait2 => self.scaled_window() > self.remote_last_win,
      _ => false
    }
  }

  fn seq_to_transmit(&self) -> bool {
    let local_mss = self.mtu - IPV4_HEADER_LEN - TCP_HEADER_LEN - ETHER_HEADER_LEN;
    let effective_mss = local_mss.min(self.remote_mss);
    let data_in_flight = self.remote_last_seq != self.local_seq_no;
    
    // If we want to send a SYN and we haven't done so, do it!
    if matches!(self.state,TcpState::SynSent | TcpState::SynReceived) && !data_in_flight {
      return true;
    }

    let max_send_seq = 
                self.local_seq_no + std::cmp::min(self.remote_win_len, self.tx_buffer.len());
    let max_send = if max_send_seq >= self.remote_last_seq {
      max_send_seq - self.remote_last_seq
    } else {
      0
    };

    let mut can_send = max_send != 0;
    let can_send_full = max_send >= effective_mss;

    let want_fin = match self.state {
      TcpState::FinWait1 => true,
      TcpState::Closing => true,
      TcpState::LastAck => true,
      _ => false,
    };

    if self.nagle && data_in_flight && !can_send_full {
      can_send = false
    }

    let can_fin = want_fin && self.remote_last_seq == self.local_seq_no + self.tx_buffer.len();
    
    can_send || can_fin
  }

  fn build<F>(&mut self,mut mbuf:Mbuf,ts:Instant,emit:F)
  where 
    F:FnOnce(Mbuf) -> bool {
    let mut repr = TcpRepr {
      ctrl:TcpControl::None,
      seq_number: self.remote_last_seq,
      ack_number:Some(self.remote_seq_no + self.rx_buffer.len()),
      window_len:self.scaled_window(),
      window_scale:None,
      max_seg_size:None,
      sack_permitted:false,
      sack_ranges:[None,None,None]
    };

    let router_info = RouterInfo {
      dest_ipv4:self.remote_ipv4,
      dest_mac:self.remote_mac,
      dest_port:self.remote_port,
      src_mac:self.local_mac,
      src_ipv4:self.local_ipv4,
      src_port:self.local_port
    };
    // We transmit data in all states where we may have data in 
    // the buffer, or the transmit half of the connection is still
    // open
    match self.state {
      TcpState::Closed => {
        repr.ctrl = TcpControl::Rst;
      }

      TcpState::SynSent | TcpState::SynReceived => {
        repr.ctrl = TcpControl::Syn;
        repr.window_len = self.rx_buffer.window_size().min((1 << 16) - 1) as u16;
        if self.state == TcpState::SynSent {
          repr.ack_number = None;
          repr.window_scale = Some(self.remote_win_shift);
          repr.sack_permitted = true;
        } else {
          repr.sack_permitted = self.remote_has_sack;
          repr.window_scale = self.remote_win_scale.map(|_| self.remote_win_shift);
        }
      }

      TcpState::Established
      | TcpState::FinWait1
      | TcpState::Closing
      | TcpState::CloseWait
      | TcpState::LastAck => {
        // Right edge of window
        let win_right_edge = self.local_seq_no + self.remote_win_len;

        // Max amount of octets we're allowed to send according to the remote window
        let win_limit = if win_right_edge >= self.remote_last_seq {
          win_right_edge - self.remote_last_seq
        } else {
          // This can happen if we've sent some data and later the remote
          // side has shrunk its window so that data is no longer inside
          // the window.
          // This should be very rare and is strongly discouraged by the RFCs
          // but it does happen in practice.
          // http://www.tcpipguide.com/free/t_TCPWindowManagementIssues.htm
          0
        };

        // Maximum size we're allowed to send. This can be limited by 3 factors:
        // 1. remote window
        // 2. MSS the remote is willing to accept, probably determined by their MTU
        // 3. MSS we can send
        let max_payload_len = self.mtu - ETHER_HEADER_LEN - TCP_HEADER_LEN - IPV4_HEADER_LEN;
        let size = win_limit
                                .min(self.remote_mss)
                                .min(max_payload_len);
        let offset = self.remote_last_seq - self.local_seq_no;
        

        // Actual size we're allowed to send. This can be limited by 2 factors:
        // 1. maximum size we're allowed to send
        // 2. the remaining data size in tx buffer
        let payload_len = if offset < self.tx_buffer.len() {
          0
        } else {
          size.min(self.tx_buffer.len() - offset)
        };
        // extend mbuf data
        unsafe {
          mbuf.extend(payload_len);
        }

        // fill data to mbuf
        let sent = self.tx_buffer.read_allocated(offset, mbuf.data_mut());
        
        assert_eq!(sent,payload_len);
        assert_eq!(mbuf.len(),sent);

        log::log!(log::Level::Trace,
          "tcp: `{}:{}` <==> `{}:{}`: prepare {} bytes payload to send",
          self.local_ipv4,
          self.local_port,
          self.remote_ipv4,
          self.remote_port,
          sent);

        if offset + sent == self.tx_buffer.len() {
          match self.state {
            TcpState::FinWait1 | TcpState::LastAck | TcpState::Closing => {
              repr.ctrl = TcpControl::Fin;
            },
            TcpState::Established | TcpState::CloseWait if !(sent == 0) => {
              repr.ctrl = TcpControl::Psh;
            },
            _ => (),
          }
        }
      }
      _ => {}
    }

    let is_keep_alive;
    if self.timer.should_keep_alive(ts) && mbuf.len() == 0 {
      repr.seq_number = repr.seq_number - 1;
      // RFC 1122
      mbuf.extend_from_slice(b"\x00");
      is_keep_alive = true;
    } else {
      is_keep_alive = false;
    }

    if is_keep_alive {
      log::log!(log::Level::Trace,
        "tcp: `{}:{}` <==> `{}:{}`: sending a keep-alive",
        self.local_ipv4,
        self.local_port,
        self.remote_ipv4,
        self.remote_port);
    } else if mbuf.len() != 0 {
      log::log!(log::Level::Trace,
        "tcp: `{}:{}` <==> `{}:{}`: tx_buffer: sending {} octets at offset {}",
        self.local_ipv4,
        self.local_port,
        self.remote_ipv4,
        self.remote_port,
        mbuf.len(),
        self.remote_last_seq - self.local_seq_no);
    }

    if repr.ctrl != TcpControl::None || mbuf.len() == 0 {
      let flags = match (repr.ctrl,repr.ack_number) {
        (TcpControl::Syn, None) => "SYN",
        (TcpControl::Syn, Some(_)) => "SYN|ACK",
        (TcpControl::Fin, Some(_)) => "FIN|ACK",
        (TcpControl::Rst, Some(_)) => "RST|ACK",
        (TcpControl::Psh, Some(_)) => "PSH|ACK",
        (TcpControl::None, Some(_)) => "ACK",
        _ => "<unreachable>",
      };
      log::log!(log::Level::Trace,
        "tcp: `{}:{}` <==> `{}:{}`: sending {}",
        self.local_ipv4,
        self.local_port,
        self.remote_ipv4,
        self.remote_port,
        flags);
    }

    if repr.ctrl == TcpControl::Syn {
      let max_segment_size = self.mtu - ETHER_HEADER_LEN - IPV4_HEADER_LEN - TCP_HEADER_LEN;
      repr.max_seg_size = Some(max_segment_size as u16);
    }

    let segment_len = mbuf.len() + repr.ctrl.len();

    (self.builder)(&mut mbuf,&repr,&router_info);

    if !emit(mbuf) {
      log::log!(log::Level::Trace,
        "tcp: `{}:{}` <==> `{}:{}`: failed to send packet",
        self.local_ipv4,
        self.local_port,
        self.remote_ipv4,
        self.remote_port);
      return;
    }

    self.timer.rewind_keep_alive(ts,self.keep_alive);

    match self.ack_delay_timer {
      AckDelayTimer::Idle => {}
      AckDelayTimer::Waiting(_) => {
        log::log!(log::Level::Trace,
          "tcp: `{}:{}` <==> `{}:{}`: stop delayed ack timer",
          self.local_ipv4,
          self.local_port,
          self.remote_ipv4,
          self.remote_port);
      }
      AckDelayTimer::Immediate => {
        log::log!(log::Level::Trace,
          "tcp: `{}:{}` <==> `{}:{}`: stop delayed ack timer (was force-expired)",
          self.local_ipv4,
          self.local_port,
          self.remote_ipv4,
          self.remote_port);
      }
    }
    self.ack_delay_timer = AckDelayTimer::Idle;

    if is_keep_alive {
      return;
    }

    self.remote_last_seq = repr.seq_number + segment_len;
    self.remote_last_ack = repr.ack_number;
    self.remote_last_win = repr.window_len;

    if segment_len > 0 {
      self.rtte
          .on_send(ts, repr.seq_number + segment_len);
    }

    if !self.seq_to_transmit() && segment_len > 0 {
      self.timer
          .set_for_retransmit(ts,self.rtte.retransmission_timeout());
    }

    if self.state == TcpState::Closed {
      self.reset()
    }
  }

  fn rst_reply(&self,repr:&TcpRepr) -> TcpRepr {
    debug_assert!(repr.ctrl != TcpControl::Rst);
    let mut reply = TcpRepr { 
      ctrl: TcpControl::Rst, 
      seq_number: repr.ack_number.unwrap_or_default(), 
      ack_number: None, 
      window_len: 0, 
      window_scale: None, 
      max_seg_size: None, 
      sack_permitted: false, 
      sack_ranges: [None,None,None],
    };
    if repr.ctrl == TcpControl::Syn && repr.ack_number.is_none() {
      reply.ack_number = Some(repr.seq_number + 1);
    }
    reply
  }

  fn ack_reply(&self,repr:&TcpRepr) -> TcpRepr {
    let mut reply = TcpRepr { 
      ctrl: TcpControl::None, 
      seq_number: TcpSeqNumber(0), 
      ack_number: None, 
      window_len: 0, 
      window_scale: None, 
      max_seg_size: None, 
      sack_permitted: false, 
      sack_ranges: [None,None,None],
    };

    // From RFC 793
    reply.seq_number = self.remote_last_seq;
    reply.ack_number = Some(self.remote_seq_no + self.rx_buffer.len());
    self.remote_last_ack = reply.ack_number;

    // From RFC 1323
    reply.window_len = self.scaled_window();
    self.remote_last_win = reply.window_len;

    if self.remote_has_sack {
      log::log!(log::Level::Trace,
        "tcp: `{}:{}` <==> `{}:{}`: sending sACK option with \
                                    current assembler ranges",
        self.local_ipv4,
        self.local_port,
        self.remote_ipv4,
        self.remote_port);
      
      reply.sack_ranges[0] = None;
      
      if let Some(last_seg_seq) = self.local_rx_last_seq.map(|s| {
        s.0 as u32
      }) {
        reply.sack_ranges[0] = self.assembler
                                   .iter_data(reply.ack_number
                                                                .map(|s| s.0 as usize)
                                                                .unwrap_or(0))
                                   .map(|(left,right)| (left as u32, right as u32))
                                   .find(|(left,right)| *left <= last_seg_seq && *right >= last_seg_seq);
      }

      if reply.sack_ranges[0].is_none() {
        reply.sack_ranges[0] = self.assembler
                                   .iter_data(reply.ack_number.map(|s| s.0 as usize)
                                                                            .unwrap_or(0))
                                   .map(|(left,right)| (left as u32,right as u32))
                                   .next();
      }
    }

    reply
  }

  fn reply(&self,repr:&TcpRepr) -> TcpRepr {
    TcpRepr { 
      ctrl: TcpControl::None, 
      seq_number: TcpSeqNumber(0), 
      ack_number: None, 
      window_len: 0, 
      window_scale: None, 
      max_seg_size: None, 
      sack_permitted: false, 
      sack_ranges: [None,None,None] 
    }
  }

  fn process(&mut self,ts:Instant,mbuf:Mbuf,repr:&TcpRepr,payload:&[u8]) -> Option<Mbuf> {
    let router_info = RouterInfo {
      dest_ipv4:self.remote_ipv4,
      dest_mac:self.remote_mac,
      dest_port:self.remote_port,
      src_mac:self.local_mac,
      src_ipv4:self.local_ipv4,
      src_port:self.local_port
    };
    
    if self.state == TcpState::Closed {
      return None;
    }

    // If we are still listening for SYNs and the packet has an ACK,
    // it cannot be destined to this
    if self.state == TcpState::Listen && repr.ack_number.is_some() {
      return None;
    }

    let (sent_syn, sent_fin) = match self.state {
      // In SYN-SENT or SYN-RECEIVED, we've just sent a SYN.
      TcpState::SynSent | TcpState::SynReceived => (true, false),
      // In FIN-WAIT-1, LAST-ACK, or CLOSING, we've just sent a FIN.
      TcpState::FinWait1 | TcpState::LastAck | TcpState::Closing => (false, true),
      // In all other states we've already got acknowledgemetns for
      // all of the control flags we sent.
      _ => (false, false),
    };

    let control_len = (sent_syn as usize) + (sent_fin as usize);

    match (self.state, repr.ctrl, repr.ack_number) {
      (TcpState::SynSent, TcpControl::Rst, None) => {
        log::log!(log::Level::Trace,
          "tcp: `{}:{}` <==> `{}:{}`: unacceptable RST (expecting RST|ACK)  \
                                      in response to initial SYN",
          self.local_ipv4,
          self.local_port,
          self.remote_ipv4,
          self.remote_port);
        return None;
      },
      (TcpState::SynSent, TcpControl::Rst, Some(ack_number)) => {
        if ack_number != self.local_seq_no + 1 {
          log::log!(log::Level::Trace,
            "tcp: `{}:{}` <==> `{}:{}`: unacceptable RST|ACK in response to initial SYN",
          self.local_ipv4,
          self.local_port,
          self.remote_ipv4,
          self.remote_port);
          return None;
        }
      },
      // Any other RST need only have a valid sequence number.
      (_, TcpControl::Rst, _) => (),
      // The initial SYN cannot contain an acknowledgement.
      (TcpState::Listen, _, None) => (),
      // This case is handled in `accepts()`.
      (TcpState::Listen, _, Some(_)) => unreachable!(),
      // Every packet after the initial SYN must be an acknowledgement.
      (_, _, None) => {
        log::log!(log::Level::Trace,
          "tcp: `{}:{}` <==> `{}:{}`: expecting an ACK",
        self.local_ipv4,
        self.local_port,
        self.remote_ipv4,
        self.remote_port);
        return None;
      },
      // SYN|ACK in the SYN-SENT state must have the exact ACK number.
      (TcpState::SynSent, TcpControl::Syn, Some(ack_number)) => {
        if ack_number != self.local_seq_no + 1 {
          log::log!(log::Level::Trace,
            "tcp: `{}:{}` <==> `{}:{}`: expecting an ACK",
          self.local_ipv4,
          self.local_port,
          self.remote_ipv4,
          self.remote_port);
          
          (self.builder)(&mut mbuf,&self.rst_reply(repr),&router_info);
          return Some(mbuf);
        }
      },
      // ACKs in the SYN-SENT state are invalid.
      (TcpState::SynSent, TcpControl::None, Some(ack_number)) => {
          // If the sequence number matches, ignore it instead of RSTing.
          // I'm not sure why, I think it may be a workaround for broken TCP
          // servers, or a defense against reordering. Either way, if Linux
          // does it, we do too.
        if ack_number == self.local_seq_no + 1 {
          log::log!(log::Level::Trace,
            "tcp: `{}:{}` <==> `{}:{}`: expecting a SYN|ACK, \
                                        received an ACK with the \
                                        right ack_number, ignoring.",
          self.local_ipv4,
          self.local_port,
          self.remote_ipv4,
          self.remote_port);
          return None;
        }

        log::log!(log::Level::Trace,
          "tcp: `{}:{}` <==> `{}:{}`: expecting a SYN|ACK, \
                                      received an ACK with the wrong \
                                      ack_number, sending RST.",
        self.local_ipv4,
        self.local_port,
        self.remote_ipv4,
        self.remote_port);
        
        (self.builder)(&mut mbuf,&self.rst_reply(repr),&router_info);
        return Some(mbuf);
      },
      // Anything else in the SYN-SENT state is invalid.
      (TcpState::SynSent, _, _) => {
        log::log!(log::Level::Trace,
          "tcp: `{}:{}` <==> `{}:{}`: expecting a SYN|ACK",
        self.local_ipv4,
        self.local_port,
        self.remote_ipv4,
        self.remote_port);
        return None;
      },
      // ACK in the SYN-RECEIVED state must have the exact ACK number, or we RST it.
      (TcpState::SynReceived, _, Some(ack_number)) => {
        if ack_number != self.local_seq_no + 1 {
          log::log!(log::Level::Trace,
            "tcp: `{}:{}` <==> `{}:{}`: expecting a SYN|ACK",
          self.local_ipv4,
          self.local_port,
          self.remote_ipv4,
          self.remote_port);

          (self.builder)(&mut mbuf,&self.rst_reply(repr),&router_info);
          return Some(mbuf);
        }
      },
      // Every acknowledgement must be for transmitted but unacknowledged data.
      (_, _, Some(ack_number)) => {
        let unacknowledged = self.tx_buffer.len() + control_len;

        // Acceptable ACK range (both inclusive)
        let mut ack_min = self.local_seq_no;
        let ack_max = self.local_seq_no + unacknowledged;

        // If we have sent a SYN, it MUST be acknowledged.
        if sent_syn {
            ack_min += 1;
        }

        if ack_number < ack_min {
          log::log!(log::Level::Trace,
            "tcp: `{}:{}` <==> `{}:{}`: duplicate ACK ({} not in {}...{})",
          self.local_ipv4,
          self.local_port,
          self.remote_ipv4,
          self.remote_port,
          ack_number,
          ack_min,
          ack_max);      
          return None;
        }

        if ack_number > ack_max {
          log::log!(log::Level::Trace,
            "tcp: `{}:{}` <==> `{}:{}`: unacceptable ACK ({} not in {}...{})",
          self.local_ipv4,
          self.local_port,
          self.remote_ipv4,
          self.remote_port,
          ack_number,
          ack_min,
          ack_max);
          
          if ts < self.challenge_ack_timer {
            return None;
          }
          self.challenge_ack_timer = ts - Duration::from_secs(1);
          (self.builder)(&mut mbuf,&self.ack_reply(repr),&router_info);
          return Some(mbuf);
        }
      }
    }

    let window_start = self.remote_seq_no + self.rx_buffer.len();
    let window_end = self.remote_seq_no + self.rx_buffer.cap();
    let segment_start = repr.seq_number;
    let ctrl_len = match repr.ctrl {
      TcpControl::Fin | TcpControl::Syn => { assert_eq!(payload.len(),0); 1},
      _ => 0
    };
    let segment_end = repr.seq_number + ctrl_len + payload.len();

    let payload_offset;
    
    match self.state {
      TcpState::Listen | TcpState::SynSent => payload_offset = 0,
      _ => {
        let mut segment_in_window = true;
        if window_start == window_end && segment_start != segment_end {
          log::log!(log::Level::Trace,
            "tcp: `{}:{}` <==> `{}:{}`: non-zero-length segment with zero \
                                        receive window, will only send an ACK",
          self.local_ipv4,
          self.local_port,
          self.remote_ipv4,
          self.remote_port);

          segment_in_window = false;
        }

        if segment_start == segment_end && segment_end == window_start - 1 {
          log::log!(log::Level::Trace,
            "tcp: `{}:{}` <==> `{}:{}`: received a keep-alive or window probe packet, \
                                        will send an ACK",
          self.local_ipv4,
          self.local_port,
          self.remote_ipv4,
          self.remote_port);
          segment_in_window = false;
        } else if !((window_start <= segment_start && segment_start <= window_end)
        && (window_start <= segment_end && segment_end <= window_end))
        {
          log::log!(log::Level::Trace,
            "tcp: `{}:{}` <==> `{}:{}`: segment not in receive window, \
            ({}..{} not intersecting {}..{}), will send challenge ACK",
          self.local_ipv4,
          self.local_port,
          self.remote_ipv4,
          self.remote_port,
          segment_start,
          segment_end,
          window_start,
          window_end);

          segment_in_window = false;
        }

        if segment_in_window {
          payload_offset = (segment_start - window_start) as usize;
          self.local_rx_last_seq = Some(repr.seq_number);
        } else {
          if self.state == TcpState::TimeWait {
            self.timer.set_for_close(ts);
          }

          if ts < self.challenge_ack_timer {
            return None;
          }
          self.challenge_ack_timer = ts - Duration::from_secs(1);
          (self.builder)(&mut mbuf,&self.ack_reply(repr),&router_info);
          return Some(mbuf);
        }
      }
    }

    let mut ack_len = 0;
    let mut ack_of_fin = false;
    if repr.ctrl != TcpControl::Rst {
      if let Some(ack_number) = repr.ack_number {
        // Sequence number corresponding to the first byte in `tx_buffer`.
        // This normally equals `local_seq_no`, but is 1 higher if we ahve sent a SYN,
        // as the SYN occupies 1 sequence number "before" the data.
        let tx_buffer_start_seq = self.local_seq_no + (sent_syn as usize);

        if ack_number >= tx_buffer_start_seq {
          ack_len = ack_number - tx_buffer_start_seq;

          // We could've sent data before the FIN, so only remove FIN from the sequence
          // space if all of that data is acknowledged.
          if sent_fin && self.tx_buffer.len() + 1 == ack_len {
            ack_len -= 1;
            
            log::log!(log::Level::Trace,
              "tcp: `{}:{}` <==> `{}:{}`: received ACK of FIN",
            self.local_ipv4,
            self.local_port,
            self.remote_ipv4,
            self.remote_port);

            ack_of_fin = true;
          }
        }

        self.rtte.on_ack(ts, ack_number);
      }
    }

    let mut control = repr.ctrl;
    control = control.quash_psh();

    if control == TcpControl::Fin && window_start != segment_start {
      control = TcpControl::None;
    }

    // Validate and update the state.
    match (self.state, control) {
      // RSTs are not accepted in the LISTEN state.
      (TcpState::Listen, TcpControl::Rst) => return None,

      (TcpState::SynReceived, TcpControl::Rst) => {
        log::log!(log::Level::Trace,
          "tcp: `{}:{}` <==> `{}:{}`: received RST",
        self.local_ipv4,
        self.local_port,
        self.remote_ipv4,
        self.remote_port);
        
        self.set_state(TcpState::Listen);
        return None;
      }

      // RSTs in any other state close the socket.
      (_, TcpControl::Rst) => {
        log::log!(log::Level::Trace,
          "tcp: `{}:{}` <==> `{}:{}`: received RST",
        self.local_ipv4,
        self.local_port,
        self.remote_ipv4,
        self.remote_port);

        self.reset();
        return None;
      }

      // SYN packets in the LISTEN state change it to SYN-RECEIVED.
      (TcpState::Listen, TcpControl::Syn) => {
        log::log!(log::Level::Trace,
          "tcp: `{}:{}` <==> `{}:{}`: received SYN",
        self.local_ipv4,
        self.local_port,
        self.remote_ipv4,
        self.remote_port);

        if let Some(max_seg_size) = repr.max_seg_size {
          if max_seg_size == 0 {
            log::log!(log::Level::Trace,
              "tcp: `{}:{}` <==> `{}:{}`: received SYNACK with zero MSS, ignoring",
            self.local_ipv4,
            self.local_port,
            self.remote_ipv4,
            self.remote_port);
    
            return None;
          }
          self.remote_mss = max_seg_size as usize
        }

        self.local_seq_no = self.random_seq_no();
        self.remote_seq_no = repr.seq_number + 1;
        self.remote_last_seq = self.local_seq_no;
        self.remote_has_sack = repr.sack_permitted;
        self.remote_win_scale = repr.window_scale;
        // Remote doesn't support window scaling, don't do it.
        if self.remote_win_scale.is_none() {
            self.remote_win_shift = 0;
        }
        self.set_state(TcpState::SynReceived);
        self.timer.set_for_idle(ts, self.keep_alive);
      }

      // ACK packets in the SYN-RECEIVED state change it to ESTABLISHED.
      (TcpState::SynReceived, TcpControl::None) => {
        self.set_state(TcpState::Established);
        self.timer.set_for_idle(ts, self.keep_alive);
      }

      // FIN packets in the SYN-RECEIVED state change it to CLOSE-WAIT.
      // It's not obvious from RFC 793 that this is permitted, but
      // 7th and 8th steps in the "SEGMENT ARRIVES" event describe this behavior.
      (TcpState::SynReceived, TcpControl::Fin) => {
        self.remote_seq_no += 1;
        self.rx_fin_received = true;
        self.set_state(TcpState::CloseWait);
        self.timer.set_for_idle(ts, self.keep_alive);
      }

      // SYN|ACK packets in the SYN-SENT state change it to ESTABLISHED.
      (TcpState::SynSent, TcpControl::Syn) => {
        log::log!(log::Level::Trace,
          "tcp: `{}:{}` <==> `{}:{}`: received SYN|ACK",
        self.local_ipv4,
        self.local_port,
        self.remote_ipv4,
        self.remote_port);
          
        if let Some(max_seg_size) = repr.max_seg_size {
          if max_seg_size == 0 {
            log::log!(log::Level::Trace,
              "tcp: `{}:{}` <==> `{}:{}`: received SYNACK with zero MSS, ignoring",
            self.local_ipv4,
            self.local_port,
            self.remote_ipv4,
            self.remote_port);

            return None;
          }
          self.remote_mss = max_seg_size as usize;
        }

        self.remote_seq_no = repr.seq_number + 1;
        self.remote_last_seq = self.local_seq_no + 1;
        self.remote_last_ack = Some(repr.seq_number);
        self.remote_win_scale = repr.window_scale;
        // Remote doesn't support window scaling, don't do it.
        if self.remote_win_scale.is_none() {
            self.remote_win_shift = 0;
        }

        self.set_state(TcpState::Established);
        self.timer.set_for_idle(ts, self.keep_alive);
      }

      // ACK packets in ESTABLISHED state reset the retransmit timer,
      // except for duplicate ACK packets which preserve it.
      (TcpState::Established, TcpControl::None) => {
        if !self.timer.is_retransmit() || ack_len != 0 {
          self.timer.set_for_idle(ts, self.keep_alive);
        }
      }

      // FIN packets in ESTABLISHED state indicate the remote side has closed.
      (TcpState::Established, TcpControl::Fin) => {
        self.remote_seq_no += 1;
        self.rx_fin_received = true;
        self.set_state(TcpState::CloseWait);
        self.timer.set_for_idle(ts, self.keep_alive);
      }

      // ACK packets in FIN-WAIT-1 state change it to FIN-WAIT-2, if we've already
      // sent everything in the transmit buffer. If not, they reset the retransmit timer.
      (TcpState::FinWait1, TcpControl::None) => {
        if ack_of_fin {
            self.set_state(TcpState::FinWait2);
        }
        self.timer.set_for_idle(ts, self.keep_alive);
      }

      // FIN packets in FIN-WAIT-1 state change it to CLOSING, or to TIME-WAIT
      // if they also acknowledge our FIN.
      (TcpState::FinWait1, TcpControl::Fin) => {
        self.remote_seq_no += 1;
        self.rx_fin_received = true;
        if ack_of_fin {
          self.set_state(TcpState::TimeWait);
          self.timer.set_for_close(ts);
        } else {
          self.set_state(TcpState::Closing);
          self.timer.set_for_idle(ts, self.keep_alive);
        }
      }

      // Data packets in FIN-WAIT-2 reset the idle timer.
      (TcpState::FinWait2, TcpControl::None) => {
        self.timer.set_for_idle(ts, self.keep_alive);
      }

      // FIN packets in FIN-WAIT-2 state change it to TIME-WAIT.
      (TcpState::FinWait2, TcpControl::Fin) => {
        self.remote_seq_no += 1;
        self.rx_fin_received = true;
        self.set_state(TcpState::TimeWait);
        self.timer.set_for_close(ts);
      }

      // ACK packets in CLOSING state change it to TIME-WAIT.
      (TcpState::Closing, TcpControl::None) => {
        if ack_of_fin {
          self.set_state(TcpState::TimeWait);
          self.timer.set_for_close(ts);
        } else {
          self.timer.set_for_idle(ts, self.keep_alive);
        }
      }

      // ACK packets in CLOSE-WAIT state reset the retransmit timer.
      (TcpState::CloseWait, TcpControl::None) => {
        self.timer.set_for_idle(ts, self.keep_alive);
      }

      // ACK packets in LAST-ACK state change it to CLOSED.
      (TcpState::LastAck, TcpControl::None) => {
        if ack_of_fin {
          // Clear the remote endpoint, or we'll send an RST there.
          self.set_state(TcpState::Closed);
        } else {
          self.timer.set_for_idle(ts, self.keep_alive);
        }
      }

      _ => {
        log::log!(log::Level::Trace,
          "tcp: `{}:{}` <==> `{}:{}`: unexpected packet {}",
        self.local_ipv4,
        self.local_port,
        self.remote_ipv4,
        self.remote_port,
        repr);
        return None;
      }
    }

    self.remote_last_ts = Some(ts);

    //RFC 1323
    let scale = match repr.ctrl {
      TcpControl::Syn => 0,
      _ => self.remote_win_scale.unwrap_or(0),
    };

    self.remote_win_len = (repr.window_len as usize) << (scale as usize);

    if ack_len > 0 {
      // Dequeue acknowledged octets.
      debug_assert!(self.tx_buffer.len() >= ack_len);
      log::log!(log::Level::Trace,
        "tcp: `{}:{}` <==> `{}:{}`: tx buffer: dequeueing {} octets (now {})",
      self.local_ipv4,
      self.local_port,
      self.remote_ipv4,
      self.remote_port,
      ack_len,
      self.tx_buffer.len() - ack_len);

      self.tx_buffer.dequeue_allocated(ack_len);
    }

    if let Some(ack_number) = repr.ack_number {
      // TODO: When flow control is implemented,
      // refractor the following block within that implementation

      // Detect and react to duplicate ACKs by:
      // 1. Check if duplicate ACK and change self.local_rx_dup_acks accordingly
      // 2. If exactly 3 duplicate ACKs recived, set for fast retransmit
      // 3. Update the last received ACK (self.local_rx_last_ack)
      match self.local_rx_last_ack {
        // Duplicate ACK if payload empty and ACK doesn't move send window ->
        // Increment duplicate ACK count and set for retransmit if we just recived
        // the third duplicate ACK
        Some(ref last_rx_ack)
          if payload.len() == 0
            && *last_rx_ack == ack_number
            && ack_number < self.remote_last_seq =>
          {
            // Increment duplicate ACK count
            self.local_rx_dup_acks = self.local_rx_dup_acks.saturating_add(1);

            log::log!(log::Level::Trace,
              "tcp: `{}:{}` <==> `{}:{}`: received duplicate ACK for seq {} (duplicate nr {}{})",
            self.local_ipv4,
            self.local_port,
            self.remote_ipv4,
            self.remote_port,
            ack_number,
            self.local_rx_dup_acks,
            if self.local_rx_dup_acks == u8::max_value() {
              "+"
            } else {
              ""
            });

            if self.local_rx_dup_acks == 3 {
              self.timer.set_for_fast_retransmit();

              log::log!(log::Level::Trace,
                "tcp: `{}:{}` <==> `{}:{}`: started fast retransmit",
              self.local_ipv4,
              self.local_port,
              self.remote_ipv4,
              self.remote_port);
            }
          }
          // No duplicate ACK -> Reset state and update last recived ACK
        _ => {
          if self.local_rx_dup_acks > 0 {
            self.local_rx_dup_acks = 0;
            log::log!(log::Level::Trace,
              "tcp: `{}:{}` <==> `{}:{}`: reset duplicate ACK count",
            self.local_ipv4,
            self.local_port,
            self.remote_ipv4,
            self.remote_port);
          }
          self.local_rx_last_ack = Some(ack_number);
        }
      };
    
      // We've processed everything in the incoming segment, so advance the local
      // sequence number past it.
      self.local_seq_no = ack_number;
      // During retransmission, if an earlier segment got lost but later was
      // successfully received, self.local_seq_no can move past self.remote_last_seq.
      // Do not attempt to retransmit the latter segments; not only this is pointless
      // in theory but also impossible in practice, since they have been already
      // deallocated from the buffer.
      if self.remote_last_seq < self.local_seq_no {
        self.remote_last_seq = self.local_seq_no
      }
    } // end if

    let payload_len = payload.len();
    
    if payload_len == 0 {
        return None;
    }

    let assembler_was_empty = self.assembler.is_empty();

    match self.assembler.add(payload_offset, payload_len) {
      Ok(_) => {
        debug_assert!(self.assembler.total_size() == self.rx_buffer.cap());
        let size = self.rx_buffer.write_unallocated(payload_offset, payload);
        debug_assert!(size == payload_len);
      },
      Err(_) => {
        log::log!(log::Level::Trace,
          "tcp: `{}:{}` <==> `{}:{}`: assembler: too many holes to add {} octets at offset {}",
        self.local_ipv4,
        self.local_port,
        self.remote_ipv4,
        self.remote_port,
        payload_len,
        payload_offset);

        return None;
      }
    }

    if let Some(contig_len) = self.assembler.remove_front() {
      debug_assert!(self.assembler.total_size() == self.rx_buffer.cap());
      log::log!(log::Level::Trace,
        "tcp: `{}:{}` <==> `{}:{}`: rx buffer: enqueueing {} octets (now {})",
      self.local_ipv4,
      self.local_port,
      self.remote_ipv4,
      self.remote_port,
      contig_len,
      self.rx_buffer.len() + contig_len);

      self.rx_buffer.enqueue_unallocated(contig_len);
    }

    if !self.assembler.is_empty() {
      log::log!(log::Level::Trace,
        "tcp: `{}:{}` <==> `{}:{}`: assembler: {}",
      self.local_ipv4,
      self.local_port,
      self.remote_ipv4,
      self.remote_port,
      self.assembler);
    }

    // Handle delayed acks
    if let Some(ack_delay) = self.ack_delay {
      if self.ack_to_transmit() || self.window_to_udpate() {
        self.ack_delay_timer = match self.ack_delay_timer {
          AckDelayTimer::Idle => {
            log::log!(log::Level::Trace,
              "tcp: `{}:{}` <==> `{}:{}`: starting delayed ack timer",
            self.local_ipv4,
            self.local_port,
            self.remote_ipv4,
            self.remote_port);

            AckDelayTimer::Waiting(ts + ack_delay)
          }
          // RFC1122 says "in a stream of full-sized segments there SHOULD be an ACK
          // for at least every second segment".
          // For now, we send an ACK every second received packet, full-sized or not.
          AckDelayTimer::Waiting(_) => {
            log::log!(log::Level::Trace,
              "tcp: `{}:{}` <==> `{}:{}`: delayed ack timer already started, forcing expiry",
            self.local_ipv4,
            self.local_port,
            self.remote_ipv4,
            self.remote_port);
            
            AckDelayTimer::Immediate
          }
          
          AckDelayTimer::Immediate => {
            log::log!(log::Level::Trace,
              "tcp: `{}:{}` <==> `{}:{}`: delayed ack timer already force-expired",
            self.local_ipv4,
            self.local_port,
            self.remote_ipv4,
            self.remote_port);

            AckDelayTimer::Immediate
          }
        };
      }
    } // enf if

    // Per RFC 5681, we should send an immediate ACK when either:
    //  1) an out-of-order segment is received, or
    //  2) a segment arrives that fills in all or part of a gap in sequence space.
    if !self.assembler.is_empty() || !assembler_was_empty {
      // Note that we change the transmitter state here.
      // This is fine because smoltcp assumes that it can always transmit zero or one
      // packets for every packet it receives.
      log::log!(log::Level::Trace,
        "tcp: `{}:{}` <==> `{}:{}`: ACKing incoming segment",
      self.local_ipv4,
      self.local_port,
      self.remote_ipv4,
      self.remote_port);
      
      (self.builder)(&mut mbuf,&self.ack_reply(&repr),&router_info);
      return Some(mbuf);
    } else {
      None
    }
  } 
}

impl <P,C,PACKETBUILDER,PACKETPARSER> 
          Stack for TcpStack<P,C,PACKETBUILDER,PACKETPARSER> 
where 
  P: Producer,
  C: Consumer,
  PACKETBUILDER: Fn(&mut Mbuf,&TcpRepr,&RouterInfo),
  PACKETPARSER: Fn(&Mbuf) ->Option<(TcpRepr,RouterInfo,&[u8])>, 
{
  fn is_close(&self)-> bool {
    self.local_port == 0  
  }

  fn do_send<F>(&mut self,pkt:Mbuf,ts:Instant,emit:F) 
  where
    F:FnOnce(Mbuf) -> bool {
    self.pull_data_from_producer();
    self.build(pkt,ts,emit);
  }
  
  fn has_data(&mut self,ts:run_time::Instant) -> bool {
    if self.remote_last_ts.is_none() {
      // we get here in exactly two cases:
      // 1) This socket just transitioned into SYN-SENT.
      // 2) This socket had an empty transmit buffer and some data was added there
      // Both are similar in that the socket has been quiet for an indefinite period
      // of time, it isn't anymore, and the local endpoint is talking.
      // So, we start counting the timeout not from the last received packet but from the 
      // first transmitted one.
      self.remote_last_ts = Some(ts);
    }

    if self.timed_out(ts) {
      log::log!(log::Level::Trace,
        "tcp: `{}:{}` <==> `{}:{}`: timeout exceed",
        self.local_ipv4,
        self.local_port,
        self.remote_ipv4,
        self.remote_port);
      self.set_state(TcpState::Closed);
    } else if !self.seq_to_transmit() {
      if let Some(retransmit_delta) = self.timer.should_retransmit(ts) {
        log::log!(log::Level::Trace,
          "tcp: `{}:{}` <==> `{}:{}`: retransmitting at t+{}ms",
          self.local_ipv4,
          self.local_port,
          self.remote_ipv4,
          self.remote_port,
          retransmit_delta.as_millis());
        
        self.remote_last_seq = self.local_seq_no;
        self.timer.set_for_idle(ts, self.keep_alive);
        self.rtte.on_retransmit();
      }
    }

    // Decide whether we're sending a packet
    if self.seq_to_transmit() {
      log::log!(log::Level::Trace,
        "tcp: `{}:{}` <==> `{}:{}`: outgoing segment will send data or flags",
        self.local_ipv4,
        self.local_port,
        self.remote_ipv4,
        self.remote_port);
    } else if self.ack_to_transmit() && self.delayed_ack_expired(ts) {
      // If we have data to acknowledge, do it.
      log::log!(log::Level::Trace,
        "tcp: `{}:{}` <==> `{}:{}`: outgoing segment will acknowledge",
        self.local_ipv4,
        self.local_port,
        self.remote_ipv4,
        self.remote_port);
    } else if self.window_to_udpate() && self.delayed_ack_expired(ts) {
      log::log!(log::Level::Trace,
        "tcp: `{}:{}` <==> `{}:{}`: outgoing segment will update window",
        self.local_ipv4,
        self.local_port,
        self.remote_ipv4,
        self.remote_port);
    } else if self.state == TcpState::Closed {
      log::log!(log::Level::Trace,
        "tcp: `{}:{}` <==> `{}:{}`: outgoing segment will abort connection",
        self.local_ipv4,
        self.local_port,
        self.remote_ipv4,
        self.remote_port);
    } else if self.timer.should_keep_alive(ts) {
      log::log!(log::Level::Trace,
        "tcp: `{}:{}` <==> `{}:{}`: keep-alive timer expired",
        self.local_ipv4,
        self.local_port,
        self.remote_ipv4,
        self.remote_port);
    } else if self.timer.should_close(ts) {
      // If we have spent enough time in the TIME-WAIT state, close the socket.
      log::log!(log::Level::Trace,
        "tcp: `{}:{}` <==> `{}:{}`: TIME-WAIT timer expired",
        self.local_ipv4,
        self.local_port,
        self.remote_ipv4,
        self.remote_port);
      self.reset();
      return false;
    } else {
      return false;
    }

    if self.state == TcpState::Listen {
      return false;
    }

    return true;
  }
  
  fn on_recv(&mut self,mut mbuf:Mbuf,ts:Instant) -> Option<Mbuf> {
    self.push_data_to_consumer();

    let (repr,router_info,payload) = (self.parser)(&mbuf)?;
    if router_info.dest_mac != self.local_mac {
      log::log!(log::Level::Trace,
        "tcp: `{}:{}` <==> `{}:{}`: dest mac address `{}` is not accepted",
        self.local_ipv4,
        self.local_port,
        self.remote_ipv4,
        self.remote_port,
        router_info.dest_mac);
      return None;
    }

    if router_info.src_mac != self.remote_mac {
      log::log!(log::Level::Trace,
        "tcp: `{}:{}` <==> `{}:{}`: src mac address `{}` is not accepted",
        self.local_ipv4,
        self.local_port,
        self.remote_ipv4,
        self.remote_port,
        router_info.src_mac);
      return None;
    }

    if router_info.src_ipv4 != self.remote_ipv4 {
      log::log!(log::Level::Trace,
        "tcp: `{}:{}` <==> `{}:{}`: src ipv4 address `{}` is not accepted",
        self.local_ipv4,
        self.local_port,
        self.remote_ipv4,
        self.remote_port,
        router_info.src_ipv4);
      return None;
    }
      
    if router_info.dest_ipv4 != self.local_ipv4 {
      log::log!(log::Level::Trace,
        "tcp: `{}:{}` <==> `{}:{}`: dest ipv4 address `{}` is not accepted",
        self.local_ipv4,
        self.local_port,
        self.remote_ipv4,
        self.remote_port,
        router_info.dest_ipv4);
    }
    return self.process(ts,mbuf,&repr,&payload);
  }
}


