use run_dpdk::Mbuf;
use run_dpdk::Pbuf;
use run_packet::ether::ETHER_HEADER_LEN;
use run_packet::ether::EtherPacket;
use run_packet::ipv4::IPV4_HEADER_LEN;
use run_packet::ipv4::Ipv4Addr;
use run_packet::ether::MacAddr;
use run_packet::tcp::TCP_HEADER_LEN;
use run_time::Instant;
use std::fmt;
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
  PACKETPARSER: Fn(&mut Mbuf) ->Option<(TcpRepr,RouterInfo,&[u8])>, 
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
  PACKETPARSER: Fn(&mut Mbuf) ->Option<(TcpRepr,RouterInfo,&[u8])>, 
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
  PACKETPARSER: Fn(&mut Mbuf) ->Option<(TcpRepr,RouterInfo,&[u8])>, 
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

  fn fill_mbuf<F>(&mut self,mut mbuf:Mbuf,ts:Instant,emit:F)
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
}

impl <P,C,PACKETBUILDER,PACKETPARSER> 
          Stack for TcpStack<P,C,PACKETBUILDER,PACKETPARSER> 
where 
  P: Producer,
  C: Consumer,
  PACKETBUILDER: Fn(&mut Mbuf,&TcpRepr,&RouterInfo),
  PACKETPARSER: Fn(&mut Mbuf) ->Option<(TcpRepr,RouterInfo,&[u8])>, 
{
  fn is_close(&self)-> bool {
    self.local_port == 0  
  }

  fn do_send<F>(&mut self,pkt:Mbuf,ts:Instant,emit:F) 
  where
    F:FnOnce(Mbuf) -> bool {
    self.pull_data_from_producer();
    self.fill_mbuf(pkt,ts,emit);
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
  
  fn on_recv(&mut self,mut mbuf:Mbuf,ts:run_time::Instant) -> Option<Mbuf> {
    if let Some(
      (repr,
      router_info,
      payload)
    ) = (self.parser)(&mut mbuf) {
      
      todo!()
    } else {
      return None;
    }
  }
}


