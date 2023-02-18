use std::fmt;
use run_packet::{ether::MacAddr, ipv4::Ipv4Addr};
use run_time::Instant;
use std::time::Duration;



pub const DEFAULT_MSS: usize = 536;

pub const ACK_DELAY_DEFAULT: Duration = Duration::from_millis(10);
pub const CLOSE_DELAY: Duration = Duration::from_millis(10_000);
pub const RTTE_INITIAL_RTT: u32 = 300;
pub const RTTE_INITIAL_DEV: u32 = 100;
pub const RTTE_MIN_MARGIN: u32 = 5;

pub const RTTE_MIN_RTO: u32 = 10;
pub const RTTE_MAX_RTO: u32 = 10000;

#[derive(Debug,PartialEq, Eq, Ord,Clone, Copy,Default)]
#[repr(transparent)]
pub struct TcpSeqNumber(pub i32);

impl core::fmt::Display for TcpSeqNumber{
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
      write!(f,"{}",self.0)
  }
}

impl core::ops::Add<usize> for TcpSeqNumber {
  type Output = TcpSeqNumber;

  fn add(self, rhs: usize) -> TcpSeqNumber {
      if rhs > i32::MAX as usize {
          panic!("attempt to add to sequence number with unsigned overflow")
      }
      TcpSeqNumber(self.0.wrapping_add(rhs as i32))
  }
}

impl core::ops::Sub<usize> for TcpSeqNumber {
  type Output = TcpSeqNumber;

  fn sub(self, rhs: usize) -> TcpSeqNumber {
      if rhs > i32::MAX as usize {
          panic!("attempt to subtract to sequence number with unsigned overflow")
      }
      TcpSeqNumber(self.0.wrapping_sub(rhs as i32))
  }
}

impl core::ops::AddAssign<usize> for TcpSeqNumber {
  fn add_assign(&mut self, rhs: usize) {
      *self = *self + rhs;
  }
}

impl core::ops::Sub for TcpSeqNumber {
  type Output = usize;

  fn sub(self, rhs: TcpSeqNumber) -> usize {
      let result = self.0.wrapping_sub(rhs.0);
      if result < 0 {
          panic!("attempt to subtract sequence numbers with underflow")
      }
      result as usize
  }
}

impl core::cmp::PartialOrd for TcpSeqNumber {
  fn partial_cmp(&self, other: &TcpSeqNumber) -> Option<core::cmp::Ordering> {
      self.0.wrapping_sub(other.0).partial_cmp(&0)
  }
}


#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum TcpState {
  Closed,
  Listen,
  SynSent,
  SynReceived,
  Established,
  FinWait1,
  FinWait2,
  CloseWait,
  Closing,
  LastAck,
  TimeWait
}
impl Default for TcpState {
  fn default() -> Self {
      TcpState::Closed
  }
}

impl fmt::Display for TcpState {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
      match *self {
        TcpState::Closed => write!(f, "CLOSED"),
        TcpState::Listen => write!(f, "LISTEN"),
        TcpState::SynSent => write!(f, "SYN-SENT"),
        TcpState::SynReceived => write!(f, "SYN-RECEIVED"),
        TcpState::Established => write!(f, "ESTABLISHED"),
        TcpState::FinWait1 => write!(f, "FIN-WAIT-1"),
        TcpState::FinWait2 => write!(f, "FIN-WAIT-2"),
        TcpState::CloseWait => write!(f, "CLOSE-WAIT"),
        TcpState::Closing => write!(f, "CLOSING"),
        TcpState::LastAck => write!(f, "LAST-ACK"),
        TcpState::TimeWait => write!(f, "TIME-WAIT"),
      }
  }
}


#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum AckDelayTimer {
    Idle,
    Waiting(Instant),
    Immediate,
}

#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct RttEstimator {
  rtt: u32,
  deviation: u32,
  timestamp: Option<(Instant,TcpSeqNumber)>,
  max_seq_sent: Option<TcpSeqNumber>,
  rto_count: u8
}

impl Default for RttEstimator {
  fn default() -> Self {
    Self { 
      rtt: RTTE_INITIAL_RTT, 
      deviation: RTTE_INITIAL_DEV, 
      timestamp: None, 
      max_seq_sent: None, 
      rto_count: 0 
    }
  }
}


impl RttEstimator {
  pub(crate) fn retransmission_timeout(&self) -> Duration {
    let margin = RTTE_MIN_MARGIN.max(self.deviation * 4);
    let ms = (self.rtt + margin).max(RTTE_MIN_RTO).min(RTTE_MAX_RTO);
    Duration::from_millis(ms as u64)
  }

  pub(crate) fn sample(&mut self,new_rtt: u32) {
    self.rtt = (self.rtt * 7 + new_rtt + 7) / 8;
    let diff = (self.rtt as i32 - new_rtt as i32).abs() as u32;
    self.deviation = (self.deviation * 3 + diff + 3) / 4;
    self.rto_count = 0;
    let rto = self.retransmission_timeout().as_millis();
    log::log!(log::Level::Trace,
      "rtte: sample={:?} rtt={:?} dev={:?} rto={:?}",
      new_rtt,
      self.rtt,
      self.deviation,
      rto);
  }

  pub(crate) fn on_send(&mut self,ts:Instant,seq: TcpSeqNumber) {
    if self.max_seq_sent
           .map(|max_seq_sent| seq > max_seq_sent)
           .unwrap_or(true)
    {
      self.max_seq_sent = Some(seq);
      if self.timestamp.is_none() {
        self.timestamp = Some((ts,seq));
        log::log!(log::Level::Trace,"rtte: sampling at seq={:?}",seq);
      }
    }
  }

  pub(crate) fn on_ack(&mut self,ts:Instant,seq: TcpSeqNumber) {
    if let Some((sent_ts,sent_seq)) = self.timestamp {
      if seq >= sent_seq {
        self.sample((ts - sent_ts).as_millis() as u32);
        self.timestamp = None;
      }
    }
  }

  pub(crate) fn on_retransmit(&mut self) {
    if self.timestamp.is_some() {
      log::log!(log::Level::Trace,"rtte: abort sampling due to retransmit");
    }
    self.timestamp = None;
    self.rto_count = self.rto_count.saturating_add(1);
    if self.rto_count >=3 {
      self.rto_count = 0;
      self.rtt = RTTE_MAX_RTO.min(self.rtt * 2);
      let rto = self.retransmission_timeout().as_millis();
      log::log!(log::Level::Trace,
        "rtte: too many retransmissions,increasing: rtt={:?} dev={:?} rto={:?}",
        self.rtt,
        self.deviation,
        rto);
    }
  }
}

#[derive(Debug, PartialOrd, Ord, PartialEq, Eq, Clone, Copy)]
pub(crate) enum PollAt {
    /// The socket needs to be polled immidiately.
    Now,
    /// The socket needs to be polled at given [Instant][struct.Instant].
    Time(Instant),
    /// The socket does not need to be polled unless there are external changes.
    Ingress,
}


#[derive(Debug, Clone, Copy, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Timer {
    Idle {
        keep_alive_at: Option<Instant>,
    },
    Retransmit {
        expires_at: Instant,
        delay: Duration,
    },
    FastRetransmit,
    Close {
        expires_at: Instant,
    },
}

impl Timer {
  pub fn new() -> Timer {
    Timer::Idle { 
      keep_alive_at: None, 
    }
  }

  pub fn should_keep_alive(&self,ts:Instant) -> bool {
    match *self {
      Timer::Idle { 
        keep_alive_at:Some(keep_aliva_at) 
      } if ts >= keep_aliva_at => true,
      _ => false,
    }
  }

  pub fn should_retransmit(&self,ts:Instant) -> Option<Duration> {
    match *self {
      Timer::Retransmit { expires_at, delay } if ts >= expires_at => {
          Some(ts - expires_at + delay)
      }
      Timer::FastRetransmit => Some(Duration::from_millis(0)),
      _ => None,
    }
  }

  pub fn should_close(&self,ts:Instant) -> bool {
    match *self {
      Timer::Close { expires_at } if ts >= expires_at => true,
      _ => false
    }
  }

  pub(crate) fn poll_at(&self) -> PollAt {
    match *self {
      Timer::Idle {
          keep_alive_at: Some(keep_alive_at),
      } => PollAt::Time(keep_alive_at),
      Timer::Idle {
          keep_alive_at: None,
      } => PollAt::Ingress,
      Timer::Retransmit { expires_at, .. } => PollAt::Time(expires_at),
      Timer::FastRetransmit => PollAt::Now,
      Timer::Close { expires_at } => PollAt::Time(expires_at),
    }
  }

  pub fn set_for_idle(&mut self, timestamp: Instant, interval: Option<Duration>) {
    *self = Timer::Idle {
        keep_alive_at: interval.map(|interval| timestamp + interval),
    }
  }

  pub fn set_keep_alive(&mut self) {
    if let Timer::Idle {
        ref mut keep_alive_at,
    } = *self
    {
        if keep_alive_at.is_none() {
            *keep_alive_at = Some(Instant::from_millis(0))
        }
    }
  }

  pub(crate) fn rewind_keep_alive(&mut self, timestamp: Instant, interval: Option<Duration>) {
    if let Timer::Idle {
        ref mut keep_alive_at,
    } = *self
    {
        *keep_alive_at = interval.map(|interval| timestamp + interval)
    }
  }

  pub(crate) fn set_for_retransmit(&mut self, timestamp: Instant, delay: Duration) {
    match *self {
        Timer::Idle { .. } | Timer::FastRetransmit { .. } => {
            *self = Timer::Retransmit {
                expires_at: timestamp + delay,
                delay,
            }
        }
        Timer::Retransmit { expires_at, delay } if timestamp >= expires_at => {
            *self = Timer::Retransmit {
                expires_at: timestamp + delay,
                delay: delay * 2,
            }
        }
        Timer::Retransmit { .. } => (),
        Timer::Close { .. } => (),
    }
  }

  pub fn set_for_fast_retransmit(&mut self) {
    *self = Timer::FastRetransmit
  }

  pub fn set_for_close(&mut self, timestamp: Instant) {
    *self = Timer::Close {
        expires_at: timestamp + CLOSE_DELAY,
    }
  }

  pub fn is_retransmit(&self) -> bool {
    match *self {
        Timer::Retransmit { .. } | Timer::FastRetransmit => true,
        _ => false,
    }
  }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum TcpControl {
    None,
    Psh,
    Syn,
    Fin,
    Rst,
}

impl TcpControl {
  /// Return the length of a control flag, in terms of sequence space.
  pub fn len(self) -> usize {
    match self {
        TcpControl::Syn | TcpControl::Fin => 1,
        _ => 0,
    }
  }

  /// Turn the PSH flag into no flag, and keep the rest as-is.
  pub fn quash_psh(self) -> TcpControl {
    match self {
        TcpControl::Psh => TcpControl::None,
        _ => self,
    }
  }
}

#[derive(Debug,PartialEq,Eq)]
pub struct TcpRepr {
  pub ctrl:TcpControl,
  pub seq_number: TcpSeqNumber,
  pub ack_number: Option<TcpSeqNumber>,
  pub window_len: u16,
  pub window_scale: Option<u8>,
  pub max_seg_size: Option<u16>,
  pub sack_permitted: bool,
  pub sack_ranges: [Option<(u32,u32)>;3],
}

impl core::fmt::Display for TcpRepr {
  fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
    match self.ctrl {
      TcpControl::Syn => write!(f, " syn")?,
      TcpControl::Fin => write!(f, " fin")?,
      TcpControl::Rst => write!(f, " rst")?,
      TcpControl::Psh => write!(f, " psh")?,
      TcpControl::None => (),
    }
    write!(f, " seq={}", self.seq_number)?;
    if let Some(ack_number) = self.ack_number {
      write!(f, " ack={}", ack_number)?;
    }
    write!(f, " win={}", self.window_len)?;
    if let Some(max_seg_size) = self.max_seg_size {
        write!(f, " mss={}", max_seg_size)?;
    }
    Ok(())
  }
}

pub struct RouterInfo {
  pub dest_mac:MacAddr,
  pub src_mac:MacAddr,
  pub dest_ipv4:Ipv4Addr,
  pub src_ipv4:Ipv4Addr,
  pub dest_port:u16,
  pub src_port:u16,
}