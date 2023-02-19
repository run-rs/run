#[derive(Debug, PartialOrd, Ord, PartialEq, Eq, Clone, Copy)]
pub(crate) enum PollAt {
    /// The socket needs to be polled immidiately.
    Now,
    /// The socket needs to be polled at given [Instant][struct.Instant].
    Time(smoltcp::time::Instant),
    /// The socket does not need to be polled unless there are external changes.
    Ingress,
}


#[derive(Debug, Clone, Copy, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Timer {
    Idle {
        keep_alive_at: Option<smoltcp::time::Instant>,
    },
    Retransmit {
        expires_at: smoltcp::time::Instant,
        delay: smoltcp::time::Duration,
    },
    FastRetransmit,
    Close {
        expires_at: smoltcp::time::Instant,
    },
}

impl Timer {
  pub fn new() -> Timer {
    Timer::Idle { 
      keep_alive_at: None, 
    }
  }

  pub fn should_keep_alive(&self,ts:smoltcp::time::Instant) -> bool {
    match *self {
      Timer::Idle { 
        keep_alive_at:Some(keep_aliva_at) 
      } if ts >= keep_aliva_at => true,
      _ => false,
    }
  }

  pub fn should_retransmit(&self,ts:smoltcp::time::Instant) -> Option<smoltcp::time::Duration> {
    match *self {
      Timer::Retransmit { expires_at, delay } if ts >= expires_at => {
          Some(ts - expires_at + delay)
      }
      Timer::FastRetransmit => Some(smoltcp::time::Duration::from_millis(0)),
      _ => None,
    }
  }

  pub fn should_close(&self,ts:smoltcp::time::Instant) -> bool {
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

  pub fn set_for_idle(&mut self, timestamp: smoltcp::time::Instant, interval: Option<smoltcp::time::Duration>) {
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
            *keep_alive_at = Some(smoltcp::time::Instant::from_millis(0))
        }
    }
  }

  pub(crate) fn rewind_keep_alive(&mut self, timestamp: smoltcp::time::Instant, interval: Option<smoltcp::time::Duration>) {
    if let Timer::Idle {
        ref mut keep_alive_at,
    } = *self
    {
        *keep_alive_at = interval.map(|interval| timestamp + interval)
    }
  }

  pub(crate) fn set_for_retransmit(&mut self, timestamp: smoltcp::time::Instant, delay: smoltcp::time::Duration) {
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

  pub fn set_for_close(&mut self, timestamp: smoltcp::time::Instant) {
    *self = Timer::Close {
        expires_at: timestamp + super::constant::CLOSE_DELAY,
    }
  }

  pub fn is_retransmit(&self) -> bool {
    match *self {
        Timer::Retransmit { .. } | Timer::FastRetransmit => true,
        _ => false,
    }
  }
}