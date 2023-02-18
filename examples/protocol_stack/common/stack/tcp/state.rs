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

impl std::fmt::Display for TcpState {
  fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
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