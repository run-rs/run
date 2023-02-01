#[derive(Debug, PartialEq, Eq, Default)]
pub struct TcpRepr {
  pub ctrl: super::tcp_ctrl::TcpControl,
  pub seq_number: super::seq_number::TcpSeqNumber,
  pub ack_number: Option<super::seq_number::TcpSeqNumber>,
  pub window_len: u16,
  pub window_scale: Option<u8>,
  pub max_seg_size: Option<u16>,
  pub sack_permitted: bool,
  pub sack_ranges: [Option<(u32, u32)>; 3],
}

impl core::fmt::Display for TcpRepr {
  fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
    match self.ctrl {
      super::tcp_ctrl::TcpControl::Syn => write!(f, " syn")?,
      super::tcp_ctrl::TcpControl::Fin => write!(f, " fin")?,
      super::tcp_ctrl::TcpControl::Rst => write!(f, " rst")?,
      super::tcp_ctrl::TcpControl::Psh => write!(f, " psh")?,
      super::tcp_ctrl::TcpControl::None => (),
    }
    write!(f, " seq={}", self.seq_number.0 as u32)?;
    if let Some(ack_number) = self.ack_number {
      write!(f, " ack={}", ack_number.0 as u32)?;
    }
    write!(f, " win={}", self.window_len)?;
    if let Some(max_seg_size) = self.max_seg_size {
      write!(f, " mss={}", max_seg_size)?;
    }
    Ok(())
  }
}
