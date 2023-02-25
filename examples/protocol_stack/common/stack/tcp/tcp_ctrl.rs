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

impl Default for TcpControl {
  fn default() -> Self {
    TcpControl::None
  }
}
