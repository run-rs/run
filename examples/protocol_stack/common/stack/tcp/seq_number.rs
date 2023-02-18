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