#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum AckDelayTimer {
  Idle,
  Waiting(smoltcp::time::Instant),
  Immediate,
}
