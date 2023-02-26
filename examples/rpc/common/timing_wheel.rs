use std::sync::{Arc, Mutex};

use crate::hugealloc::HugeAlloctor;

pub struct TimingWheel {}

impl TimingWheel {
  pub(crate) fn new(args: &TimingWheelArgs) -> Self {
    Self {}
  }

  pub(crate) fn catchup(&mut self) {
    unimplemented!()
  }
}

pub(crate) struct TimingWheelArgs<'a> {
  pub(crate) freq_ghz: f64,
  pub(crate) huge_alloc: &'a mut HugeAlloctor,
}
