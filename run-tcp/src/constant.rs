pub const DEFAULT_MSS: usize = 536;

pub const ACK_DELAY_DEFAULT: smoltcp::time::Duration =
  smoltcp::time::Duration::from_millis(10);

pub const CLOSE_DELAY: smoltcp::time::Duration =
  smoltcp::time::Duration::from_millis(10_000);

pub const RTTE_INITIAL_RTT: u32 = 300;

pub const RTTE_INITIAL_DEV: u32 = 100;

pub const RTTE_MIN_MARGIN: u32 = 5;

pub const RTTE_MIN_RTO: u32 = 10;

pub const RTTE_MAX_RTO: u32 = 10000;
