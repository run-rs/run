use run_packet::{tcp::TCP_HEADER_LEN, ether::ETHER_HEADER_LEN, ipv4::IPV4_HEADER_LEN};

pub const DEFAULT_MSS: usize = 536;

pub const ACK_DELAY_DEFAULT: std::time::Duration = 
                                            std::time::Duration::
                                                           from_millis(10);

pub const CLOSE_DELAY: std::time::Duration = 
                                      std::time::Duration::from_millis(10_000);

pub const RTTE_INITIAL_RTT: u32 = 300;

pub const RTTE_INITIAL_DEV: u32 = 100;

pub const RTTE_MIN_MARGIN: u32 = 5;


pub const RTTE_MIN_RTO: u32 = 10;

pub const RTTE_MAX_RTO: u32 = 10000;

pub const MAX_TOTAL_HEAD_OVERHEAD:usize = 60 + ETHER_HEADER_LEN + IPV4_HEADER_LEN;
