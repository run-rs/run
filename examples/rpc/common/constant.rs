use run_packet::{ether::ETHER_HEADER_LEN, ipv4::IPV4_HEADER_LEN, udp::UDP_HEADER_LEN};

use crate::common::msgbuffer::RpcHeader;


pub const K_MAX_HOSTNAME_LEN:usize = 128;
pub const K_MAX_ROUTING_INFO_SIZE:usize =ETHER_HEADER_LEN+IPV4_HEADER_LEN+UDP_HEADER_LEN;
pub const K_MAX_MEM_REG_INFO_SIZE:usize=64;
pub const MAX_RPC_ID:usize= u8::MAX as usize -1;
pub const REQ_TYPE_ARRAY_SIZE:usize=u8::MAX as usize +1;
pub const INVALID_REQ_TYPE:usize = REQ_TYPE_ARRAY_SIZE-1;
pub const MACHINE_FAILURE_TIMEOUT_MS:u64=500;
pub const BASE_SM_UDP_PORT:u16 =31850;
pub const MAX_NUM_ERPC_PROCESSES:u16=32;
pub const MAX_NUMA_NODES:u32=8;
pub const HUGE_PAGE_SIZE:usize=2*1024*1024;//2MB
pub const MAX_MSG_SIZE:usize=MAX_CLASS_SIZE-((MAX_CLASS_SIZE/TTR_MAX_DATA_PER_PKT)*std::mem::size_of::<RpcHeader>());

/// HugeAlloc
pub const MAX_CLASS_SIZE:usize=8*1024*1024;


/// TTr
pub const TTR_MAX_DATA_PER_PKT:usize= 1300;
pub const TTR_NUM_RX_RING_ENTRIES:usize=4096;
pub const TTR_UNSIG_BATCH:usize=32;

/// microseconds
pub const RPC_REQUEST_TIMEOUT:u64=5000;
pub const INVALID_RPC_ID:u8=MAX_RPC_ID as u8 +1;

pub const MAX_PHY_PORT:u8=16;

// Congestion control
pub const ENABLE_CC:bool=true;
pub const K_CC_PACING:bool=ENABLE_CC;

/*  RPC Session  */
///Packet credits. This must be a power of two for fast matching of packet
///numbers to their position in the TX timestamp array.
pub const SESSION_CREDITS:usize=32;
pub const SESSION_REQ_WINDOW:usize=8;
pub const SESSION_PKT_SIZE:usize=128;
pub const SM_RX_BUFFER_SIZE:usize = SESSION_REQ_WINDOW*SESSION_PKT_SIZE;
pub const SM_TX_BUFFER_SIZE:usize =SESSION_PKT_SIZE*SESSION_REQ_WINDOW;