use arrayvec::ArrayVec;
use run_dpdk::Mbuf;
use run_packet::{ether::MacAddr, ipv4::Ipv4Addr};

use super::msgbuffer::MsgBuffer;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutingInfo {
  pub local_addr: Ipv4Addr,
  pub remote_addr: Ipv4Addr,
  pub local_port: u16,
  pub remote_port: u16,
  pub peer_mac: MacAddr,
  pub local_mac: MacAddr,
}

impl Default for RoutingInfo {
  fn default() -> Self {
    Self {
      peer_mac: MacAddr::default(),
      local_mac: MacAddr::default(),
      local_addr: Ipv4Addr::default(),
      remote_addr: Ipv4Addr::default(),
      local_port: 0,
      remote_port: 0,
    }
  }
}

impl RoutingInfo {}

pub trait Transport {
  /// With Retry until all packets has been sent
  fn tx_burst(&mut self, tx_burst: &mut ArrayVec<TxBurstItem, 32>);

  fn rx_burst(&mut self, rx_batch: &mut ArrayVec<Mbuf, 32>);
}

pub struct TxBurstItem {
  pub msg_buffer: MsgBuffer,
  pub pkt_idx: usize,
  pub drop: bool,
}
