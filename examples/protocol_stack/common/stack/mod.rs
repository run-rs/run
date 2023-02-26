pub mod tcp;

#[derive(Debug, Default)]
pub struct RouterInfo {
  pub dest_mac: run_packet::ether::MacAddr,
  pub src_mac: run_packet::ether::MacAddr,
  pub dest_ipv4: run_packet::ipv4::Ipv4Addr,
  pub src_ipv4: run_packet::ipv4::Ipv4Addr,
  pub dest_port: u16,
  pub src_port: u16,
}
