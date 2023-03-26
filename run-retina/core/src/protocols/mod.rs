//! Protocol parsing and manipulation.

#[cfg(all(feature = "retina", not(feature = "run")))]
pub mod packet;

#[cfg(all(feature = "run", not(feature = "retina")))]
pub mod packet {
  pub mod ethernet {
    pub use run_packet::ether::EtherPacket as Ethernet;
    pub use run_packet::ether::EtherType;
    pub use run_packet::ether::ETHER_HEADER_LEN;
  }
  
  pub mod ipv4 {
    pub use run_packet::ipv4::IpProtocol;
    pub use run_packet::ipv4::Ipv4Packet as Ipv4;
  }
  
  pub mod tcp {
    pub use run_packet::tcp::TcpPacket as Tcp;
    pub(crate) const CWR: u8 = 0b1000_0000;
    pub(crate) const ECE: u8 = 0b0100_0000;
    pub(crate) const URG: u8 = 0b0010_0000;
    pub(crate) const ACK: u8 = 0b0001_0000;
    pub(crate) const PSH: u8 = 0b0000_1000;
    pub(crate) const RST: u8 = 0b0000_0100;
    pub(crate) const SYN: u8 = 0b0000_0010;
    pub(crate) const FIN: u8 = 0b0000_0001;
    pub const TCP_PROTOCOL: usize = 6;
  }
  
  pub mod udp {
    pub use run_packet::udp::UdpPacket as Udp;
    pub const UDP_PROTOCOL: usize = 17;
    pub use run_packet::udp::UDP_HEADER_LEN;
  }
  
  pub use run_packet::Cursor;
  pub use run_packet::PktBuf;
}

pub mod stream;
