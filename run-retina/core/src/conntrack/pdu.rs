use crate::memory::mbuf::Mbuf;
use crate::protocols::packet::ethernet::Ethernet;
use crate::protocols::packet::ipv4::Ipv4;
// use crate::protocols::packet::ipv6::Ipv6;
use crate::protocols::packet::tcp::{Tcp, TCP_PROTOCOL};
use crate::protocols::packet::udp::{Udp, UDP_PROTOCOL};
#[cfg(all(feature = "retina", not(feature = "run")))]
use crate::protocols::packet::Packet;
#[cfg(all(feature = "run", not(feature = "retina")))]
use crate::protocols::packet::ipv4::IpProtocol;
#[cfg(all(feature = "run", not(feature = "retina")))]
use crate::protocols::packet::Cursor;
#[cfg(all(feature = "run", not(feature = "retina")))]
use crate::protocols::packet::udp::UDP_HEADER_LEN;

use anyhow::{bail, Result};

use std::net::{IpAddr, SocketAddr};

/// Transport-layer protocol data unit for stream reassembly and application-layer protocol parsing.
#[derive(Debug)]
pub struct L4Pdu {
  /// Internal packet buffer containing frame data.
  pub(crate) mbuf: Mbuf,
  /// Transport layer context.
  pub(crate) ctxt: L4Context,
  /// `true` if segment is in the direction of orig -> resp.
  pub(crate) dir: bool,
}

impl L4Pdu {
  pub(crate) fn new(mbuf: Mbuf, ctxt: L4Context, dir: bool) -> Self {
    L4Pdu { mbuf, ctxt, dir }
  }

  #[inline]
  pub(crate) fn mbuf_own(self) -> Mbuf {
    self.mbuf
  }

  #[inline]
  pub(crate) fn mbuf_ref(&self) -> &Mbuf {
    &self.mbuf
  }

  #[inline]
  pub(crate) fn offset(&self) -> usize {
    self.ctxt.offset
  }

  #[inline]
  pub(crate) fn length(&self) -> usize {
    self.ctxt.length
  }

  #[inline]
  pub(crate) fn seq_no(&self) -> u32 {
    self.ctxt.seq_no
  }

  #[inline]
  pub(crate) fn flags(&self) -> u8 {
    self.ctxt.flags
  }
}

/// Parsed transport-layer context from the packet used for connection tracking.
#[derive(Debug, Clone, Copy)]
pub struct L4Context {
  /// Source socket address.
  pub(crate) src: SocketAddr,
  /// Destination socket address.
  pub(crate) dst: SocketAddr,
  /// L4 protocol.
  pub(crate) proto: usize,
  /// Index of the predicate that was last matched in the packet filter.
  pub(crate) idx: usize,
  /// Offset into the mbuf where payload begins.
  pub(crate) offset: usize,
  /// Length of the payload in bytes.
  pub(crate) length: usize,
  /// Raw sequence number of segment.
  pub(crate) seq_no: u32,
  /// TCP flags.
  pub(crate) flags: u8,
}

impl L4Context {
  #[cfg(all(feature = "retina", not(feature = "run")))]
  pub(crate) fn new(mbuf: &Mbuf, idx: usize) -> Result<Self> {
    println!("retina");
    if let Ok(eth) = mbuf.parse_to::<Ethernet>() {
      if let Ok(ipv4) = eth.parse_to::<Ipv4>() {
        if let Ok(tcp) = ipv4.parse_to::<Tcp>() {
          if let Some(payload_size) = (ipv4.total_length() as usize)
            .checked_sub(ipv4.header_len() + tcp.header_len())
          {
            Ok(L4Context {
              src: SocketAddr::new(IpAddr::V4(ipv4.src_addr()), tcp.src_port()),
              dst: SocketAddr::new(IpAddr::V4(ipv4.dst_addr()), tcp.dst_port()),
              proto: TCP_PROTOCOL,
              idx,
              offset: tcp.next_header_offset(),
              length: payload_size,
              seq_no: tcp.seq_no(),
              flags: tcp.flags(),
            })
          } else {
            bail!("Malformed Packet");
          }
        } else if let Ok(udp) = ipv4.parse_to::<Udp>() {
          if let Some(payload_size) = (ipv4.total_length() as usize)
            .checked_sub(ipv4.header_len() + udp.header_len())
          {
            Ok(L4Context {
              src: SocketAddr::new(IpAddr::V4(ipv4.src_addr()), udp.src_port()),
              dst: SocketAddr::new(IpAddr::V4(ipv4.dst_addr()), udp.dst_port()),
              proto: UDP_PROTOCOL,
              idx,
              offset: udp.next_header_offset(),
              length: payload_size,
              seq_no: 0,
              flags: 0,
            })
          } else {
            bail!("Malformed Packet");
          }
        } else {
          bail!("Not TCP or UDP");
        }
      } else {
        bail!("Not IP");
      }
    } else {
      bail!("Not Ethernet");
    }
  }

  #[cfg(all(feature = "run", not(feature = "retina")))]
  pub(crate) fn new(mbuf: &Mbuf, idx: usize) -> Result<Self> {
    println!("run");
    let cursor = Cursor::new(mbuf.data());
        if let Ok(eth) = Ethernet::parse(cursor) {
            if let Ok(ipv4) = Ipv4::parse(eth.cursor_payload()) {
                let ipv4_header = ipv4.cursor_header();
                match ipv4.protocol() {
                    IpProtocol::TCP => {
                        if let Ok(tcp) = Tcp::parse(ipv4.cursor_payload()) {
                            Ok(L4Context {
                                src: SocketAddr::new(IpAddr::V4(ipv4_header.source_ip().into()), tcp.src_port()),
                                dst: SocketAddr::new(IpAddr::V4(ipv4_header.dest_ip().into()), tcp.dst_port()),
                                proto: TCP_PROTOCOL,
                                idx,
                                length: ipv4_header.packet_len() as usize - ipv4_header.header_len() as usize,
                                offset: tcp.buf().cursor() + tcp.header_len() as usize,
                                seq_no: tcp.seq_number(),
                                flags: tcp.flags() as u8,
                            })
                        } else {
                            bail!("Malformed Packet");
                        }
                    },
                    IpProtocol::UDP => {
                        if let Ok(udp) = Udp::parse(ipv4.cursor_payload()) {
                            Ok(L4Context {
                                src: SocketAddr::new(IpAddr::V4(ipv4.source_ip().into()), udp.source_port()),
                                dst: SocketAddr::new(IpAddr::V4(ipv4.dest_ip().into()), udp.dest_port()),
                                proto: UDP_PROTOCOL,
                                idx,
                                length: ipv4_header.packet_len() as usize - ipv4_header.header_len() as usize,
                                offset: udp.buf().cursor() + UDP_HEADER_LEN,
                                seq_no: 0,
                                flags: 0,
                            })
                        } else {
                            bail!("Malformed Packet");
                        }
                    },
                    _ => {
                        bail!("Not Udp or Tcp");
                    }
                } // end match
            } else {
                bail!("Not Ipv4");
            }
        } else {
            bail!("Not Ethernet");
        }
  }
}
