use bytes::Buf;

use crate::checksum_utils;
use crate::ipv4::{Ipv4Addr, Ipv4PseudoHeader};
use crate::{Cursor, CursorMut};
use crate::{PktBuf, PktMut};

use super::{TcpHeader, TCP_HEADER_LEN};

packet_base! {
    pub struct TcpPacket: TcpHeader {
        header_len: TCP_HEADER_LEN,
        get_methods: [
            (header_len, u8),
            (src_port, u16),
            (dst_port, u16),
            (seq_number, u32),
            (ack_number, u32),
            (fin, bool),
            (syn, bool),
            (rst, bool),
            (psh, bool),
            (ack, bool),
            (urg, bool),
            (ece, bool),
            (cwr, bool),
            (flags,u16),
            (ns, bool),
            (check_reserved, bool),
            (window_size, u16),
            (checksum, u16),
            (urgent_ptr, u16),
        ],
        set_methods: [
            (set_src_port, value: u16),
            (set_dst_port, value: u16),
            (set_seq_number, value: u32),
            (set_ack_number, value: u32),
            (clear_flags),
            (set_fin, value: bool),
            (set_syn, value: bool),
            (set_rst, value: bool),
            (set_psh, value: bool),
            (set_ack, value: bool),
            (set_urg, value: bool),
            (set_ece, value: bool),
            (set_cwr, value: bool),
            (set_ns, value: bool),
            (set_flags,value: u16),
            (adjust_reserved),
            (set_window_size, value: u16),
            (set_checksum, value: u16),
            (set_urgent_ptr, value: u16),
        ],
        unchecked_set_methods:[
            (set_header_len_unchecked, set_header_len, value: u8),
        ]
    }
}

impl<T: Buf> TcpPacket<T> {
  pub fn parse(buf: T) -> Result<TcpPacket<T>, T> {
    let chunk_len = buf.chunk().len();
    if chunk_len < TCP_HEADER_LEN {
      return Err(buf);
    }

    let packet = TcpPacket::parse_unchecked(buf);
    let header_len = usize::from(packet.header_len());

    if header_len < TCP_HEADER_LEN || header_len > chunk_len {
      return Err(packet.release());
    }

    Ok(packet)
  }

  #[inline]
  pub fn option_bytes(&self) -> &[u8] {
    &self.buf.chunk()[TCP_HEADER_LEN..self.header_len().into()]
  }
}

impl<T: PktBuf> TcpPacket<T> {
  pub fn calc_checksum(&mut self) -> u16 {
    let total_len = self.buf().remaining();

    let result = checksum_utils::from_buf(&mut self.buf, total_len);
    self.buf.move_back(total_len);
    result
  }

  #[inline]
  pub fn verify_ipv4_checksum(
    &mut self,
    src_addr: Ipv4Addr,
    dst_addr: Ipv4Addr,
  ) -> bool {
    let phdr = Ipv4PseudoHeader::from_tcp_pkt(src_addr, dst_addr, self);

    let cksum =
      checksum_utils::combine(&[phdr.calc_checksum(), self.calc_checksum()]);

    cksum == !0
  }

  #[inline]
  pub fn payload(self) -> T {
    let header_len = usize::from(self.header_len());

    let mut buf = self.release();
    buf.advance(header_len);

    buf
  }
}

impl<T: PktMut> TcpPacket<T> {
  #[inline]
  pub fn set_option_bytes(&mut self, option_bytes: &[u8]) {
    let header_len = self.header_len();
    let data = &mut self.buf.chunk_mut()[TCP_HEADER_LEN..header_len as usize];
    data.copy_from_slice(option_bytes);
  }

  #[inline]
  pub fn option_bytes_mut(&mut self) -> &mut [u8] {
    let header_len = self.header_len();
    return &mut self.buf.chunk_mut()[TCP_HEADER_LEN..header_len as usize];
  }

  #[inline]
  pub fn adjust_ipv4_checksum(
    &mut self,
    src_addr: Ipv4Addr,
    dst_addr: Ipv4Addr,
  ) {
    self.set_checksum(0);

    let phdr = Ipv4PseudoHeader::from_tcp_pkt(src_addr, dst_addr, self);

    let cksum =
      !checksum_utils::combine(&[phdr.calc_checksum(), self.calc_checksum()]);

    self.set_checksum(cksum)
  }

  #[inline]
  pub fn prepend_header<HT: AsRef<[u8]>>(
    mut buf: T,
    header: &TcpHeader<HT>,
  ) -> TcpPacket<T> {
    let header_len: usize = header.header_len().into();
    assert!(header_len >= TCP_HEADER_LEN && header_len <= buf.chunk_headroom());

    buf.move_back(header_len);

    let data = &mut buf.chunk_mut()[0..TCP_HEADER_LEN];
    data.copy_from_slice(header.as_bytes());

    TcpPacket::parse_unchecked(buf)
  }
}

impl<'a> TcpPacket<Cursor<'a>> {
    #[inline]
    pub fn cursor_header(&self) -> TcpHeader<&'a [u8]> {
        let data = &self.buf.chunk_shared_lifetime()[..TCP_HEADER_LEN];
        TcpHeader::new_unchecked(data)
    }

    #[inline]
    pub fn cursor_options(&self) -> &'a [u8] {
        &self.buf.chunk_shared_lifetime()[TCP_HEADER_LEN..usize::from(self.header_len())]
    }

    #[inline]
    pub fn cursor_payload(&self) -> Cursor<'a> {
        Cursor::new(&self.buf.chunk_shared_lifetime()[usize::from(self.header_len())..])
    }
}

impl<'a> TcpPacket<CursorMut<'a>> {
    #[inline]
    pub fn split(self) -> (TcpHeader<&'a mut [u8]>, &'a [u8], CursorMut<'a>) {
        let header_len = self.header_len();

        let (hdr, payload) = self
            .buf
            .chunk_mut_shared_lifetime()
            .split_at_mut(usize::from(header_len));
        let (hdr, options) = hdr.split_at_mut(TCP_HEADER_LEN);

        (
            TcpHeader::new_unchecked(hdr),
            options,
            CursorMut::new(payload),
        )
    }
}

#[cfg(test)]
mod test_tcppkt {
  use super::*;
  use crate::ether::*;
  use crate::ipv4::*;
  use crate::tcp::TCP_HEADER_TEMPLATE;
  use crate::{Cursor, CursorMut};

  static FRAME_BYTES: [u8; 200] = [
    0x00, 0x26, 0x62, 0x2f, 0x47, 0x87, 0x00, 0x1d, 0x60, 0xb3, 0x01, 0x84,
    0x08, 0x00, 0x45, 0x00, 0x00, 0xba, 0xcb, 0x5d, 0x40, 0x00, 0x40, 0x06,
    0x28, 0x64, 0xc0, 0xa8, 0x01, 0x8c, 0xae, 0x8f, 0xd5, 0xb8, 0xe1, 0x4e,
    0x00, 0x50, 0x8e, 0x50, 0x19, 0x02, 0xc7, 0x52, 0x9d, 0x89, 0x80, 0x18,
    0x00, 0x2e, 0x47, 0x29, 0x00, 0x00, 0x01, 0x01, 0x08, 0x0a, 0x00, 0x21,
    0xd2, 0x5f, 0x31, 0xc7, 0xba, 0x48, 0x47, 0x45, 0x54, 0x20, 0x2f, 0x69,
    0x6d, 0x61, 0x67, 0x65, 0x73, 0x2f, 0x6c, 0x61, 0x79, 0x6f, 0x75, 0x74,
    0x2f, 0x6c, 0x6f, 0x67, 0x6f, 0x2e, 0x70, 0x6e, 0x67, 0x20, 0x48, 0x54,
    0x54, 0x50, 0x2f, 0x31, 0x2e, 0x30, 0x0d, 0x0a, 0x55, 0x73, 0x65, 0x72,
    0x2d, 0x41, 0x67, 0x65, 0x6e, 0x74, 0x3a, 0x20, 0x57, 0x67, 0x65, 0x74,
    0x2f, 0x31, 0x2e, 0x31, 0x32, 0x20, 0x28, 0x6c, 0x69, 0x6e, 0x75, 0x78,
    0x2d, 0x67, 0x6e, 0x75, 0x29, 0x0d, 0x0a, 0x41, 0x63, 0x63, 0x65, 0x70,
    0x74, 0x3a, 0x20, 0x2a, 0x2f, 0x2a, 0x0d, 0x0a, 0x48, 0x6f, 0x73, 0x74,
    0x3a, 0x20, 0x70, 0x61, 0x63, 0x6b, 0x65, 0x74, 0x6c, 0x69, 0x66, 0x65,
    0x2e, 0x6e, 0x65, 0x74, 0x0d, 0x0a, 0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63,
    0x74, 0x69, 0x6f, 0x6e, 0x3a, 0x20, 0x4b, 0x65, 0x65, 0x70, 0x2d, 0x41,
    0x6c, 0x69, 0x76, 0x65, 0x0d, 0x0a, 0x0d, 0x0a,
  ];

  #[test]
  fn test_parse() {
    let buf = Cursor::new(&FRAME_BYTES[..]);

    let ethpkt = EtherPacket::parse(buf).unwrap();
    assert_eq!(ethpkt.ethertype(), EtherType::IPV4);

    let ippkt = Ipv4Packet::parse(ethpkt.payload()).unwrap();
    assert_eq!(ippkt.protocol(), IpProtocol::TCP);

    let tcppkt = TcpPacket::parse(ippkt.payload()).unwrap();
    assert_eq!(tcppkt.src_port(), 57678);
    assert_eq!(tcppkt.dst_port(), 80);
    assert_eq!(tcppkt.buf().remaining() - tcppkt.header_len() as usize, 134);
    assert_eq!(tcppkt.seq_number(), 0x8e501902);
    assert_eq!(tcppkt.ack_number(), 0xc7529d89);
    assert_eq!(tcppkt.header_len(), 32);
    assert_eq!(tcppkt.check_reserved(), true);
    assert_eq!(tcppkt.ns(), false);
    assert_eq!(tcppkt.cwr(), false);
    assert_eq!(tcppkt.ece(), false);
    assert_eq!(tcppkt.urg(), false);
    assert_eq!(tcppkt.ack(), true);
    assert_eq!(tcppkt.psh(), true);
    assert_eq!(tcppkt.rst(), false);
    assert_eq!(tcppkt.syn(), false);
    assert_eq!(tcppkt.fin(), false);
    assert_eq!(tcppkt.window_size(), 46);
    assert_eq!(tcppkt.checksum(), 0x4729);
    assert_eq!(tcppkt.urgent_ptr(), 0);

    assert_eq!(tcppkt.option_bytes().len(), 12);
    assert_eq!(
      tcppkt.option_bytes(),
      &FRAME_BYTES[ETHER_HEADER_LEN + IPV4_HEADER_LEN + TCP_HEADER_LEN
        ..(ETHER_HEADER_LEN + IPV4_HEADER_LEN + TCP_HEADER_LEN + 12)]
    );

    assert_eq!(
      tcppkt.payload().chunk(),
      &FRAME_BYTES
        [(ETHER_HEADER_LEN + IPV4_HEADER_LEN + TCP_HEADER_LEN + 12)..]
    )
  }

  #[test]
  fn test_build() {
    let mut bytes = [0xff; 200];
    (&mut bytes[ETHER_HEADER_LEN + IPV4_HEADER_LEN + TCP_HEADER_LEN + 12..])
      .copy_from_slice(
        &FRAME_BYTES
          [ETHER_HEADER_LEN + IPV4_HEADER_LEN + TCP_HEADER_LEN + 12..],
      );

    let mut buf = CursorMut::new(&mut bytes[..]);
    buf.advance(ETHER_HEADER_LEN + IPV4_HEADER_LEN + TCP_HEADER_LEN + 12);

    let mut tcpheader = TCP_HEADER_TEMPLATE;
    tcpheader.set_header_len(32);
    let mut tcppkt = TcpPacket::prepend_header(buf, &tcpheader);
    tcppkt.set_src_port(57678);
    tcppkt.set_dst_port(80);
    tcppkt.set_seq_number(0x8e501902);
    tcppkt.set_ack_number(0xc7529d89);
    tcppkt.adjust_reserved();
    tcppkt.set_ns(false);
    tcppkt.set_cwr(false);
    tcppkt.set_ece(false);
    tcppkt.set_urg(false);
    tcppkt.set_ack(true);
    tcppkt.set_psh(true);
    tcppkt.set_rst(false);
    tcppkt.set_syn(false);
    tcppkt.set_fin(false);
    tcppkt.set_window_size(46);
    tcppkt.set_checksum(0x4729);
    tcppkt.set_urgent_ptr(0);
    tcppkt.set_option_bytes(
      &FRAME_BYTES[ETHER_HEADER_LEN + IPV4_HEADER_LEN + TCP_HEADER_LEN
        ..(ETHER_HEADER_LEN + IPV4_HEADER_LEN + TCP_HEADER_LEN + 12)],
    );

    let mut ipheader = IPV4_HEADER_TEMPLATE;
    ipheader.set_header_len(20);
    ipheader.adjust_version();
    ipheader.set_dscp(0);
    ipheader.set_ecn(0);
    ipheader.set_ident(0xcb5d);
    ipheader.clear_flags();
    ipheader.set_dont_frag(true);
    ipheader.set_more_frags(false);
    ipheader.set_frag_offset(0);
    ipheader.set_time_to_live(64);
    ipheader.set_protocol(IpProtocol::TCP);
    ipheader.set_checksum(0x2864);
    ipheader.set_source_ip(Ipv4Addr([192, 168, 1, 140]));
    ipheader.set_dest_ip(Ipv4Addr([174, 143, 213, 184]));
    let ippkt = Ipv4Packet::prepend_header(tcppkt.release(), &ipheader);

    let mut ethheader = ETHER_HEADER_TEMPLATE;
    ethheader.set_dest_mac(MacAddr([0x00, 0x26, 0x62, 0x2f, 0x47, 0x87]));
    ethheader.set_source_mac(MacAddr([0x00, 0x1d, 0x60, 0xb3, 0x01, 0x84]));
    ethheader.set_ethertype(EtherType::IPV4);
    let pkt = EtherPacket::prepend_header(ippkt.release(), &ethheader);

    assert_eq!(pkt.release().chunk(), &FRAME_BYTES[..]);
  }

  #[test]
  fn smol_data_parse() {
    static PACKET_BYTES: [u8; 28] = [
      0xbf, 0x00, 0x00, 0x50, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
      0x60, 0x35, 0x01, 0x23, 0x01, 0xb6, 0x02, 0x01, 0x03, 0x03, 0x0c, 0x01,
      0xaa, 0x00, 0x00, 0xff,
    ];
    static OPTION_BYTES: [u8; 4] = [0x03, 0x03, 0x0c, 0x01];
    static PAYLOAD_BYTES: [u8; 4] = [0xaa, 0x00, 0x00, 0xff];
    const SRC_ADDR: Ipv4Addr = Ipv4Addr([192, 168, 1, 1]);
    const DST_ADDR: Ipv4Addr = Ipv4Addr([192, 168, 1, 2]);

    let mut bytes = [0xa5; 28];
    (&mut bytes[TCP_HEADER_LEN + 4..]).copy_from_slice(&PAYLOAD_BYTES[..]);

    let buf = Cursor::new(&PACKET_BYTES[..]);

    let mut packet = TcpPacket::parse(buf).unwrap();
    assert_eq!(packet.src_port(), 48896);
    assert_eq!(packet.dst_port(), 80);
    assert_eq!(packet.seq_number(), 0x01234567);
    assert_eq!(packet.ack_number(), 0x89abcdefu32);
    assert_eq!(packet.header_len(), 24);
    assert!(packet.fin());
    assert!(!packet.syn());
    assert!(packet.rst());
    assert!(!packet.psh());
    assert!(packet.ack());
    assert!(packet.urg());
    assert_eq!(packet.window_size(), 0x0123);
    assert_eq!(packet.urgent_ptr(), 0x0201);
    assert_eq!(packet.checksum(), 0x01b6);
    assert_eq!(packet.option_bytes(), &OPTION_BYTES[..]);
    assert_eq!(
      &packet.buf().chunk()[packet.header_len().into()..],
      &PAYLOAD_BYTES[..]
    );
    assert!(packet.verify_ipv4_checksum(SRC_ADDR, DST_ADDR));
  }

  #[test]
  fn smol_data_build() {
    static PACKET_BYTES: [u8; 28] = [
      0xbf, 0x00, 0x00, 0x50, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
      0x60, 0x35, 0x01, 0x23, 0x01, 0xb6, 0x02, 0x01, 0x03, 0x03, 0x0c, 0x01,
      0xaa, 0x00, 0x00, 0xff,
    ];
    static OPTION_BYTES: [u8; 4] = [0x03, 0x03, 0x0c, 0x01];
    static PAYLOAD_BYTES: [u8; 4] = [0xaa, 0x00, 0x00, 0xff];
    const SRC_ADDR: Ipv4Addr = Ipv4Addr([192, 168, 1, 1]);
    const DST_ADDR: Ipv4Addr = Ipv4Addr([192, 168, 1, 2]);

    let mut bytes = [0xa5; 28];
    (&mut bytes[TCP_HEADER_LEN + 4..]).copy_from_slice(&PAYLOAD_BYTES[..]);

    let mut buf = CursorMut::new(&mut bytes[..]);
    buf.advance(TCP_HEADER_LEN + 4);

    let mut tcpheader = TCP_HEADER_TEMPLATE;
    tcpheader.set_header_len(24);
    let mut packet = TcpPacket::prepend_header(buf, &tcpheader);
    packet.set_src_port(48896);
    packet.set_dst_port(80);
    packet.set_seq_number(0x01234567);
    packet.set_ack_number(0x89abcdefu32);
    packet.clear_flags();
    packet.set_fin(true);
    packet.set_syn(false);
    packet.set_rst(true);
    packet.set_psh(false);
    packet.set_ack(true);
    packet.set_urg(true);
    packet.set_window_size(0x0123);
    packet.set_urgent_ptr(0x0201);
    packet.set_checksum(0xEEEE);
    packet.set_option_bytes(&OPTION_BYTES[..]);
    packet.adjust_ipv4_checksum(SRC_ADDR, DST_ADDR);
    assert_eq!(packet.buf().chunk(), &PACKET_BYTES[..]);
    assert_eq!(&bytes[..], &PACKET_BYTES[..]);
  }
}
