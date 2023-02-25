use byteorder::{ByteOrder, NetworkEndian};

mod field {
  pub const OPT_END: u8 = 0x00;
  pub const OPT_NOP: u8 = 0x01;
  pub const OPT_MSS: u8 = 0x02;
  pub const OPT_WS: u8 = 0x03;
  pub const OPT_SACKPERM: u8 = 0x04;
  pub const OPT_SACKRNG: u8 = 0x05;
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum TcpOption<'a> {
  EndOfList,
  NoOperation,
  MaxSegmentSize(u16),
  WindowScale(u8),
  SackPermitted,
  SackRange([Option<(u32, u32)>; 3]),
  Unknown { kind: u8, data: &'a [u8] },
}

impl<'a> TcpOption<'a> {
  pub fn parse(buffer: &'a [u8]) -> Result<(&'a [u8], TcpOption<'a>), ()> {
    let (length, option);
    match *buffer.get(0).ok_or(())? {
      field::OPT_END => {
        length = 1;
        option = TcpOption::EndOfList;
      }
      field::OPT_NOP => {
        length = 1;
        option = TcpOption::NoOperation;
      }
      kind => {
        length = *buffer.get(1).ok_or(())? as usize;
        let data = buffer.get(2..length).ok_or(())?;
        match (kind, length) {
          (field::OPT_END, _) | (field::OPT_NOP, _) => unreachable!(),
          (field::OPT_MSS, 4) => {
            option = TcpOption::MaxSegmentSize(NetworkEndian::read_u16(data))
          }
          (field::OPT_MSS, _) => return Err(()),
          (field::OPT_WS, 3) => option = TcpOption::WindowScale(data[0]),
          (field::OPT_WS, _) => return Err(()),
          (field::OPT_SACKPERM, 2) => option = TcpOption::SackPermitted,
          (field::OPT_SACKPERM, _) => return Err(()),
          (field::OPT_SACKRNG, n) => {
            if n < 10 || (n - 2) % 8 != 0 {
              return Err(());
            }
            if n > 26 {}
            let mut sack_ranges: [Option<(u32, u32)>; 3] = [None; 3];
            sack_ranges.iter_mut().enumerate().for_each(|(i, nmut)| {
              let left = i * 8;
              *nmut = if left < data.len() {
                let mid = left + 4;
                let right = mid + 4;
                let range_left = NetworkEndian::read_u32(&data[left..mid]);
                let range_right = NetworkEndian::read_u32(&data[mid..right]);
                Some((range_left, range_right))
              } else {
                None
              };
            });
            option = TcpOption::SackRange(sack_ranges);
          }
          (_, _) => option = TcpOption::Unknown { kind, data },
        }
      }
    }
    Ok((&buffer[length..], option))
  }

  pub fn buffer_len(&self) -> usize {
    match *self {
      TcpOption::EndOfList => 1,
      TcpOption::NoOperation => 1,
      TcpOption::MaxSegmentSize(_) => 4,
      TcpOption::WindowScale(_) => 3,
      TcpOption::SackPermitted => 2,
      TcpOption::SackRange(s) => {
        s.iter().filter(|s| s.is_some()).count() * 8 + 2
      }
      TcpOption::Unknown { data, .. } => 2 + data.len(),
    }
  }

  pub fn build<'b>(&self, buffer: &'b mut [u8]) -> &'b mut [u8] {
    let length;
    match *self {
      TcpOption::EndOfList => {
        length = 1;
        for p in buffer.iter_mut() {
          *p = field::OPT_END;
        }
      }
      TcpOption::NoOperation => {
        length = 1;
        buffer[0] = field::OPT_NOP;
      }
      _ => {
        length = self.buffer_len();
        buffer[1] = length as u8;
        match self {
          &TcpOption::EndOfList | &TcpOption::NoOperation => unreachable!(),
          &TcpOption::MaxSegmentSize(value) => {
            buffer[0] = field::OPT_MSS;
            NetworkEndian::write_u16(&mut buffer[2..], value)
          }
          &TcpOption::WindowScale(value) => {
            buffer[0] = field::OPT_WS;
            buffer[2] = value;
          }
          &TcpOption::SackPermitted => {
            buffer[0] = field::OPT_SACKPERM;
          }
          &TcpOption::SackRange(slice) => {
            buffer[0] = field::OPT_SACKRNG;
            slice.iter().filter(|s| s.is_some()).enumerate().for_each(
              |(i, s)| {
                let (first, second) = *s.as_ref().unwrap();
                let pos = i * 8 + 2;
                NetworkEndian::write_u32(&mut buffer[pos..], first);
                NetworkEndian::write_u32(&mut buffer[pos + 4..], second);
              },
            );
          }
          &TcpOption::Unknown {
            kind,
            data: provided,
          } => {
            buffer[0] = kind;
            buffer[2..].copy_from_slice(provided)
          }
        }
      }
    }
    &mut buffer[length..]
  }
}
