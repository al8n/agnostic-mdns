use std::{
  collections::HashSet,
  net::{Ipv4Addr, Ipv6Addr},
};

use smallvec_wrapper::{SmallVec, XXLargeVec};
use smol_str::SmolStr;
use triomphe::Arc;

use crate::types::SRV;

use super::{
  ddd_to_byte, escape_bytes, is_ddd, CompressionMap, DNSClass, Name, ProtoError, RecordData,
  RecordType, SlicableSmolStr,
};

const IPV4_LEN: usize = 4;
const IPV6_LEN: usize = 16;
const U16_SIZE: usize = 2;
const U32_SIZE: usize = 4;
const RECORD_HEADER_ENCODED_WITHOUT_NAME_SIZE: usize = 10; // ty(2) + class(2) + ttl(4) + rdlen(2)

/// The header all mDNS resource records share.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RecordHeader {
  name: Name,
  ty: RecordType,
  class: DNSClass,
  ttl: u32,
}

impl RecordHeader {
  /// Returns the name of the record.
  #[inline]
  pub const fn name(&self) -> &Name {
    &self.name
  }

  /// Returns the type of the record.
  #[inline]
  pub const fn ty(&self) -> RecordType {
    self.ty
  }

  /// Returns the class of the record.
  #[inline]
  pub const fn class(&self) -> DNSClass {
    self.class
  }

  /// Returns the time-to-live of the record.
  #[inline]
  pub const fn ttl(&self) -> u32 {
    self.ttl
  }
}

/// The mDNS resource record.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Record {
  header: RecordHeader,
  data: RecordData,
}

impl Record {
  /// Creates a new mDNS resource record.
  pub fn from_rdata(name: Name, ttl: u32, data: RecordData) -> Self {
    Self {
      header: RecordHeader {
        name,
        ty: data.ty(),
        class: DNSClass::IN,
        ttl,
      },
      data,
    }
  }

  /// Consumes the record and returns the [`RecordHeader`] and [`RecordData`].
  #[inline]
  pub fn into_components(self) -> (RecordHeader, RecordData) {
    (self.header, self.data)
  }

  /// Returns a reference to the record's header.
  #[inline]
  pub const fn header(&self) -> &RecordHeader {
    &self.header
  }

  /// Returns a reference to the record's data.
  #[inline]
  pub const fn data(&self) -> &RecordData {
    &self.data
  }

  pub(super) fn decode(
    src: &[u8],
    off: usize,
    consume: bool,
  ) -> Result<(Option<Self>, usize), ProtoError> {
    let (name, mut off) = Name::decode(src, off)?;
    let len = src.len();
    if len < off + RECORD_HEADER_ENCODED_WITHOUT_NAME_SIZE {
      return Err(ProtoError::BufferTooSmall);
    }

    let ty = RecordType::from(u16::from_be_bytes([src[off], src[off + 1]]));
    off += U16_SIZE;
    let class = DNSClass::from(u16::from_be_bytes([src[off], src[off + 1]]));
    off += U16_SIZE;
    let ttl = u32::from_be_bytes(src[off..off + U32_SIZE].try_into().unwrap());
    off += U32_SIZE;
    let rdlen = u16::from_be_bytes([src[off], src[off + 1]]) as usize;
    off += U16_SIZE;
    if rdlen > len {
      return Err(ProtoError::Overflow);
    }

    if consume {
      return Ok((None, off + rdlen));
    }
    let src = &src[..off + rdlen];
    let len = src.len();
    let data = match ty {
      RecordType::A => {
        if off + IPV4_LEN > len {
          return Err(ProtoError::NotEnoughData);
        }

        let octets: [u8; IPV4_LEN] = src[off..off + IPV4_LEN].try_into().unwrap();
        off += IPV4_LEN;
        RecordData::A(Ipv4Addr::from(octets))
      }
      RecordType::AAAA => {
        if off + IPV6_LEN > len {
          return Err(ProtoError::NotEnoughData);
        }

        let octets: [u8; IPV6_LEN] = src[off..off + IPV6_LEN].try_into().unwrap();
        off += IPV6_LEN;
        RecordData::AAAA(Ipv6Addr::from(octets))
      }
      RecordType::PTR => {
        let (name, off1) = Name::decode(src, off)?;
        off = off1;
        RecordData::PTR(name)
      }
      RecordType::SRV => {
        if off + 6 > len {
          return Err(ProtoError::NotEnoughData);
        }

        let priority = u16::from_be_bytes([src[off], src[off + 1]]);
        off += U16_SIZE;
        let weight = u16::from_be_bytes([src[off], src[off + 1]]);
        off += U16_SIZE;
        let port = u16::from_be_bytes([src[off], src[off + 1]]);
        off += U16_SIZE;

        let (name, off1) = Name::decode(src, off)?;
        off = off1;
        RecordData::SRV(SRV::new(priority, weight, port, name))
      }
      RecordType::TXT => {
        let (txt, off1) = decode_txt(src, off)?;
        off = off1;
        RecordData::TXT(Arc::from_iter(txt))
      }
      _ => return Ok((None, off + rdlen)),
    };

    let mut r = Self::from_rdata(name, ttl, data);
    r.header.class = class;
    Ok((Some(r), off))
  }

  pub(super) fn encode(
    &self,
    buf: &mut [u8],
    off: usize,
    cmap: &mut Option<CompressionMap>,
    compress: bool,
  ) -> Result<usize, ProtoError> {
    if off == buf.len() {
      return Ok(off);
    }

    let mut off = self.header.name.encode(buf, off, cmap, compress)?;
    if buf.len() < off + RECORD_HEADER_ENCODED_WITHOUT_NAME_SIZE {
      return Err(ProtoError::BufferTooSmall);
    }

    buf[off..off + U16_SIZE].copy_from_slice(&(u16::from(self.header.ty)).to_be_bytes());
    off += U16_SIZE;
    buf[off..off + U16_SIZE].copy_from_slice(&(u16::from(self.header.class)).to_be_bytes());
    off += U16_SIZE;
    buf[off..off + U32_SIZE].copy_from_slice(&self.header.ttl.to_be_bytes());
    off += U32_SIZE;
    buf[off..off + U16_SIZE].copy_from_slice(&0u16.to_be_bytes()); // update later
    off += U16_SIZE;

    let heoff = off;

    let off1 = match &self.data {
      RecordData::A(ipv4_addr) => {
        if buf.len() < off + IPV4_LEN {
          return Err(ProtoError::BufferTooSmall);
        }

        buf[off..off + IPV4_LEN].copy_from_slice(&ipv4_addr.octets());
        off + IPV4_LEN
      }
      RecordData::AAAA(ipv6_addr) => {
        if buf.len() < off + IPV6_LEN {
          return Err(ProtoError::BufferTooSmall);
        }

        buf[off..off + IPV6_LEN].copy_from_slice(&ipv6_addr.octets());
        off + IPV6_LEN
      }
      RecordData::PTR(name) => name.encode(buf, off, cmap, compress)?,
      RecordData::SRV(srv) => {
        if buf.len() < off + 6 {
          return Err(ProtoError::BufferTooSmall);
        }

        buf[off..off + U16_SIZE].copy_from_slice(&srv.priority().to_be_bytes());
        off += U16_SIZE;
        buf[off..off + U16_SIZE].copy_from_slice(&srv.weight().to_be_bytes());
        off += U16_SIZE;
        buf[off..off + U16_SIZE].copy_from_slice(&srv.port().to_be_bytes());
        off += U16_SIZE;

        srv.target().encode(buf, off, cmap, false)?
      }
      RecordData::TXT(txt) => encode_txt(txt, buf, off)?,
    };

    let rdlen = off1 - heoff;
    if rdlen > u16::MAX as usize {
      return Err(ProtoError::InvalidRdata);
    }

    buf[heoff - 2..heoff].copy_from_slice(&(rdlen as u16).to_be_bytes());

    Ok(off1)
  }

  pub(super) fn encoded_len(&self, cmap: &mut Option<HashSet<SlicableSmolStr>>) -> usize {
    let mut off =
      self.header.name.encoded_len(0, cmap, true) + RECORD_HEADER_ENCODED_WITHOUT_NAME_SIZE;
    match &self.data {
      RecordData::A(_) => off + IPV4_LEN,
      RecordData::AAAA(_) => off + IPV6_LEN,
      RecordData::PTR(name) => name.encoded_len(off, cmap, true),
      RecordData::SRV(srv) => {
        let l = off + 6;
        srv.target().encoded_len(l, cmap, false)
      }
      RecordData::TXT(txt) => {
        for s in txt.iter() {
          off += s.len() + 1;
        }
        off
      }
    }
  }
}

fn encode_txt(txt: &[SmolStr], buf: &mut [u8], mut off: usize) -> Result<usize, ProtoError> {
  if txt.is_empty() {
    if off >= buf.len() {
      return Err(ProtoError::BufferTooSmall);
    }

    buf[off] = 0;
    return Ok(off);
  }

  for s in txt {
    off = encode_txt_string(s, buf, off)?;
  }

  Ok(off)
}

fn encode_txt_string(s: &str, buf: &mut [u8], mut off: usize) -> Result<usize, ProtoError> {
  let len_byte_offset = off;
  if off >= buf.len() || s.len() > 256 * 4 + 1
  /* If all \DDD */
  {
    return Err(ProtoError::BufferTooSmall);
  }

  off += 1;
  let s = s.as_bytes();

  let mut i = 0;

  while i < s.len() {
    if off >= buf.len() {
      return Err(ProtoError::BufferTooSmall);
    }

    let c = s[i];
    if c == b'\\' {
      i += 1;
      if i == s.len() {
        break;
      }

      // check for \DDD
      if is_ddd(&s[i..]) {
        buf[off] = ddd_to_byte(&s[i..]);
        i += 2;
      } else {
        buf[off] = s[i];
      }
    } else {
      buf[off] = c;
    }

    off += 1;
    i += 1;
  }

  let l = off - len_byte_offset - 1;
  if l > 255 {
    return Err(ProtoError::TxtDataTooLong);
  }

  buf[len_byte_offset] = l as u8;
  Ok(off)
}

fn decode_txt(msg: &[u8], mut off: usize) -> Result<(SmallVec<SmolStr>, usize), ProtoError> {
  let mut txt = SmallVec::new();
  while off < msg.len() {
    let (s, off1) = decode_txt_string(msg, off)?;
    txt.push(s);
    off = off1;
  }

  Ok((txt, off))
}

fn decode_txt_string(msg: &[u8], mut off: usize) -> Result<(SmolStr, usize), ProtoError> {
  if off + 1 > msg.len() {
    return Err(ProtoError::NotEnoughData);
  }

  let l = msg[off] as usize;
  off += 1;

  if off + l > msg.len() {
    return Err(ProtoError::NotEnoughData);
  }

  let mut buf = XXLargeVec::<u8>::new();
  let mut consumed = 0;
  for (i, &b) in msg[off..off + l].iter().enumerate() {
    match () {
      () if b == b'"' || b == b'\\' => {
        buf.extend_from_slice(&msg[off + consumed..off + i]);
        buf.push(b'\\');
        buf.push(b);
        consumed = i + 1;
      }
      () if !(b' '..=b'~').contains(&b) => {
        buf.extend_from_slice(&msg[off + consumed..off + i]);
        buf.extend_from_slice(escape_bytes(b, &mut [0; 4]));
        consumed = i + 1;
      }
      _ => {}
    }
  }

  if consumed == 0 {
    // no escaping needed
    return core::str::from_utf8(&msg[off..off + l])
      .map(|s| (SmolStr::new(s), off + l))
      .map_err(ProtoError::Utf8);
  }

  buf.extend_from_slice(&msg[off + consumed..off + l]);
  core::str::from_utf8(&buf)
    .map(|s| (SmolStr::new(s), off + l))
    .map_err(ProtoError::Utf8)
}
