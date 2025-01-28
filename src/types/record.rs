use dns_protocol::{Label, ResourceRecord};

use super::{DNSClass, Name, RecordDataRef, RecordType, DNS_CLASS_IN};

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
pub struct RecordRef<'a> {
  name: Label<'a>,
  ttl: u32,
  data: RecordDataRef<'a>,
}

impl<'a> From<&RecordRef<'a>> for ResourceRecord<'a> {
  fn from(value: &RecordRef<'a>) -> Self {
    let data = match value.data {
      RecordDataRef::A(rd) => rd.data(),
      RecordDataRef::AAAA(rd) => rd.data(),
      RecordDataRef::PTR(rd) => rd.data(),
      RecordDataRef::SRV(rd) => rd.data(),
      RecordDataRef::TXT(rd) => rd.data(),
    };

    ResourceRecord::new(value.name, value.data.ty(), DNS_CLASS_IN, value.ttl, data)
  }
}

impl<'a> RecordRef<'a> {
  /// Creates a new mDNS resource record.
  pub fn from_rdata(name: Label<'a>, ttl: u32, data: RecordDataRef<'a>) -> Self {
    Self { name, ttl, data }
  }

  /// Returns a reference to the record's data.
  #[inline]
  pub const fn data(&self) -> &RecordDataRef<'a> {
    &self.data
  }

  /// Returns the time-to-live of the record.
  #[inline]
  pub const fn ttl(&self) -> u32 {
    self.ttl
  }

  /// Returns the label of the record.
  #[inline]
  pub const fn label(&self) -> &Label<'a> {
    &self.name
  }

  // #[inline]
  // pub(crate) fn write_data(&self, buf: &mut [u8]) -> usize {
  //   let mut off = 0;
  //   match &self.data {
  //     RecordDataRef::A(ipv4_addr) => {
  //       buf[off..off + IPV4_LEN].copy_from_slice(&ipv4_addr.octets());
  //       off += IPV4_LEN;
  //     }
  //     RecordDataRef::AAAA(ipv6_addr) => {
  //       buf[off..off + IPV6_LEN].copy_from_slice(&ipv6_addr.octets());
  //       off += IPV6_LEN;
  //     }
  //     RecordDataRef::PTR(name) => {
  //       let len = name.len();
  //       buf[..len].copy_from_slice(name.as_bytes());
  //       off += len;
  //     }
  //     RecordDataRef::SRV(srv) => {
  //       buf[off..off + U16_SIZE].copy_from_slice(&srv.priority().to_be_bytes());
  //       off += U16_SIZE;
  //       buf[off..off + U16_SIZE].copy_from_slice(&srv.weight().to_be_bytes());
  //       off += U16_SIZE;
  //       buf[off..off + U16_SIZE].copy_from_slice(&srv.port().to_be_bytes());
  //       off += U16_SIZE;
  //       let len = srv.target().len();
  //       buf[off..off + len].copy_from_slice(srv.target().as_bytes());
  //       off += len;
  //     }
  //     RecordDataRef::TXT(txt) => {
  //       off += encode_txt(txt, buf, off).unwrap();
  //     }
  //   }

  //   off
  // }

  // pub(super) fn decode(
  //   src: &[u8],
  //   off: usize,
  //   consume: bool,
  // ) -> Result<(Option<Self>, usize), ProtoError> {
  //   let (name, mut off) = Name::decode(src, off)?;
  //   let len = src.len();
  //   if len < off + RECORD_HEADER_ENCODED_WITHOUT_NAME_SIZE {
  //     return Err(ProtoError::BufferTooSmall);
  //   }

  //   let ty = RecordType::from(u16::from_be_bytes([src[off], src[off + 1]]));
  //   off += U16_SIZE;
  //   let class = DNSClass::from(u16::from_be_bytes([src[off], src[off + 1]]));
  //   off += U16_SIZE;
  //   let ttl = u32::from_be_bytes(src[off..off + U32_SIZE].try_into().unwrap());
  //   off += U32_SIZE;
  //   let rdlen = u16::from_be_bytes([src[off], src[off + 1]]) as usize;
  //   off += U16_SIZE;
  //   if rdlen > len {
  //     return Err(ProtoError::Overflow);
  //   }

  //   if consume {
  //     return Ok((None, off + rdlen));
  //   }
  //   let src = &src[..off + rdlen];
  //   let len = src.len();
  //   let data = match ty {
  //     RecordType::A => {
  //       if off + IPV4_LEN > len {
  //         return Err(ProtoError::NotEnoughData);
  //       }

  //       let octets: [u8; IPV4_LEN] = src[off..off + IPV4_LEN].try_into().unwrap();
  //       off += IPV4_LEN;
  //       RecordDataRef::A(Ipv4Addr::from(octets))
  //     }
  //     RecordType::AAAA => {
  //       if off + IPV6_LEN > len {
  //         return Err(ProtoError::NotEnoughData);
  //       }

  //       let octets: [u8; IPV6_LEN] = src[off..off + IPV6_LEN].try_into().unwrap();
  //       off += IPV6_LEN;
  //       RecordDataRef::AAAA(Ipv6Addr::from(octets))
  //     }
  //     RecordType::PTR => {
  //       let (name, off1) = Name::decode(src, off)?;
  //       off = off1;
  //       RecordDataRef::PTR(name)
  //     }
  //     RecordType::SRV => {
  //       if off + 6 > len {
  //         return Err(ProtoError::NotEnoughData);
  //       }

  //       let priority = u16::from_be_bytes([src[off], src[off + 1]]);
  //       off += U16_SIZE;
  //       let weight = u16::from_be_bytes([src[off], src[off + 1]]);
  //       off += U16_SIZE;
  //       let port = u16::from_be_bytes([src[off], src[off + 1]]);
  //       off += U16_SIZE;

  //       let (name, off1) = Name::decode(src, off)?;
  //       off = off1;
  //       RecordDataRef::SRV(SRV::new(priority, weight, port, name))
  //     }
  //     RecordType::TXT => {
  //       let (txt, off1) = decode_txt(src, off)?;
  //       off = off1;
  //       RecordDataRef::TXT(Arc::from_iter(txt))
  //     }
  //     _ => return Ok((None, off + rdlen)),
  //   };

  //   let mut r = Self::from_rdata(name, ttl, data);
  //   r.header.class = class;
  //   Ok((Some(r), off))
  // }

  // pub(super) fn encode(
  //   &self,
  //   buf: &mut [u8],
  //   off: usize,
  //   cmap: &mut Option<CompressionMap>,
  //   compress: bool,
  // ) -> Result<usize, ProtoError> {
  //   if off == buf.len() {
  //     return Ok(off);
  //   }

  //   let mut off = self.header.name.encode(buf, off, cmap, compress)?;
  //   if buf.len() < off + RECORD_HEADER_ENCODED_WITHOUT_NAME_SIZE {
  //     return Err(ProtoError::BufferTooSmall);
  //   }

  //   buf[off..off + U16_SIZE].copy_from_slice(&(u16::from(self.header.ty)).to_be_bytes());
  //   off += U16_SIZE;
  //   buf[off..off + U16_SIZE].copy_from_slice(&(u16::from(self.header.class)).to_be_bytes());
  //   off += U16_SIZE;
  //   buf[off..off + U32_SIZE].copy_from_slice(&self.header.ttl.to_be_bytes());
  //   off += U32_SIZE;
  //   buf[off..off + U16_SIZE].copy_from_slice(&0u16.to_be_bytes()); // update later
  //   off += U16_SIZE;

  //   let heoff = off;

  //   let off1 = match &self.data {
  //     RecordDataRef::A(ipv4_addr) => {
  //       if buf.len() < off + IPV4_LEN {
  //         return Err(ProtoError::BufferTooSmall);
  //       }

  //       buf[off..off + IPV4_LEN].copy_from_slice(&ipv4_addr.octets());
  //       off + IPV4_LEN
  //     }
  //     RecordDataRef::AAAA(ipv6_addr) => {
  //       if buf.len() < off + IPV6_LEN {
  //         return Err(ProtoError::BufferTooSmall);
  //       }

  //       buf[off..off + IPV6_LEN].copy_from_slice(&ipv6_addr.octets());
  //       off + IPV6_LEN
  //     }
  //     RecordDataRef::PTR(name) => name.encode(buf, off, cmap, compress)?,
  //     RecordDataRef::SRV(srv) => {
  //       if buf.len() < off + 6 {
  //         return Err(ProtoError::BufferTooSmall);
  //       }

  //       buf[off..off + U16_SIZE].copy_from_slice(&srv.priority().to_be_bytes());
  //       off += U16_SIZE;
  //       buf[off..off + U16_SIZE].copy_from_slice(&srv.weight().to_be_bytes());
  //       off += U16_SIZE;
  //       buf[off..off + U16_SIZE].copy_from_slice(&srv.port().to_be_bytes());
  //       off += U16_SIZE;

  //       srv.target().encode(buf, off, cmap, false)?
  //     }
  //     RecordDataRef::TXT(txt) => encode_txt(txt, buf, off)?,
  //   };

  //   let rdlen = off1 - heoff;
  //   if rdlen > u16::MAX as usize {
  //     return Err(ProtoError::InvalidRdata);
  //   }

  //   buf[heoff - 2..heoff].copy_from_slice(&(rdlen as u16).to_be_bytes());

  //   Ok(off1)
  // }

  // pub(super) fn encoded_len(&self, cmap: &mut Option<HashSet<SlicableSmolStr>>) -> usize {
  //   let mut off =
  //     self.header.name.encoded_len(0, cmap, true) + RECORD_HEADER_ENCODED_WITHOUT_NAME_SIZE;
  //   match &self.data {
  //     RecordDataRef::A(_) => off + IPV4_LEN,
  //     RecordDataRef::AAAA(_) => off + IPV6_LEN,
  //     RecordDataRef::PTR(name) => name.encoded_len(off, cmap, true),
  //     RecordDataRef::SRV(srv) => {
  //       let l = off + 6;
  //       srv.target().encoded_len(l, cmap, false)
  //     }
  //     RecordDataRef::TXT(txt) => {
  //       for s in txt.iter() {
  //         off += s.len() + 1;
  //       }
  //       off
  //     }
  //   }
  // }
}
