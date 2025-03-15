use mdns_proto::proto::{Label, ResourceRecord};
use super::{DNS_CLASS_IN, RecordDataRef};

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
}

// /// The mDNS resource record.
// #[derive(Debug, Clone, PartialEq, Eq, Hash)]
// pub(crate) struct Record {
//   header: RecordHeader,
//   data: RecordData,
// }

// impl Record {
//   /// Creates a new mDNS resource record.
//   pub fn from_rdata(name: SmolStr, ttl: u32, data: RecordData) -> Self {
//     Self {
//       header: RecordHeader {
//         name,
//         ty: data.ty(),
//         class: DNS_CLASS_IN,
//         ttl,
//       },
//       data,
//     }
//   }

//   /// Consumes the record and returns the [`RecordHeader`] and [`RecordData`].
//   #[inline]
//   pub fn into_components(self) -> (RecordHeader, RecordData) {
//     (self.header, self.data)
//   }

//   // pub(super) fn decode(
//   //   src: &[u8],
//   //   off: usize,
//   //   consume: bool,
//   // ) -> Result<(Option<Self>, usize), ProtoError> {
//   //   let (name, mut off) = Name::decode(src, off)?;
//   //   let len = src.len();
//   //   if len < off + RECORD_HEADER_ENCODED_WITHOUT_NAME_SIZE {
//   //     return Err(ProtoError::BufferTooSmall);
//   //   }

//   //   let ty = ResourceType::try_from(u16::from_be_bytes([src[off], src[off + 1]]))
//   //     .map_err(|_| ProtoError::InvalidRdata)?;
//   //   off += U16_SIZE;
//   //   let class = u16::from_be_bytes([src[off], src[off + 1]]);
//   //   off += U16_SIZE;
//   //   let ttl = u32::from_be_bytes(src[off..off + U32_SIZE].try_into().unwrap());
//   //   off += U32_SIZE;
//   //   let rdlen = u16::from_be_bytes([src[off], src[off + 1]]) as usize;
//   //   off += U16_SIZE;
//   //   if rdlen > len {
//   //     return Err(ProtoError::Overflow);
//   //   }

//   //   if consume {
//   //     return Ok((None, off + rdlen));
//   //   }
//   //   let src = &src[..off + rdlen];
//   //   let len = src.len();
//   //   let data = match ty {
//   //     ResourceType::A => {
//   //       if off + IPV4_LEN > len {
//   //         return Err(ProtoError::NotEnoughData);
//   //       }

//   //       let octets: [u8; IPV4_LEN] = src[off..off + IPV4_LEN].try_into().unwrap();
//   //       off += IPV4_LEN;
//   //       RecordData::A(Ipv4Addr::from(octets))
//   //     }
//   //     ResourceType::AAAA => {
//   //       if off + IPV6_LEN > len {
//   //         return Err(ProtoError::NotEnoughData);
//   //       }

//   //       let octets: [u8; IPV6_LEN] = src[off..off + IPV6_LEN].try_into().unwrap();
//   //       off += IPV6_LEN;
//   //       RecordData::AAAA(Ipv6Addr::from(octets))
//   //     }
//   //     ResourceType::Ptr => {
//   //       let (name, off1) = Name::decode(src, off)?;
//   //       off = off1;
//   //       RecordData::PTR(name)
//   //     }
//   //     ResourceType::Srv => {
//   //       if off + 6 > len {
//   //         return Err(ProtoError::NotEnoughData);
//   //       }

//   //       let priority = u16::from_be_bytes([src[off], src[off + 1]]);
//   //       off += U16_SIZE;
//   //       let weight = u16::from_be_bytes([src[off], src[off + 1]]);
//   //       off += U16_SIZE;
//   //       let port = u16::from_be_bytes([src[off], src[off + 1]]);
//   //       off += U16_SIZE;

//   //       let (target, off1) = Name::decode(src, off)?;
//   //       off = off1;
//   //       RecordData::SRV {
//   //         priority,
//   //         weight,
//   //         port,
//   //         target,
//   //       }
//   //     }
//   //     ResourceType::Txt => {
//   //       let (txt, off1) = TXT::decode_strings(src, off)?;
//   //       off = off1;
//   //       RecordData::TXT(match txt.into_inner() {
//   //         Either::Left(s) => Arc::from_iter(s),
//   //         Either::Right(txts) => Arc::from(txts),
//   //       })
//   //     }
//   //     _ => return Ok((None, off + rdlen)),
//   //   };

//   //   let mut r = Self::from_rdata(name, ttl, data);
//   //   r.header.class = class;
//   //   Ok((Some(r), off))
//   // }
// }
