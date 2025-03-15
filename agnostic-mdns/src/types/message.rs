// use super::{MESSAGE_HEADER_SIZE, ProtoError, record::Record};

// /// The message used in mDNS.
// #[derive(Debug)]
// pub(crate) struct Message {
//   answers: Vec<Record>,
//   additionals: Vec<Record>,
// }

// impl Message {
//   #[inline]
//   pub(crate) fn into_iter(self) -> impl Iterator<Item = Record> {
//     self.answers.into_iter().chain(self.additionals)
//   }

//   // #[inline]
//   // pub(crate) fn decode(src: &[u8]) -> Result<Self, ProtoError> {
//   //   let buflen = src.len();
//   //   if buflen < MESSAGE_HEADER_SIZE {
//   //     return Err(ProtoError::NotEnoughData);
//   //   }

//   //   let qdcount = u16::from_be_bytes([src[4], src[5]]);
//   //   let ancount = u16::from_be_bytes([src[6], src[7]]);
//   //   let nscount = u16::from_be_bytes([src[8], src[9]]);
//   //   let arcount = u16::from_be_bytes([src[10], src[11]]);

//   //   let mut off = MESSAGE_HEADER_SIZE;
//   //   if off == buflen {
//   //     return Ok(Self {
//   //       answers: Vec::new(),
//   //       additionals: Vec::new(),
//   //     });
//   //   }

//   //   if qdcount > 0 {
//   //     for _ in 0..qdcount {
//   //       let off1 = off;
//   //       let noff = Query::skip_decode(src, off)?;
//   //       if off1 == noff {
//   //         // Offset does not increase anymore, dh.Qdcount is a lie!
//   //         break;
//   //       }

//   //       off = noff;
//   //     }
//   //   }

//   //   let (answers, off1) = Self::decode_rr_slice(src, off, ancount, false)?;
//   //   off = off1;
//   //   let (_, off1) = Self::decode_rr_slice(src, off, nscount, true)?;
//   //   off = off1;
//   //   let (ar, _) = Self::decode_rr_slice(src, off, arcount, false)?;
//   //   Ok(Self {
//   //     answers,
//   //     additionals: ar,
//   //   })
//   // }

//   // fn decode_rr_slice(
//   //   src: &[u8],
//   //   mut off: usize,
//   //   count: u16,
//   //   consume: bool,
//   // ) -> Result<(Vec<Record>, usize), ProtoError> {
//   //   // Don't pre-allocate, l may be under attacker control
//   //   let mut records = Vec::new();
//   //   for _ in 0..count {
//   //     let off1 = off;
//   //     let (r, noff) = Record::decode(src, off, consume)?;
//   //     // If offset does not increase anymore, l is a lie
//   //     if off1 == noff {
//   //       break;
//   //     }

//   //     off = noff;

//   //     if let Some(r) = r {
//   //       records.push(r);
//   //     }
//   //   }

//   //   Ok((records, off))
//   // }
// }
