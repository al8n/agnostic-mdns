// use super::{Name, ProtoError};
// use mdns_proto::{error::Error, Flags, Message, Question, ResourceType};
// use smol_str::SmolStr;

// #[derive(Debug, Clone, PartialEq, Eq)]
// pub(crate) struct Query {
//   name: SmolStr,
//   ty: ResourceType,
//   want_unicast_response: bool,
// }

// impl Query {
//   #[inline]
//   pub const fn new(name: SmolStr, want_unicast_response: bool) -> Self {
//     Self {
//       name,
//       ty: ResourceType::Ptr,
//       want_unicast_response,
//     }
//   }

//   /// Only consumes the buffer if there is enough data to decode the query.
//   #[inline]
//   pub fn skip_decode(src: &[u8], off: usize) -> Result<usize, ProtoError> {
//     let mut off = Name::skip_decode(src, off)?;
//     let len = src.len();
//     if off == src.len() {
//       return Ok(off);
//     }

//     if len < off + 2 {
//       return Err(ProtoError::NotEnoughData);
//     }

//     // type
//     off += 2;
//     if len == off {
//       return Ok(off);
//     }

//     if len < off + 2 {
//       return Err(ProtoError::NotEnoughData);
//     }

//     // class
//     off += 2;
//     Ok(off)
//   }

//   /// Encodes the query into a DNS message wire format.
//   #[inline]
//   pub fn encode(&self, buf: &mut [u8]) -> Result<usize, Error> {
//     // RFC 6762, section 18.12.  Repurposing of Top Bit of qclass in Query
//     // Section
//     //
//     // In the Query Section of a Multicast DNS query, the top bit of the qclass
//     // field is used to indicate that unicast responses are preferred for this
//     // particular question.  (See Section 5.4.)
//     let qclass = if self.want_unicast_response {
//       let base: u16 = 1;
//       base | (1 << 15)
//     } else {
//       1
//     };

//     let question = Question::new(self.name.as_str(), ResourceType::Ptr, qclass);
//     let mut questions = [question];

//     Message::new(0, Flags::new(), &mut questions, &mut [], &mut [], &mut []).write(buf)
//   }
// }
