use smallvec_wrapper::XXLargeVec;

use super::{DNSClass, EncodeError, Name, RecordType, MESSAGE_HEADER_SIZE, QDCOUNT_OFFSET};


pub(crate) struct Question {
  name: Name,
  ty: RecordType,
  class: DNSClass,
  want_unicast_response: bool,
}

impl Question {
  #[inline]
  pub const fn new(name: Name, want_unicast_response: bool) -> Self {
    Self {
      name,
      ty: RecordType::PTR,
      class: DNSClass::IN,
      want_unicast_response,
    }
  }

  #[inline]
  pub fn encode(&self) -> Result<XXLargeVec<u8>, EncodeError> {
    let uncompressed_len = self.encoded_len();
    let mut buf = XXLargeVec::with_capacity(uncompressed_len);

    let mut off = 0;
    let mut header = [0u8; MESSAGE_HEADER_SIZE];
    header[QDCOUNT_OFFSET..QDCOUNT_OFFSET + 2].copy_from_slice(&(1u16).to_be_bytes());
    buf.extend_from_slice(&header);
    off += MESSAGE_HEADER_SIZE;

    self.name.encode(&mut buf, off, &mut None)?;
    buf.extend_from_slice(&(self.ty as u16).to_be_bytes());

    // RFC 6762, section 18.12.  Repurposing of Top Bit of qclass in Question
    // Section
    //
    // In the Question Section of a Multicast DNS query, the top bit of the qclass
    // field is used to indicate that unicast responses are preferred for this
    // particular question.  (See Section 5.4.)
    let qclass = if self.want_unicast_response {
      let base = self.class as u16;
      base | (1 << 15)
    } else {
      self.class as u16
    };
    buf.extend_from_slice(&qclass.to_be_bytes());
    Ok(buf)
  }

  #[inline]
  fn encoded_len(&self) -> usize {
    MESSAGE_HEADER_SIZE + self.name.encoded_len(MESSAGE_HEADER_SIZE, None) + 2 + 2
  }
}