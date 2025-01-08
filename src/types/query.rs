use smallvec_wrapper::XXLargeVec;

use super::{DNSClass, Name, ProtoError, RecordType, MESSAGE_HEADER_SIZE, QDCOUNT_OFFSET};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Query {
  name: Name,
  ty: RecordType,
  class: DNSClass,
  want_unicast_response: bool,
}

impl Query {
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
  pub const fn name(&self) -> &Name {
    &self.name
  }

  #[inline]
  pub const fn query_class(&self) -> DNSClass {
    self.class
  }

  #[inline]
  pub const fn query_type(&self) -> RecordType {
    self.ty
  }

  /// Decodes a query in a DNS message wire format, this is not the opposite method of `encode`.
  #[inline]
  pub fn decode(src: &[u8], off: usize) -> Result<(Self, usize), ProtoError> {
    let (name, mut off) = Name::decode(src, off)?;
    let len = src.len();
    if off == src.len() {
      return Ok((
        Self {
          name,
          ty: RecordType::UNKNOWN(0),
          class: DNSClass::UNKNOWN(0),
          want_unicast_response: false,
        },
        off,
      ));
    }

    if len < off + 2 {
      return Err(ProtoError::NotEnoughData);
    }
    let ty = RecordType::from(u16::from_be_bytes([src[off], src[off + 1]]));
    off += 2;
    if len == off {
      return Ok((
        Self {
          name,
          ty,
          class: DNSClass::UNKNOWN(0),
          want_unicast_response: false,
        },
        off,
      ));
    }

    if len < off + 2 {
      return Err(ProtoError::NotEnoughData);
    }

    let bclass = u16::from_be_bytes([src[off], src[off + 1]]);
    let class = DNSClass::from(bclass);
    off += 2;
    Ok((
      Self {
        name,
        ty,
        class,
        want_unicast_response: bclass & (1 << 15) != 0,
      },
      off,
    ))
  }

  /// Encodes the query into a DNS message wire format.
  #[inline]
  pub fn encode(&self) -> Result<XXLargeVec<u8>, ProtoError> {
    let uncompressed_len = self.encoded_len();
    let mut buf = XXLargeVec::with_capacity(uncompressed_len + 1);
    buf.resize(uncompressed_len + 1, 0);

    let mut off = 0;
    let mut header = [0u8; MESSAGE_HEADER_SIZE];
    header[QDCOUNT_OFFSET..QDCOUNT_OFFSET + 2].copy_from_slice(&(1u16).to_be_bytes());
    buf[0..MESSAGE_HEADER_SIZE].copy_from_slice(&header);
    off += MESSAGE_HEADER_SIZE;

    let mut off = self.name.encode(&mut buf, off, &mut None, false)?;
    buf[off..off + 2].copy_from_slice(&u16::from(self.ty).to_be_bytes());
    off += 2;

    // RFC 6762, section 18.12.  Repurposing of Top Bit of qclass in Query
    // Section
    //
    // In the Query Section of a Multicast DNS query, the top bit of the qclass
    // field is used to indicate that unicast responses are preferred for this
    // particular question.  (See Section 5.4.)
    let qclass = if self.want_unicast_response {
      let base: u16 = self.class.into();
      base | (1 << 15)
    } else {
      self.class.into()
    };
    buf[off..off + 2].copy_from_slice(&qclass.to_be_bytes());
    Ok(buf)
  }

  #[inline]
  fn encoded_len(&self) -> usize {
    MESSAGE_HEADER_SIZE + self.name.encoded_len(MESSAGE_HEADER_SIZE, &mut None, false) + 2 + 2
  }
}
