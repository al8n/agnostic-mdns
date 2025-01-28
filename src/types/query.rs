use super::{Name, RecordType};
use dns_protocol::{Error, Flags, Message, Question, ResourceType};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Query {
  name: Name,
  ty: RecordType,
  want_unicast_response: bool,
}

impl Query {
  #[inline]
  pub const fn new(name: Name, want_unicast_response: bool) -> Self {
    Self {
      name,
      ty: RecordType::PTR,
      want_unicast_response,
    }
  }

  #[inline]
  pub const fn name(&self) -> &Name {
    &self.name
  }

  #[inline]
  pub const fn query_type(&self) -> RecordType {
    self.ty
  }

  /// Encodes the query into a DNS message wire format.
  #[inline]
  pub fn encode(&self, buf: &mut [u8]) -> Result<usize, Error> {
    // RFC 6762, section 18.12.  Repurposing of Top Bit of qclass in Query
    // Section
    //
    // In the Query Section of a Multicast DNS query, the top bit of the qclass
    // field is used to indicate that unicast responses are preferred for this
    // particular question.  (See Section 5.4.)
    let qclass = if self.want_unicast_response {
      let base: u16 = 1;
      base | (1 << 15)
    } else {
      1
    };

    let question = Question::new(self.name.as_str(), ResourceType::Ptr, qclass);
    let mut questions = [question];

    Message::new(0, Flags::new(), &mut questions, &mut [], &mut [], &mut []).write(buf)
  }
}
