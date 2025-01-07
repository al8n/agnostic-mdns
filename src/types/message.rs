use smallvec_wrapper::OneOrMore;

use super::{DecodeError, Record};


/// The message used in mDNS.
pub struct Message {
  // header: MessageHeader,
  answers: Vec<Record>,
  additionals: Vec<Record>,
}

impl Message {
  #[inline]
  pub(crate) fn into_iter(self) -> impl Iterator<Item = Record> {
    self.answers.into_iter().chain(self.additionals)
  }

  #[inline]
  pub(crate) fn decode(src: &[u8]) -> Result<Self, DecodeError> {
    todo!()
  }
}