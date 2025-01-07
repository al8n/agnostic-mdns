use smallvec_wrapper::OneOrMore;

use super::{DecodeError, Query, Record, OP_CODE_QUERY, RESPONSE_CODE_NO_ERROR};

pub(crate) struct Header {
  id: u16,
  pub(crate) opcode: u16,
  pub(crate) response_code: u16,
  pub(crate) truncated: bool,
  compress: bool,
}


/// The message used in mDNS.
pub(crate) struct Message {
  pub(crate) header: Header,
  questions: Vec<Query>,
  answers: Vec<Record>,
  additionals: Vec<Record>,
}

impl Message {
  #[inline]
  pub(crate) fn id(&self) -> u16 {
    self.header.id
  }

  #[inline]
  pub(crate) fn questions(&self) -> &[Query] {
    &self.questions
  }
  
  #[inline]
  pub(crate) fn into_iter(self) -> impl Iterator<Item = Record> {
    self.answers.into_iter().chain(self.additionals)
  }

  #[inline]
  pub(crate) fn decode(src: &[u8]) -> Result<Self, DecodeError> {
    todo!()
  }
}