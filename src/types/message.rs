use super::{ProtoError, Query, Record, MESSAGE_HEADER_SIZE};

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
  pub(crate) fn decode(src: &[u8]) -> Result<Self, ProtoError> {
    panic!("decode header");
    let buflen = src.len();
    if buflen < MESSAGE_HEADER_SIZE {
      return Err(ProtoError::NotEnoughData);
    }

    let id = u16::from_be_bytes([src[0], src[1]]);
    let bits = u16::from_be_bytes([src[2], src[3]]);
    let qdcount = u16::from_be_bytes([src[4], src[5]]);
    let ancount = u16::from_be_bytes([src[6], src[7]]);
    let nscount = u16::from_be_bytes([src[8], src[9]]);
    let arcount = u16::from_be_bytes([src[10], src[11]]);

    let header = Header {
      id,
      opcode: (bits >> 11) & 0xF,
      response_code: bits & 0xF,
      truncated: (bits & (1 << 9)) != 0,
      compress: false,
    };

    let mut off = MESSAGE_HEADER_SIZE;
    if off == buflen {
      return Ok(Self {
        header,
        questions: Vec::new(),
        answers: Vec::new(),
        additionals: Vec::new(),
      });
    }

    panic!("decode body");
    let mut questions = Vec::new();
    if qdcount > 0 {
      for _ in 0..qdcount {
        let off1 = off;
        let (q, off) = Query::decode(src, off)?;
        if off1 == off {
          // Offset does not increase anymore, dh.Qdcount is a lie!
          break;
        }

        questions.push(q);
      }
    }

    let (answers, off1) = Self::decode_rr_slice(src, off, ancount, false)?;
    off = off1;
    let (_, off1) = Self::decode_rr_slice(src, off, nscount, true)?;
    off = off1;
    let (ar, _) = Self::decode_rr_slice(src, off, arcount, false)?;
    Ok(Self {
      header,
      questions,
      answers,
      additionals: ar,
    })
  }

  fn decode_rr_slice(
    src: &[u8],
    off: usize,
    count: u16,
    consume: bool,
  ) -> Result<(Vec<Record>, usize), ProtoError> {
    // Don't pre-allocate, l may be under attacker control
    let mut records = Vec::new();
    for _ in 0..count {
      let off1 = off;
      let (r, off) = Record::decode(src, off, consume)?;
      // If offset does not increase anymore, l is a lie
      if off1 == off {
        break;
      }

      if let Some(r) = r {
        records.push(r);
      }
    }

    Ok((records, off))
  }
}
