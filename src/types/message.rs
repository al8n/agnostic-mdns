use super::{ProtoError, Query, Record, MESSAGE_HEADER_SIZE};

#[derive(Debug)]
pub(crate) struct Header {
  id: u16,
  pub(crate) opcode: u16,
  pub(crate) response_code: u16,
  pub(crate) truncated: bool,
}

/// The message used in mDNS.
#[derive(Debug)]
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
  pub(crate) fn queries(&self) -> &[Query] {
    &self.questions
  }

  #[inline]
  pub(crate) fn into_iter(self) -> impl Iterator<Item = Record> {
    self.answers.into_iter().chain(self.additionals)
  }

  #[inline]
  pub(crate) fn decode(src: &[u8]) -> Result<Self, ProtoError> {
    // panic!("decode header");
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

    let mut questions = Vec::new();
    if qdcount > 0 {
      for _ in 0..qdcount {
        let off1 = off;
        let (q, noff) = Query::decode(src, off)?;
        if off1 == noff {
          // Offset does not increase anymore, dh.Qdcount is a lie!
          break;
        }

        off = noff;
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
    mut off: usize,
    count: u16,
    consume: bool,
  ) -> Result<(Vec<Record>, usize), ProtoError> {
    // Don't pre-allocate, l may be under attacker control
    let mut records = Vec::new();
    for _ in 0..count {
      let off1 = off;
      let (r, noff) = Record::decode(src, off, consume)?;
      // If offset does not increase anymore, l is a lie
      if off1 == noff {
        break;
      }

      off = noff;

      if let Some(r) = r {
        records.push(r);
      }
    }

    Ok((records, off))
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn decode() {
    let src = [
      0, 0, 132, 0, 0, 0, 0, 5, 0, 0, 0, 0, 7, 95, 102, 111, 111, 98, 97, 114, 4, 95, 116, 99, 112,
      5, 108, 111, 99, 97, 108, 0, 0, 12, 0, 1, 0, 0, 0, 120, 0, 11, 8, 104, 111, 115, 116, 110,
      97, 109, 101, 192, 12, 192, 42, 0, 33, 0, 1, 0, 0, 0, 120, 0, 16, 0, 10, 0, 1, 0, 80, 8, 116,
      101, 115, 116, 104, 111, 115, 116, 0, 192, 42, 0, 1, 0, 1, 0, 0, 0, 120, 0, 4, 192, 168, 0,
      42, 192, 42, 0, 28, 0, 1, 0, 0, 0, 120, 0, 16, 38, 32, 0, 0, 16, 0, 25, 0, 176, 194, 208,
      178, 196, 17, 24, 188, 192, 42, 0, 16, 0, 1, 0, 0, 0, 120, 0, 17, 16, 76, 111, 99, 97, 108,
      32, 119, 101, 98, 32, 115, 101, 114, 118, 101, 114,
    ];
    let msg = Message::decode(&src).unwrap();
    println!("{:?}", msg);
  }
}
