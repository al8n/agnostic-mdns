use std::collections::HashSet;

use smallvec_wrapper::{OneOrMore, XXLargeVec};

use crate::types::CompressionMap;

use super::{ProtoError, Record, SlicableSmolStr, ANCOUNT_OFFSET, MESSAGE_HEADER_SIZE};

const BITS: u16 = (1 << 15) // Response set to true
  | (1 << 10); // Authoritative set to true

#[derive(Debug)]
pub(crate) struct Answer {
  id: u16,
  records: OneOrMore<Record>,
}

impl Answer {
  pub(crate) fn new(id: u16, records: OneOrMore<Record>) -> Self {
    Self { id, records }
  }

  // 18.3: OPCODE - must be zero in response (OpcodeQuery == 0)
  // 18.4: AA (Authoritative Answer) Bit - must be set to 1
  // 18.2: QR (Query/Response) Bit - must be set to 1 in response.
  //
  // The following fields must all be set to 0:
  //  18.5: TC (TRUNCATED) Bit
  //  18.6: RD (Recursion Desired) Bit
  //  18.7: RA (Recursion Available) Bit
  //  18.8: Z (Zero) Bit
  //  18.9: AD (Authentic Data) Bit
  //  18.10: CD (Checking Disabled) Bit
  //  18.11: RCODE (Response Code)
  pub(crate) fn encode(&self) -> Result<XXLargeVec<u8>, ProtoError> {
    let mut hbuf = [0u8; MESSAGE_HEADER_SIZE];
    hbuf[0..2].copy_from_slice(&self.id.to_be_bytes());
    hbuf[2..4].copy_from_slice(&BITS.to_be_bytes());
    hbuf[ANCOUNT_OFFSET..ANCOUNT_OFFSET + 2]
      .copy_from_slice(&(self.records.len() as u16).to_be_bytes());
    let mut cmap = Some(CompressionMap::new());
    let uncompressed_len = self.encoded_len(&mut None);
    let mut buf = XXLargeVec::with_capacity(uncompressed_len + 1);
    buf.resize(uncompressed_len + 1, 0);
    buf[0..MESSAGE_HEADER_SIZE].copy_from_slice(&hbuf);
    let mut off = MESSAGE_HEADER_SIZE;

    for ans in self.records.iter() {
      off = ans.encode(&mut buf, off, &mut cmap, true)?;
    }

    buf.truncate(off);
    Ok(buf)
  }

  pub(super) fn encoded_len(&self, cmap: &mut Option<HashSet<SlicableSmolStr>>) -> usize {
    let mut l = MESSAGE_HEADER_SIZE;

    for ans in self.records.iter() {
      l += ans.encoded_len(cmap);
    }

    l
  }
}
