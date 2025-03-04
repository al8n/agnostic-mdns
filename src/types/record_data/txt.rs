use smallvec_wrapper::{SmallVec, XXLargeVec};
use smol_str::SmolStr;
use triomphe::Arc;

use crate::{
  ProtoError,
  types::{ddd_to_byte, escape_bytes, is_ddd},
};

/// ```text
/// 3.3.14. TXT RDATA format
///
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///     /                   TXT-DATA                    /
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///
/// where:
///
/// TXT-DATA        One or more <character-string>s.
///
/// TXT RRs are used to hold descriptive text.  The semantics of the text
/// depends on the domain where it is found.
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TXT {
  data: Arc<[u8]>,
  txts: Arc<[SmolStr]>,
}

impl TXT {
  /// Create a new TXT record data.
  #[inline]
  pub fn new(txts: impl Into<Arc<[SmolStr]>>) -> Result<Self, ProtoError> {
    let txts = txts.into();
    let encoded_len = txts.iter().map(|s| s.len() + 1).sum::<usize>();
    let mut buf = vec![0; encoded_len];
    encode_txt(&txts, &mut buf, 0).map(|size| Self {
      data: {
        buf.truncate(size);
        Arc::from(buf)
      },
      txts,
    })
  }

  /// Returns all of character-strings in the TXT record data.
  #[inline]
  pub fn strings(&self) -> &[SmolStr] {
    &self.txts
  }

  /// Returns the encoded bytes of the TXT record data.
  #[inline]
  pub fn data(&self) -> &[u8] {
    &self.data
  }

  pub(crate) fn decode_strings(
    src: &[u8],
    off: usize,
  ) -> Result<(SmallVec<SmolStr>, usize), ProtoError> {
    decode_txt(src, off)
  }
}

fn encode_txt(txt: &[SmolStr], buf: &mut [u8], mut off: usize) -> Result<usize, ProtoError> {
  if txt.is_empty() {
    if off >= buf.len() {
      return Err(ProtoError::BufferTooSmall);
    }

    buf[off] = 0;
    return Ok(off);
  }

  for s in txt {
    off = encode_txt_string(s, buf, off)?;
  }

  Ok(off)
}

fn encode_txt_string(s: &str, buf: &mut [u8], mut off: usize) -> Result<usize, ProtoError> {
  let len_byte_offset = off;
  if off >= buf.len() || s.len() > 256 * 4 + 1
  /* If all \DDD */
  {
    return Err(ProtoError::BufferTooSmall);
  }

  off += 1;
  let s = s.as_bytes();

  let mut i = 0;

  while i < s.len() {
    if off >= buf.len() {
      return Err(ProtoError::BufferTooSmall);
    }

    let c = s[i];
    if c == b'\\' {
      i += 1;
      if i == s.len() {
        break;
      }

      // check for \DDD
      if is_ddd(&s[i..]) {
        buf[off] = ddd_to_byte(&s[i..]);
        i += 2;
      } else {
        buf[off] = s[i];
      }
    } else {
      buf[off] = c;
    }

    off += 1;
    i += 1;
  }

  let l = off - len_byte_offset - 1;
  if l > 255 {
    return Err(ProtoError::TxtDataTooLong);
  }

  buf[len_byte_offset] = l as u8;
  Ok(off)
}

fn decode_txt(msg: &[u8], mut off: usize) -> Result<(SmallVec<SmolStr>, usize), ProtoError> {
  let mut txt = SmallVec::new();
  while off < msg.len() {
    let (s, off1) = decode_txt_string(msg, off)?;
    txt.push(s);
    off = off1;
  }

  Ok((txt, off))
}

fn decode_txt_string(msg: &[u8], mut off: usize) -> Result<(SmolStr, usize), ProtoError> {
  if off + 1 > msg.len() {
    return Err(ProtoError::NotEnoughData);
  }

  let l = msg[off] as usize;
  off += 1;

  if off + l > msg.len() {
    return Err(ProtoError::NotEnoughData);
  }

  let mut buf = XXLargeVec::<u8>::new();
  let mut consumed = 0;
  for (i, &b) in msg[off..off + l].iter().enumerate() {
    match () {
      () if b == b'"' || b == b'\\' => {
        buf.extend_from_slice(&msg[off + consumed..off + i]);
        buf.push(b'\\');
        buf.push(b);
        consumed = i + 1;
      }
      () if !(b' '..=b'~').contains(&b) => {
        buf.extend_from_slice(&msg[off + consumed..off + i]);
        buf.extend_from_slice(escape_bytes(b, &mut [0; 4]));
        consumed = i + 1;
      }
      _ => {}
    }
  }

  if consumed == 0 {
    // no escaping needed
    return core::str::from_utf8(&msg[off..off + l])
      .map(|s| (SmolStr::new(s), off + l))
      .map_err(ProtoError::Utf8);
  }

  buf.extend_from_slice(&msg[off + consumed..off + l]);
  core::str::from_utf8(&buf)
    .map(|s| (SmolStr::new(s), off + l))
    .map_err(ProtoError::Utf8)
}
