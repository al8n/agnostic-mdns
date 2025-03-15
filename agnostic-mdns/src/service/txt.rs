use smol_str::SmolStr;
use triomphe::Arc;

use super::ServiceError;

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
#[derive(Clone, PartialEq, Eq, Hash)]
#[allow(clippy::upper_case_acronyms)]
pub struct TXT {
  data: Arc<[u8]>,
  txts: Arc<[SmolStr]>,
}

impl core::fmt::Debug for TXT {
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    f.debug_tuple("TXT").field(&self.txts).finish()
  }
}

impl TXT {
  /// Create a new TXT record data.
  #[inline]
  pub fn new(txts: impl Into<Arc<[SmolStr]>>) -> Result<Self, ServiceError> {
    let txts = txts.into();
    let encoded_len = txts.iter().map(|s| s.len() + 1).sum::<usize>().max(1);
    let mut buf = vec![0; encoded_len];
    encode_txt(&txts, &mut buf).map(|size| Self {
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
}

fn encode_txt(txt: &[SmolStr], buf: &mut [u8]) -> Result<usize, ServiceError> {
  let mut off = 0;
  if txt.is_empty() {

    buf[off] = 0;
    return Ok(off);
  }

  for s in txt {
    off = encode_txt_string(s, buf, off)?;
  }

  Ok(off)
}

fn encode_txt_string(s: &str, buf: &mut [u8], mut off: usize) -> Result<usize, ServiceError> {
  let len_byte_offset = off;
  if s.len() > 256 * 4 + 1
  /* If all \DDD */
  {
    return Err(ServiceError::TxtDataTooLong);
  }

  off += 1;
  let s = s.as_bytes();

  let mut i = 0;

  while i < s.len() {
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
    return Err(ServiceError::TxtDataTooLong);
  }

  buf[len_byte_offset] = l as u8;
  Ok(off)
}

#[inline]
const fn ddd_to_byte(s: &[u8]) -> u8 {
  // Convert octal \DDD to byte value
  let d1 = (s[0] - b'0') * 100;
  let d2 = (s[1] - b'0') * 10;
  let d3 = s[2] - b'0';
  d1 + d2 + d3
}

#[inline]
const fn is_ddd(s: &[u8]) -> bool {
  if s.len() < 3 {
    return false;
  }

  // Check if next three characters are digits
  s[0].is_ascii_digit() && s[1].is_ascii_digit() && s[2].is_ascii_digit()
}
