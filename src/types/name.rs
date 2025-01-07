use std::collections::HashSet;

use smallvec_wrapper::XXLargeVec;
use smol_str::{format_smolstr, SmolStr};

use super::{CompressionMap, EncodeError, COMPRESSION_POINTER_MASK, MAX_COMPRESSION_OFFSET};

/// A name
#[derive(Debug, Default, Clone)]
pub struct Name {
  name: SmolStr,
  fqdn: bool,
}

impl PartialEq for Name {
  fn eq(&self, other: &Self) -> bool {
    self.name == other.name
  }
}

impl Eq for Name {}

impl core::hash::Hash for Name {
  fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
    self.name.hash(state);
  }
}

impl PartialOrd for Name {
  fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
    Some(self.cmp(other))
  }
}

impl Ord for Name {
  fn cmp(&self, other: &Self) -> std::cmp::Ordering {
    self.name.cmp(&other.name)
  }
}

impl From<&str> for Name {
  fn from(name: &str) -> Self {
    let fqdn = is_fqdn(name);
    Self {
      name: SmolStr::new(name),
      fqdn,
    }
  }
}

impl core::borrow::Borrow<str> for Name {
  #[inline]
  fn borrow(&self) -> &str {
    self.as_str()
  }
}

impl core::convert::AsRef<str> for Name {
  #[inline]
  fn as_ref(&self) -> &str {
    self.as_str()
  }
}

impl core::ops::Deref for Name {
  type Target = str;

  #[inline]
  fn deref(&self) -> &Self::Target {
    self.as_str()
  }
}

impl core::fmt::Display for Name {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "{}", self.name)
  }
}

impl Name {
  /// Appends a name to the current name in FQDN format.
  pub fn append_fqdn(&self, other: &str) -> Self {
    let name = format_smolstr!("{}.{}.", self.name.as_str().trim_matches('.'), other.trim_matches('.'));
    Self {
      name,
      fqdn: true,
    }
  }

  /// Appends a name to the current name
  pub fn append(&self, other: &Name) -> Self {
    let name = format_smolstr!("{}{}", self.name.as_str(), other.name.as_str());
    Self {
      fqdn: is_fqdn(name.as_str()),
      name,
    }
  }

  /// Returns `true` if the name is fully qualified.
  #[inline]
  pub const fn is_fqdn(&self) -> bool {
    self.fqdn
  }

  /// Returns a string representation of the name.
  #[inline]
  pub fn as_str(&self) -> &str {
    &self.name
  }

  #[inline]
  pub(crate) const fn from_components(name: SmolStr, fqdn: bool) -> Self {
    Self { name, fqdn }
  }

  #[inline]
  pub(crate) fn local() -> Self {
    Self {
      name: SmolStr::new("local"),
      fqdn: false,
    }
  }

  #[inline]
  pub(crate) fn local_fqdn() -> Self {
    Self {
      name: SmolStr::new("local."),
      fqdn: true,
    }
  }

  pub(super) fn encoded_len(&self, off: usize, cmap: Option<&mut HashSet<SmolStr>>) -> usize {
    if self.name.is_empty() || self.name.eq(".") {
      return 1;
    }

    let escaped = self.name.contains('\\');

    if let Some(cmap) = cmap {
      if off < MAX_COMPRESSION_OFFSET {
        // compression_len_search will insert the entry into the compression
        // map if it doesn't contain it.
        if let Some(l) = compression_len_search(cmap, &self.name, off) {
          if escaped {
            return escaped_name_len(&self.name[..l]) + 2;
          }

          return l + 2;
        }
      }
    }

    if escaped {
      return escaped_name_len(&self.name) + 1;
    }

    self.name.len() + 1
  }

  pub(super) fn encode(
    &self,
    buf: &mut [u8],
    off: usize,
    cmap: &mut Option<CompressionMap>,
  ) -> Result<usize, EncodeError> {
    let s = &self.name;
    if s.is_empty() {
      return Ok(off);
    }

    if !self.fqdn {
      return Err(EncodeError::NotFqdn);
    }

    let mut pointer: i32 = -1;
    let mut off = off;
    let mut begin = 0;
    let mut comp_begin = 0;
    let mut comp_off = 0;
    let mut bs: Option<XXLargeVec<u8>> = None;
    let mut was_dot = false;
    let ls = s.len();

    let mut i = 0;
    while i < ls {
      let c = if let Some(ref bs) = bs {
        bs[i]
      } else {
        s.as_bytes()[i]
      };

      match c {
        b'\\' => {
          if off + 1 > buf.len() {
            return Err(EncodeError::BufferTooSmall);
          }

          if bs.is_none() {
            let mut bbuf = XXLargeVec::with_capacity(ls);
            bbuf.extend_from_slice(s.as_bytes());
            bs = Some(bbuf);
          }

          let bs = bs.as_mut().unwrap();

          if is_ddd(&s[i + 1..]) {
            bs[i] = ddd_to_byte(&bs[i + 1..]);
            bs.copy_within(i + 4..ls, i + 1);
            comp_off += 3;
            i += 1;
          } else {
            bs.copy_within(i + 1..ls, i);
            comp_off += 1;
            i += 1;
          }

          was_dot = false;
        }
        b'.' => {
          if i == 0 && ls > 1 {
            return Err(EncodeError::InvalidRdata);
          }

          if was_dot {
            return Err(EncodeError::InvalidRdata);
          }
          was_dot = true;

          let label_len = i - begin;
          if label_len >= 1 << 6 {
            return Err(EncodeError::InvalidRdata);
          }

          if off + 1 + label_len > buf.len() {
            return Err(EncodeError::BufferTooSmall);
          }

          let bs_ref = bs.as_ref().map(|v| &v[..]);
          if let Some(cmap) = cmap {
            if !is_root_label(s, bs_ref, begin, ls) {
              if let Some(p) = cmap.find(&s[comp_begin..]) {
                pointer = p as i32; // Where to point to
                break;
              } else if off < MAX_COMPRESSION_OFFSET {
                // Only offsets smaller than MAX_COMPRESSION_OFFSET can be used.
                cmap.insert(SmolStr::new(&s[comp_begin..]), off as u16);
              }
            }
          }

          buf[off] = label_len as u8;

          if let Some(ref bs) = bs {
            buf[off + 1..off + 1 + label_len].copy_from_slice(&bs[begin..i]);
          } else {
            buf[off + 1..off + 1 + label_len].copy_from_slice(&s.as_bytes()[begin..i]);
          }

          off += 1 + label_len;
          begin = i + 1;
          comp_begin = begin + comp_off;
        }
        _ => was_dot = false,
      }
      i += 1;
    }

    let bs_ref = bs.as_ref().map(|v| &v[..]);
    if is_root_label(s, bs_ref, 0, ls) {
      return Ok(off);
    }

    if pointer != -1 {
      let ptr = (pointer as u16) ^ COMPRESSION_POINTER_MASK;
      buf[off..off + 2].copy_from_slice(&ptr.to_be_bytes());
      return Ok(off + 2);
    }

    if off < buf.len() {
      buf[off] = 0;
    }

    Ok(off + 1)
  }
}

fn escaped_name_len(s: &str) -> usize {
  let bytes = s.as_bytes();
  let mut name_len = s.len();
  let mut i = 0;

  while i < bytes.len() {
    if bytes[i] != b'\\' {
      i += 1;
      continue;
    }

    // Check if we have enough characters left for a potential DDD sequence
    if i + 1 < bytes.len() && is_ddd(&s[i + 1..]) {
      name_len -= 3;
      i += 4; // Skip the backslash and three digits
    } else {
      name_len -= 1;
      i += 2; // Skip the backslash and the escaped character
    }
  }

  name_len
}

fn compression_len_search(c: &mut HashSet<SmolStr>, s: &str, msg_off: usize) -> Option<usize> {
  let mut off = 0;
  let mut end = false;

  while !end {
    // Create SmolStr from the substring
    let substr = SmolStr::new(&s[off..]);

    if c.contains(&substr) {
      return Some(off);
    }

    if msg_off + off < MAX_COMPRESSION_OFFSET {
      c.insert(substr);
    }

    let next = next_label(s, off);
    off = next.0;
    end = next.1;
  }

  None
}

/// Returns the index of the start of the next label in the string s starting at offset.
/// A negative offset will cause a panic. The bool end is true when the end of the
/// string has been reached. Also see prev_label.
const fn next_label(s: &str, offset: usize) -> (usize, bool) {
  if s.is_empty() {
    return (0, true);
  }

  let bytes = s.as_bytes();
  let mut i = offset;

  while i < bytes.len().saturating_sub(1) {
    if bytes[i] != b'.' {
      i += 1;
      continue;
    }

    let mut j = i as isize - 1;
    while j >= 0 && bytes[j as usize] == b'\\' {
      j -= 1;
    }

    if ((i as isize - 1) - j) % 2 == 0 {
      i += 1;
      continue;
    }

    return (i + 1, false);
  }

  (i + 1, true)
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
const fn is_ddd(s: &str) -> bool {
  if s.len() < 3 {
    return false;
  }

  let bytes = s.as_bytes();
  // Check if next three characters are digits
  bytes[0].is_ascii_digit() && bytes[1].is_ascii_digit() && bytes[2].is_ascii_digit()
}

/// Checks if a domain name is fully qualified (ends with a dot)
#[inline]
fn is_fqdn(s: &str) -> bool {
  let len = s.len();
  if s.is_empty() || !s.ends_with('.') {
    return false;
  }

  let s = &s[..len - 1];

  if s.is_empty() || !s.ends_with('\\') {
    return true;
  }

  // Count backslashes at the end
  let last_non_backslash = s.rfind(|c| c != '\\').unwrap_or(0);

  (len - last_non_backslash) % 2 == 0
}

/// Checks if the string from off to end is the root label "."
#[inline]
fn is_root_label(s: &str, bs: Option<&[u8]>, off: usize, end: usize) -> bool {
  match bs {
    None => s[off..end].eq("."),
    Some(bytes) => end - off == 1 && bytes[off] == b'.',
  }
}
