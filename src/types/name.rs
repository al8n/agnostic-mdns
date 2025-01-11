use std::{
  collections::HashSet,
  net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use smallvec_wrapper::XXLargeVec;
use smol_str::{format_smolstr, SmolStr};

const IPV4_LABEL_MAX_LEN: usize = 29; // xxx.xxx.xxx.xxx.in-addr.arpa.
const IPV6_LABEL_MAX_LEN: usize = 73; // 32 hex digits + 32 dots + 9 chars suffix

use super::{
  ddd_to_byte, escape_byte, is_ddd, CompressionMap, ProtoError, SlicableSmolStr,
  COMPRESSION_POINTER_MASK, MAX_COMPRESSION_OFFSET, MAX_COMPRESSION_POINTERS,
  MAX_DOMAIN_NAME_WIRE_OCTETS,
};

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

impl From<SmolStr> for Name {
  fn from(name: SmolStr) -> Self {
    match name.parse::<IpAddr>() {
      Ok(ip) => ip.into(),
      Err(_) => Self {
        fqdn: is_fqdn(&name),
        name,
      },
    }
  }
}

impl From<&str> for Name {
  fn from(name: &str) -> Self {
    match name.parse::<IpAddr>() {
      Ok(ip) => ip.into(),
      Err(_) => Self {
        name: SmolStr::new(name),
        fqdn: is_fqdn(name),
      },
    }
  }
}

impl From<IpAddr> for Name {
  fn from(value: IpAddr) -> Self {
    match value {
      IpAddr::V4(ip) => ip.into(),
      IpAddr::V6(ip) => ip.into(),
    }
  }
}

impl From<Ipv4Addr> for Name {
  fn from(ip: Ipv4Addr) -> Self {
    let mut buf = [0u8; IPV4_LABEL_MAX_LEN];
    let mut pos = 0;

    // Get octets directly as array
    let octets = ip.octets();

    // Write in reverse
    for &octet in octets.iter().rev() {
      let len = write_decimal(octet, &mut buf[pos..]);
      pos += len;
      buf[pos] = b'.';
      pos += 1;
    }

    // Write suffix
    let suffix = b"in-addr.arpa.";
    buf[pos..pos + suffix.len()].copy_from_slice(suffix);
    pos += suffix.len();

    // Safe as we're writing valid ASCII
    Self {
      name: SmolStr::new(std::str::from_utf8(&buf[..pos]).unwrap()),
      fqdn: true,
    }
  }
}

impl From<Ipv6Addr> for Name {
  fn from(ip: Ipv6Addr) -> Self {
    let mut buf = [0u8; IPV6_LABEL_MAX_LEN];
    let mut pos = 0;

    // Get segments directly as array
    let segments = ip.segments();

    // Process each segment in reverse
    for &segment in segments.iter().rev() {
      // Write 4 hex digits in reverse
      let d4 = segment & 0xF;
      let d3 = (segment >> 4) & 0xF;
      let d2 = (segment >> 8) & 0xF;
      let d1 = (segment >> 12) & 0xF;

      // Write in reverse order with dots
      for &d in &[d4, d3, d2, d1] {
        buf[pos] = if d < 10 {
          b'0' + d as u8
        } else {
          b'a' + (d as u8 - 10)
        };
        pos += 1;
        buf[pos] = b'.';
        pos += 1;
      }
    }

    // Write suffix
    let suffix = b"ip6.arpa.";
    buf[pos..pos + suffix.len()].copy_from_slice(suffix);
    pos += suffix.len();

    // Safe as we're writing valid ASCII
    Self {
      name: SmolStr::new(std::str::from_utf8(&buf[..pos]).unwrap()),
      fqdn: true,
    }
  }
}

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

  /// Appends a name to the current name
  pub(crate) fn append(&self, other: &Name) -> Self {
    let name = format_smolstr!("{}{}", self.name.as_str(), other.name.as_str());
    Self {
      fqdn: is_fqdn(name.as_str()),
      name,
    }
  }

  /// Appends a name to the current name in FQDN format.
  pub(crate) fn append_fqdn(&self, other: &str) -> Self {
    let name = format_smolstr!(
      "{}.{}.",
      self.name.as_str().trim_matches('.'),
      other.trim_matches('.')
    );
    Self { name, fqdn: true }
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

  pub(super) fn encoded_len(
    &self,
    off: usize,
    cmap: &mut Option<HashSet<SlicableSmolStr>>,
    compress: bool,
  ) -> usize {
    if self.name.is_empty() || self.name.eq(".") {
      return 1;
    }

    let escaped = self.name.contains('\\');

    if let Some(cmap) = cmap {
      if off < MAX_COMPRESSION_OFFSET || compress {
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

  pub(super) fn decode(msg: &[u8], mut off: usize) -> Result<(Self, usize), ProtoError> {
    // Start with a smaller capacity and let it grow as needed
    let mut s = InlineDomain::with_capacity(23); // Most domain names are shorter than 32 bytes
    let mut off1 = 0;
    let lenmsg = msg.len();
    let mut budget = MAX_DOMAIN_NAME_WIRE_OCTETS as isize;
    let mut ptr = 0; // number of pointers followed

    loop {
      if off >= lenmsg {
        return Err(ProtoError::BufferTooSmall);
      }

      let c = msg[off];
      off += 1;

      match c & 0xC0 {
        0x00 => {
          if c == 0x00 {
            // end of name
            break;
          }

          // literal string
          let label_len = c as usize;
          if off + label_len > lenmsg {
            return Err(ProtoError::BufferTooSmall);
          }

          budget -= (label_len as isize) + 1; // +1 for the label separator
          if budget <= 0 {
            return Err(ProtoError::LongDomain);
          }

          for &b in msg[off..off + label_len].iter() {
            if is_domain_name_label_special(b) {
              s.extend_from_slice(&[b'\\', b]);
            } else if !(b' '..=b'~').contains(&b) {
              s.extend_from_slice(&escape_byte(b));
            } else {
              s.push(b);
            }
          }
          s.push(b'.');
          off += label_len;
        }
        0xC0 => {
          // pointer to somewhere else in msg.
          // remember location after first ptr,
          // since that's how many bytes we consumed.
          // also, don't follow too many pointers --
          // maybe there's a loop.
          if off >= lenmsg {
            return Err(ProtoError::NotEnoughData);
          }

          let c1 = msg[off];
          off += 1;

          if ptr == 0 {
            off1 = off;
          }

          ptr += 1;
          if ptr > MAX_COMPRESSION_POINTERS {
            return Err(ProtoError::TooManyPointers);
          }

          // pointer should guarantee that it advances and points forwards at least
          // but the condition on previous three lines guarantees that it's
          // at least loop-free
          off = ((c as usize ^ 0xC0) << 8) | c1 as usize;
        }
        _ => return Err(ProtoError::InvalidRdata),
      }
    }

    if ptr == 0 {
      off1 = off;
    }

    if s.is_empty() {
      Ok((Name::from("."), off1))
    } else {
      // SAFETY: We only added ASCII bytes and properly escaped non-ASCII
      let s = core::str::from_utf8(s.as_slice()).expect("we only added ASCII bytes");
      Ok((
        Self {
          name: SmolStr::new(s),
          fqdn: is_fqdn(s),
        },
        off1,
      ))
    }
  }

  pub(super) fn encode(
    &self,
    buf: &mut [u8],
    off: usize,
    cmap: &mut Option<CompressionMap>,
    compress: bool,
  ) -> Result<usize, ProtoError> {
    let s = &self.name;
    if s.is_empty() {
      return Ok(off);
    }

    if !self.fqdn {
      return Err(ProtoError::NotFqdn);
    }

    // Compression
    let mut pointer: i32 = -1;
    let mut off = off;
    let mut begin = 0;
    let mut comp_begin = 0;
    let mut comp_off = 0;
    let mut bs = XXLargeVec::new();
    let mut was_dot = false;
    let mut ls = s.len();

    let mut i = 0;
    while i < ls {
      let c = if !bs.is_empty() {
        bs[i]
      } else {
        s.as_bytes()[i]
      };

      match c {
        b'\\' => {
          if off + 1 > buf.len() {
            return Err(ProtoError::BufferTooSmall);
          }

          if bs.is_empty() {
            bs.extend_from_slice(s.as_bytes());
          }

          if is_ddd(&s.as_bytes()[i + 1..]) {
            bs[i] = ddd_to_byte(&bs[i + 1..]);
            bs.copy_within(i + 4..ls, i + 1);
            comp_off += 3;
            ls -= 3;
          } else {
            bs.copy_within(i + 1..ls, i);
            comp_off += 1;
            ls -= 1;
          }

          was_dot = false;
        }
        b'.' => {
          if i == 0 && s.len() > 1 {
            return Err(ProtoError::InvalidRdata);
          }

          if was_dot {
            return Err(ProtoError::InvalidRdata);
          }
          was_dot = true;

          let label_len = i - begin;
          if label_len >= 1 << 6 {
            // top two bits of length must be clear
            return Err(ProtoError::InvalidRdata);
          }

          // off can already (we're in a loop) be bigger than len(msg)
          // this happens when a name isn't fully qualified
          if off + 1 + label_len > buf.len() {
            return Err(ProtoError::BufferTooSmall);
          }

          // Don't try to compress '.'
          // We should only compress when compress is true, but we should also still pick
          // up names that can be used for *future* compression(s).
          if let Some(cmap) = cmap {
            if !is_root_label(s, &bs, begin, ls) {
              if let Some(p) = cmap.find(&s[comp_begin..]) {
                // The first hit is the longest matching dname
                // keep the pointer offset we get back and store
                // the offset of the current name, because that's
                // where we need to insert the pointer later

                // If compress is true, we're allowed to compress this dname
                if compress {
                  pointer = p as i32; // Where to point to
                  break;
                }
              } else if off < MAX_COMPRESSION_OFFSET {
                // Only offsets smaller than MAX_COMPRESSION_OFFSET can be used.
                cmap.insert(
                  SlicableSmolStr::new(s.clone(), comp_begin, s.len()),
                  off as u16,
                );
              }
            }
          }

          // The following is covered by the length check above.
          buf[off] = label_len as u8;

          if !bs.is_empty() {
            buf[off + 1..off + 1 + (i - begin)].copy_from_slice(&bs[begin..i]);
          } else {
            buf[off + 1..off + 1 + (i - begin)].copy_from_slice(&s.as_bytes()[begin..i]);
          }

          off += 1 + label_len;
          begin = i + 1;
          comp_begin = begin + comp_off;
        }
        _ => was_dot = false,
      }
      i += 1;
    }

    // Root label is special
    if is_root_label(s, &bs, 0, ls) {
      return Ok(off);
    }

    // If we did compression and we find something add the pointer here
    if pointer != -1 {
      // We have two bytes (14 bits) to put the pointer in
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
    if i + 1 < bytes.len() && is_ddd(&s.as_bytes()[i + 1..]) {
      name_len -= 3;
      i += 4; // Skip the backslash and three digits
    } else {
      name_len -= 1;
      i += 2; // Skip the backslash and the escaped character
    }
  }

  name_len
}

fn compression_len_search(
  c: &mut HashSet<SlicableSmolStr>,
  s: &SmolStr,
  msg_off: usize,
) -> Option<usize> {
  let mut off = 0;
  let mut end = false;
  let len = s.len();

  while !end {
    // Create SmolStr from the substring
    let substr = SlicableSmolStr::new(s.clone(), off, len);

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
fn is_root_label(s: &str, bs: &[u8], off: usize, end: usize) -> bool {
  match bs.is_empty() {
    true => s[off..end].eq("."),
    false => end - off == 1 && bs[off] == b'.',
  }
}

// Returns true if
// a domain name label byte should be prefixed
// with an escaping backslash.
#[inline]
const fn is_domain_name_label_special(b: u8) -> bool {
  matches!(
    b,
    b'.' | b' ' | b'\'' | b'@' | b';' | b'(' | b')' | b'"' | b'\\'
  )
}

#[inline]
fn write_decimal(mut num: u8, buf: &mut [u8]) -> usize {
  if num == 0 {
    buf[0] = b'0';
    return 1;
  }

  let mut temp = [0u8; 3];
  let mut pos = 0;

  while num > 0 {
    temp[pos] = b'0' + (num % 10);
    num /= 10;
    pos += 1;
  }

  // Write in reverse to get correct order
  for i in 0..pos {
    buf[i] = temp[pos - 1 - i];
  }
  pos
}

smallvec_wrapper::smallvec_wrapper!(
  InlineDomain<T>([T; 23]);
);

#[cfg(test)]
mod tests {
  use std::collections::HashMap;

  use super::*;

  const MAX_PRINTABLE_LABEL: &str =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789x";

  #[test]
  fn from_ipv4() {
    let ip = Ipv4Addr::new(192, 168, 0, 42);
    let name = Name::from(IpAddr::V4(ip));
    assert_eq!(name.as_ref(), "42.0.168.192.in-addr.arpa.");
  }

  #[test]
  fn from_ipv6() {
    let ip = Ipv6Addr::new(0x2620, 0, 0x1000, 0x1900, 0xb0c2, 0xd0b2, 0xc411, 0x18bc);
    let name = Name::from(IpAddr::V6(ip));
    assert_eq!(
      name.as_str(),
      "c.b.8.1.1.1.4.c.2.b.0.d.2.c.0.b.0.0.9.1.0.0.0.1.0.0.0.0.0.2.6.2.ip6.arpa."
    );
  }

  #[test]
  fn empty_domain() {
    let input = [0];
    let (name, _) = Name::decode(&input, 0).unwrap();
    assert_eq!(name.as_str(), ".");
  }

  #[test]
  fn long_label() {
    let s = [b"?".as_slice(), MAX_PRINTABLE_LABEL.as_bytes(), b"\x00"].concat();
    let exp = [MAX_PRINTABLE_LABEL, "."].concat();
    let (name, _) = Name::decode(&s, 0).unwrap();
    assert_eq!(name.as_str(), exp);
  }

  #[test]
  fn unpritable_lable() {
    let s = [
      63, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
      25, 26, 27, 28, 29, 30, 31, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
      19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 0,
    ];
    let exp = [
      92u8, 48, 48, 48, 92, 48, 48, 49, 92, 48, 48, 50, 92, 48, 48, 51, 92, 48, 48, 52, 92, 48, 48,
      53, 92, 48, 48, 54, 92, 48, 48, 55, 92, 48, 48, 56, 92, 48, 48, 57, 92, 48, 49, 48, 92, 48,
      49, 49, 92, 48, 49, 50, 92, 48, 49, 51, 92, 48, 49, 52, 92, 48, 49, 53, 92, 48, 49, 54, 92,
      48, 49, 55, 92, 48, 49, 56, 92, 48, 49, 57, 92, 48, 50, 48, 92, 48, 50, 49, 92, 48, 50, 50,
      92, 48, 50, 51, 92, 48, 50, 52, 92, 48, 50, 53, 92, 48, 50, 54, 92, 48, 50, 55, 92, 48, 50,
      56, 92, 48, 50, 57, 92, 48, 51, 48, 92, 48, 51, 49, 92, 48, 48, 48, 92, 48, 48, 49, 92, 48,
      48, 50, 92, 48, 48, 51, 92, 48, 48, 52, 92, 48, 48, 53, 92, 48, 48, 54, 92, 48, 48, 55, 92,
      48, 48, 56, 92, 48, 48, 57, 92, 48, 49, 48, 92, 48, 49, 49, 92, 48, 49, 50, 92, 48, 49, 51,
      92, 48, 49, 52, 92, 48, 49, 53, 92, 48, 49, 54, 92, 48, 49, 55, 92, 48, 49, 56, 92, 48, 49,
      57, 92, 48, 50, 48, 92, 48, 50, 49, 92, 48, 50, 50, 92, 48, 50, 51, 92, 48, 50, 52, 92, 48,
      50, 53, 92, 48, 50, 54, 92, 48, 50, 55, 92, 48, 50, 56, 92, 48, 50, 57, 92, 48, 51, 48, 46,
    ];

    let (name, _) = Name::decode(&s, 0).unwrap();
    assert_eq!(name.as_str(), core::str::from_utf8(&exp).unwrap());
  }

  #[test]
  fn long_domain() {
    let input = b"5abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVW1abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVW1abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVW1abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVW\x00";

    let exp = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0.abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVW.abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVW.abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVW.abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVW.";

    let name = Name::decode(input, 0).unwrap().0;
    assert_eq!(name.as_str(), exp);
  }

  #[test]
  fn compression_pointer() {
    let input = [
      3, b'f', b'o', b'o', 5, 3, b'c', b'o', b'm', 0, 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
      0xC0, 5,
    ];

    let exp = "foo.\\003com\\000.example.com.";
    let (name, _) = Name::decode(&input, 0).unwrap();
    assert_eq!(name.as_str(), exp);
  }

  #[test]
  fn too_long_domain() {
    let input = b"6xabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVW1abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVW1abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVW1abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVW";

    let name = Name::decode(input, 0).unwrap_err();
    assert_eq!(name, ProtoError::LongDomain);
  }

  #[test]
  fn too_long_pointer() {
    let input = [
      // 11 length values, first to last
      40, 37, 34, 31, 28, 25, 22, 19, 16, 13, 0, // 12 filler values
      120, 120, 120, 120, 120, 120, 120, 120, 120, 120, 120, 120,
      // 10 pointers, last to first
      192, 10, 192, 9, 192, 8, 192, 7, 192, 6, 192, 5, 192, 4, 192, 3, 192, 2, 192, 1,
    ];

    let err = Name::decode(&input, 0).unwrap_err();
    assert_eq!(err, ProtoError::LongDomain);
  }

  #[test]
  fn long_by_pointer() {
    let input = [
      // 11 length values, first to last
      37, 34, 31, 28, 25, 22, 19, 16, 13, 10, 0, // 9 filler values
      120, 120, 120, 120, 120, 120, 120, 120, 120, // 10 pointers, last to first
      192, 10, 192, 9, 192, 8, 192, 7, 192, 6, 192, 5, 192, 4, 192, 3, 192, 2, 192, 1,
    ];
    let output = concat!(
      "\\\"\\031\\028\\025\\022\\019\\016\\013\\010\\000xxxxxxxxx",
      "\\192\\010\\192\\009\\192\\008\\192\\007\\192\\006\\192\\005\\192\\004\\192\\003\\192\\002.",
      "\\031\\028\\025\\022\\019\\016\\013\\010\\000xxxxxxxxx",
      "\\192\\010\\192\\009\\192\\008\\192\\007\\192\\006\\192\\005\\192\\004\\192\\003.",
      "\\028\\025\\022\\019\\016\\013\\010\\000xxxxxxxxx",
      "\\192\\010\\192\\009\\192\\008\\192\\007\\192\\006\\192\\005\\192\\004.",
      "\\025\\022\\019\\016\\013\\010\\000xxxxxxxxx",
      "\\192\\010\\192\\009\\192\\008\\192\\007\\192\\006\\192\\005.",
      "\\022\\019\\016\\013\\010\\000xxxxxxxxx\\192\\010\\192\\009\\192\\008\\192\\007\\192\\006.",
      "\\019\\016\\013\\010\\000xxxxxxxxx\\192\\010\\192\\009\\192\\008\\192\\007.",
      "\\016\\013\\010\\000xxxxxxxxx\\192\\010\\192\\009\\192\\008.",
      "\\013\\010\\000xxxxxxxxx\\192\\010\\192\\009.",
      "\\010\\000xxxxxxxxx\\192\\010.",
      "\\000xxxxxxxxx."
    );

    let (name, _) = Name::decode(&input, 0).unwrap();
    assert_eq!(name.as_str(), output);
  }

  #[test]
  fn truncated_name() {
    let input = [7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3];
    let err = Name::decode(&input, 0).unwrap_err();
    assert_eq!(err, ProtoError::BufferTooSmall);
  }

  #[test]
  fn non_absolute_name() {
    let input = [
      7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm',
    ];
    let err = Name::decode(&input, 0).unwrap_err();
    assert_eq!(err, ProtoError::BufferTooSmall);
  }

  #[test]
  fn compression_pointer_cycle_too_many() {
    let input = [0xC0, 0x00];
    let err = Name::decode(&input, 0).unwrap_err();
    assert_eq!(err, ProtoError::TooManyPointers);
  }

  #[test]
  fn compression_pointer_cycle_too_long() {
    let input = [
      3, b'f', b'o', b'o', 3, b'b', b'a', b'r', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0xC0,
      0x04,
    ];
    let err = Name::decode(&input, 0).unwrap_err();
    assert_eq!(err, ProtoError::LongDomain);
  }

  #[test]
  fn forward_pointer() {
    let input = [2, 0xC0, 0xFF, 0xC0, 0x01];
    let err = Name::decode(&input, 0).unwrap_err();
    assert_eq!(err, ProtoError::BufferTooSmall);
  }

  #[test]
  fn reserved_compression_pointer_0b10() {
    let input = [7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x80];
    let err = Name::decode(&input, 0).unwrap_err();
    assert_eq!(err, ProtoError::InvalidRdata);
  }

  #[test]
  fn reserved_compression_pointer_0b01() {
    let input = [7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x40];
    let err = Name::decode(&input, 0).unwrap_err();
    assert_eq!(err, ProtoError::InvalidRdata);
  }

  #[test]
  fn encode_name_compression_map() {
    let mut expected = HashMap::new();
    expected.insert("www\\.this.is.\\131an.example.org.".to_string(), ());
    expected.insert("is.\\131an.example.org.".to_string(), ());
    expected.insert("\\131an.example.org.".to_string(), ());
    expected.insert("example.org.".to_string(), ());
    expected.insert("org.".to_string(), ());

    let mut msg = vec![0u8; 256];
    for compress in [true, false] {
      let mut compression = Some(CompressionMap::new());
      let name = Name::from("www\\.this.is.\\131an.example.org.");
      let result = name.encode(&mut msg, 0, &mut compression, compress);
      assert!(
        result.is_ok(),
        "compress: {compress}, encode name failed: {:?}",
        result.err()
      );
      assert!(
        compression_maps_equal(&expected, compression.as_ref().unwrap()),
        "expected compression maps to be equal\n{}",
        compression_maps_difference(&expected, compression.as_ref().unwrap())
      );
    }
  }

  fn compression_maps_equal(expected: &HashMap<String, ()>, actual: &CompressionMap) -> bool {
    if expected.len() != actual.map.len() {
      return false;
    }
    expected.keys().all(|k| actual.map.contains_key(k.as_str()))
  }

  fn compression_maps_difference(
    expected: &HashMap<String, ()>,
    actual: &CompressionMap,
  ) -> String {
    let mut diff = String::new();

    for k in expected.keys() {
      if !actual.map.contains_key(k.as_str()) {
        diff.push_str(&format!("- {}\n", k));
      }
    }

    for k in actual.map.keys() {
      if !expected.contains_key(k.as_ref()) {
        diff.push_str(&format!("+ {}\n", k.as_ref()));
      }
    }

    diff
  }
}
