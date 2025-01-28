use std::collections::HashMap;

use smol_str::SmolStr;

mod answer;
mod message;
mod name;
mod query;
mod record;
mod record_data;
mod record_type;
mod srv;

pub use name::Name;
pub use record::{RecordHeader, RecordRef};
pub use record_data::{RecordDataRef, A, AAAA, PTR, SRV, TXT};
pub use record_type::{RecordType, UnknownRecordTypeStr};
pub use smallvec_wrapper::{OneOrMore, TinyVec};

pub(crate) use message::Header;
pub(crate) use query::Query;

const MAX_COMPRESSION_OFFSET: usize = 2 << 13;
/// See RFC 1035 section 2.3.4
const MAX_DOMAIN_NAME_WIRE_OCTETS: usize = 255;
/// This is the maximum number of compression pointers that should occur in a
/// semantically valid message. Each label in a domain name must be at least one
/// octet and is separated by a period. The root label won't be represented by a
/// compression pointer to a compression pointer, hence the -2 to exclude the
/// smallest valid root label.
///
/// It is possible to construct a valid message that has more compression pointers
/// than this, and still doesn't loop, by pointing to a previous pointer. This is
/// not something a well written implementation should ever do, so we leave them
/// to trip the maximum compression pointer check.
const MAX_COMPRESSION_POINTERS: usize = (MAX_DOMAIN_NAME_WIRE_OCTETS + 1) / 2 - 2;

const DNS_CLASS_IN: u16 = 1;

const COMPRESSION_POINTER_MASK: u16 = 0xC000;
const MESSAGE_HEADER_SIZE: usize = 12;
const QDCOUNT_OFFSET: usize = 4;
const ANCOUNT_OFFSET: usize = 6;
pub(crate) const OP_CODE_QUERY: u16 = 0;
pub(crate) const RESPONSE_CODE_NO_ERROR: u16 = 0;

struct SlicableSmolStr {
  s: SmolStr,
  start: usize,
  end: usize,
}

impl From<SmolStr> for SlicableSmolStr {
  #[inline]
  fn from(s: SmolStr) -> Self {
    Self {
      end: s.len(),
      s,
      start: 0,
    }
  }
}

impl core::borrow::Borrow<str> for SlicableSmolStr {
  #[inline]
  fn borrow(&self) -> &str {
    &self.s[self.start..self.end]
  }
}

impl AsRef<str> for SlicableSmolStr {
  #[inline]
  fn as_ref(&self) -> &str {
    &self.s[self.start..self.end]
  }
}

impl SlicableSmolStr {
  #[inline]
  fn new(s: SmolStr, start: usize, end: usize) -> Self {
    Self { s, start, end }
  }
}

impl core::ops::Deref for SlicableSmolStr {
  type Target = str;

  fn deref(&self) -> &Self::Target {
    &self.s[self.start..self.end]
  }
}

impl PartialEq for SlicableSmolStr {
  fn eq(&self, other: &Self) -> bool {
    self.s[self.start..self.end] == other.s[other.start..other.end]
  }
}

impl Eq for SlicableSmolStr {}

impl core::hash::Hash for SlicableSmolStr {
  fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
    self.s[self.start..self.end].hash(state);
  }
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum ProtoError {
  /// Domain name is not fully qualified
  #[error("domain must be fully qualified")]
  NotFqdn,
  /// Buffer is too small
  #[error("buffer size too small")]
  BufferTooSmall,
  /// Invalid RDATA
  #[error("invalid RDATA")]
  InvalidRdata,
  /// Returned when a TXT record has more than 255 bytes of data
  #[error("TXT record data is too long")]
  TxtDataTooLong,
  /// Not enough data to decode
  #[error("not enough data to decode")]
  NotEnoughData,
  /// Domain name is too long
  #[error("name exceeds maximum length {length} bytes", length = MAX_DOMAIN_NAME_WIRE_OCTETS)]
  NameTooLong,
  /// Too many pointers
  #[error("too many compression pointers")]
  TooManyPointers,
  /// Overflowing the length in the header
  #[error("overflowing the length in the header")]
  Overflow,
  /// Utf8 error
  #[error(transparent)]
  Utf8(#[from] core::str::Utf8Error),
}

/// A subset of the DNS question classes, which only contains the classes
/// that are relevant to mDNS.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
#[repr(u16)]
#[non_exhaustive]
pub enum DNSClass {
  /// Internet
  IN = 1,
  // /// Unicast response desired, as per 5.4 in RFC
  // FORCE_UNICAST_RESPONSES = 32769,
  /// Unknown DNS class
  UNKNOWN(u16),
}

impl From<DNSClass> for u16 {
  fn from(value: DNSClass) -> Self {
    match value {
      DNSClass::IN => 1,
      DNSClass::UNKNOWN(v) => v,
    }
  }
}

impl From<u16> for DNSClass {
  fn from(value: u16) -> Self {
    match value {
      1 => DNSClass::IN,
      _ => DNSClass::UNKNOWN(value),
    }
  }
}

/// Used to allow a more efficient compression map
/// to be used for internal packDomainName calls without changing the
/// signature or functionality of public API.
struct CompressionMap {
  map: HashMap<SlicableSmolStr, u16>,
}

impl CompressionMap {
  #[inline]
  fn new() -> Self {
    Self {
      map: HashMap::new(),
    }
  }

  #[inline]
  fn insert(&mut self, s: SlicableSmolStr, pos: u16) {
    self.map.insert(s, pos);
  }

  #[inline]
  fn find(&self, s: &str) -> Option<u16> {
    self.map.get(s).copied()
  }
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

// Escape byte without allocation using a fixed buffer
#[inline]
const fn escape_bytes(b: u8, buf: &mut [u8]) -> &[u8] {
  buf[0] = b'\\';
  buf[1] = b'0' + (b / 100);
  buf[2] = b'0' + ((b / 10) % 10);
  buf[3] = b'0' + (b % 10);
  buf
}

const ESCAPED_BYTE_SMALL: &[u8] = concat!(
  "\\000\\001\\002\\003\\004\\005\\006\\007\\008\\009",
  "\\010\\011\\012\\013\\014\\015\\016\\017\\018\\019",
  "\\020\\021\\022\\023\\024\\025\\026\\027\\028\\029",
  "\\030\\031"
)
.as_bytes();

const ESCAPED_BYTE_LARGE: &[u8] = concat!(
  "\\127\\128\\129",
  "\\130\\131\\132\\133\\134\\135\\136\\137\\138\\139",
  "\\140\\141\\142\\143\\144\\145\\146\\147\\148\\149",
  "\\150\\151\\152\\153\\154\\155\\156\\157\\158\\159",
  "\\160\\161\\162\\163\\164\\165\\166\\167\\168\\169",
  "\\170\\171\\172\\173\\174\\175\\176\\177\\178\\179",
  "\\180\\181\\182\\183\\184\\185\\186\\187\\188\\189",
  "\\190\\191\\192\\193\\194\\195\\196\\197\\198\\199",
  "\\200\\201\\202\\203\\204\\205\\206\\207\\208\\209",
  "\\210\\211\\212\\213\\214\\215\\216\\217\\218\\219",
  "\\220\\221\\222\\223\\224\\225\\226\\227\\228\\229",
  "\\230\\231\\232\\233\\234\\235\\236\\237\\238\\239",
  "\\240\\241\\242\\243\\244\\245\\246\\247\\248\\249",
  "\\250\\251\\252\\253\\254\\255"
)
.as_bytes();

// escapeByte returns the \DDD escaping of b which must
// satisfy b < ' ' || b > '~'.
// func escapeByte(b byte) string {
// 	if b < ' ' {
// 		return escapedByteSmall[b*4 : b*4+4]
// 	}

// 	b -= '~' + 1
// 	// The cast here is needed as b*4 may overflow byte.
// 	return escapedByteLarge[int(b)*4 : int(b)*4+4]
// }
fn escape_byte(b: u8) -> [u8; 4] {
  if b < b' ' {
    let mut data = [0; 4];
    data.copy_from_slice(&ESCAPED_BYTE_SMALL[(b * 4) as usize..(b * 4 + 4) as usize]);
    return data;
  }

  let idx = b.wrapping_sub(b'~' + 1) as usize;
  // The cast here is needed as b*4 may overflow byte.
  let mut data = [0; 4];
  data.copy_from_slice(&ESCAPED_BYTE_LARGE[idx * 4..(idx * 4 + 4)]);
  data
}
