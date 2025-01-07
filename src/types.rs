use std::{
  collections::HashMap,
  net::{Ipv4Addr, Ipv6Addr},
  str::FromStr,
};

use smol_str::SmolStr;

mod answer;
mod srv;
mod name;
mod message;
mod query;

pub use name::Name;
pub use srv::SRV;
pub(crate) use answer::Answer;
pub(crate) use message::Message;
pub(crate) use query::Query;
use triomphe::Arc;

#[derive(Debug, thiserror::Error)]
pub enum EncodeError {
  /// Domain name is not fully qualified
  #[error("domain must be fully qualified")]
  NotFqdn,
  /// Buffer is too small
  #[error("buffer size too small")]
  BufferTooSmall,
  /// Invalid RDATA
  #[error("invalid RDATA")]
  InvalidRdata,
}

#[derive(Debug, thiserror::Error)]
pub enum DecodeError {

}

// pub(crate) struct MessageHeader {
//   id: u16,
//   bits: u16,
//   qdcount: u16,
//   ancount: u16,
//   arcount: u16,
// }

#[derive(Debug, Clone, PartialEq, Eq, Hash, thiserror::Error)]
#[error("unknown record type string: {0}")]
pub struct UnknownRecordTypeStr(pub SmolStr);

/// A subset of the DNS record types, which only continas the types that
/// are relevant to mDNS.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
#[repr(u16)]
#[non_exhaustive]
#[allow(clippy::upper_case_acronyms)]
pub enum RecordType {
  /// [RFC 1035](https://tools.ietf.org/html/rfc1035) IPv4 Address record
  A = 1,
  /// [RFC 3596](https://tools.ietf.org/html/rfc3596) IPv6 address record
  AAAA = 28,
  /// [RFC 1035](https://tools.ietf.org/html/rfc1035) All cached records, aka ANY
  ANY = 255,
  /// [RFC 1035](https://tools.ietf.org/html/rfc1035) Pointer record
  PTR = 12,
  /// [RFC 2782](https://tools.ietf.org/html/rfc2782) Service locator
  SRV = 33,
  /// [RFC 1035](https://tools.ietf.org/html/rfc1035) Text record
  TXT = 16,
}

impl TryFrom<&str> for RecordType {
  type Error = UnknownRecordTypeStr;

  #[inline]
  fn try_from(value: &str) -> Result<Self, Self::Error> {
    Ok(match value.trim() {
      "A" | "a" => RecordType::A,
      "AAAA" | "aaaa" => RecordType::AAAA,
      "ANY" | "any" => RecordType::ANY,
      "PTR" | "ptr" => RecordType::PTR,
      "SRV" | "srv" => RecordType::SRV,
      "TXT" | "txt" => RecordType::TXT,
      _ => return Err(UnknownRecordTypeStr(value.into())),
    })
  }
}

impl FromStr for RecordType {
  type Err = UnknownRecordTypeStr;

  #[inline]
  fn from_str(s: &str) -> Result<Self, Self::Err> {
    RecordType::try_from(s)
  }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, thiserror::Error)]
#[error("unknown record type: {0}")]
pub struct UnknownRecordType(pub u16);

impl TryFrom<u16> for RecordType {
  type Error = UnknownRecordType;

  #[inline]
  fn try_from(value: u16) -> Result<Self, Self::Error> {
    Ok(match value {
      1 => Self::A,
      28 => Self::AAAA,
      255 => Self::ANY,
      12 => Self::PTR,
      33 => Self::SRV,
      16 => Self::TXT,
      _ => return Err(UnknownRecordType(value)),
    })
  }
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
}

/// The header all mDNS resource records share.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RecordHeader {
  name: Name,
  ty: RecordType,
  class: DNSClass,
  ttl: u32,
}

impl RecordHeader {
  /// Returns the name of the record.
  #[inline]
  pub const fn name(&self) -> &Name {
    &self.name
  }

  /// Returns the type of the record.
  #[inline]
  pub const fn ty(&self) -> RecordType {
    self.ty
  }

  /// Returns the class of the record.
  #[inline]
  pub const fn class(&self) -> DNSClass {
    self.class
  }

  /// Returns the time-to-live of the record.
  #[inline]
  pub const fn ttl(&self) -> u32 {
    self.ttl
  }
}

/// The data of an mDNS resource record.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RecordData {
  /// ```text
  /// -- RFC 1035 -- Domain Implementation and Specification    November 1987
  ///
  /// 3.4. Internet specific RRs
  ///
  /// 3.4.1. A RDATA format
  ///
  ///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  ///     |                    ADDRESS                    |
  ///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  ///
  /// where:
  ///
  /// ADDRESS         A 32 bit Internet address.
  ///
  /// Hosts that have multiple Internet addresses will have multiple A
  /// records.
  ///
  /// A records cause no additional section processing.  The RDATA section of
  /// an A line in a Zone File is an Internet address expressed as four
  /// decimal numbers separated by dots without any embedded spaces (e.g.,
  /// "10.2.0.52" or "192.0.5.6").
  /// ```
  A(Ipv4Addr),
  /// ```text
  /// -- RFC 1886 -- IPv6 DNS Extensions              December 1995
  ///
  /// 2.2 AAAA data format
  ///
  ///    A 128 bit IPv6 address is encoded in the data portion of an AAAA
  ///    resource record in network byte order (high-order byte first).
  /// ```
  AAAA(Ipv6Addr),
  /// ```text
  /// 3.3.12. PTR RDATA format
  ///
  ///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  ///     /                   PTRDNAME                    /
  ///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  ///
  /// where:
  ///
  /// PTRDNAME        A <domain-name> which points to some location in the
  ///                 domain name space.
  ///
  /// PTR records cause no additional section processing.  These RRs are used
  /// in special domains to point to some other location in the domain space.
  /// These records are simple data, and don't imply any special processing
  /// similar to that performed by CNAME, which identifies aliases.  See the
  /// description of the IN-ADDR.ARPA domain for an example.
  /// ```
  PTR(Name),
  /// ```text
  /// RFC 2782                       DNS SRV RR                  February 2000
  ///
  /// The format of the SRV RR
  ///
  ///  _Service._Proto.Name TTL Class SRV Priority Weight Port Target
  /// ```
  SRV(SRV),
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
  TXT(Arc<[SmolStr]>),
}

impl RecordData {
  /// Returns the type of the record data.
  #[inline]
  pub const fn ty(&self) -> RecordType {
    match self {
      Self::A(_) => RecordType::A,
      Self::AAAA(_) => RecordType::AAAA,
      Self::PTR(_) => RecordType::PTR,
      Self::SRV(_) => RecordType::SRV,
      Self::TXT(_) => RecordType::TXT,
    }
  }
}

/// The mDNS resource record.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Record {
  header: RecordHeader,
  data: RecordData,
}

impl Record {
  /// Creates a new mDNS resource record.
  pub fn from_rdata(name: Name, ttl: u32, data: RecordData) -> Self {
    Self {
      header: RecordHeader {
        name,
        ty: data.ty(),
        class: DNSClass::IN,
        ttl,
      },
      data,
    }
  }

  /// Consumes the record and returns the [`RecordHeader`] and [`RecordData`].
  #[inline]
  pub fn into_components(self) -> (RecordHeader, RecordData) {
    (self.header, self.data)
  }

  /// Returns a reference to the record's header.
  #[inline]
  pub const fn header(&self) -> &RecordHeader {
    &self.header
  }

  /// Returns a reference to the record's data.
  #[inline]
  pub const fn data(&self) -> &RecordData {
    &self.data
  }

  fn encode(&self, buf: &mut [u8], off: usize, cmap: &mut CompressionMap) -> Result<usize, EncodeError> {
    todo!()
  }

  fn encoded_len(&self, cmap: &mut CompressionMap) -> usize {
    todo!()
  }
}

const MESSAGE_HEADER_SIZE: usize = 12;
const QDCOUNT_OFFSET: usize = 4;
const ANCOUNT_OFFSET: usize = 6;
pub(crate) const OP_CODE_QUERY: u16 = 0;
pub(crate) const RESPONSE_CODE_NO_ERROR: u16 = 0;

/// Used to allow a more efficient compression map
/// to be used for internal packDomainName calls without changing the
/// signature or functionality of public API.
struct CompressionMap {
  map: HashMap<SmolStr, u16>,
}

impl CompressionMap {
  #[inline]
  fn new() -> Self {
    Self {
      map: HashMap::new(),
    }
  }

  #[inline]
  fn insert(&mut self, s: SmolStr, pos: u16) {
    self.map.insert(s, pos);
  }

  #[inline]
  fn find(&self, s: &str) -> Option<u16> {
    self.map.get(s).copied()
  }
}



const MAX_COMPRESSION_OFFSET: usize = 2 << 13;
const COMPRESSION_POINTER_MASK: u16 = 0xC000;

