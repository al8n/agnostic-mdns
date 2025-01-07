use std::net::{Ipv4Addr, Ipv6Addr};

use smol_str::SmolStr;
use triomphe::Arc;

use super::{Name, RecordType, SRV};

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

impl From<Ipv4Addr> for RecordData {
  #[inline]
  fn from(value: Ipv4Addr) -> Self {
    Self::A(value)
  }
}

impl From<Ipv6Addr> for RecordData {
  #[inline]
  fn from(value: Ipv6Addr) -> Self {
    Self::AAAA(value)
  }
}

impl From<SRV> for RecordData {
  #[inline]
  fn from(value: SRV) -> Self {
    Self::SRV(value)
  }
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