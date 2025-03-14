use std::{
  net::{Ipv4Addr, Ipv6Addr},
  str::FromStr,
};

use mdns_proto::ResourceType;
use smol_str::SmolStr;
use triomphe::Arc;

use crate::{IPV4_SIZE, IPV6_SIZE};

mod ptr;
mod srv;
mod txt;

pub use ptr::*;
pub use srv::*;
pub use txt::*;

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
/// "10.2.data.52" or "192.data.5.6").
/// ```
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct A([u8; IPV4_SIZE]);

impl FromStr for A {
  type Err = <Ipv4Addr as FromStr>::Err;

  fn from_str(s: &str) -> Result<Self, Self::Err> {
    s.parse::<Ipv4Addr>().map(Into::into)
  }
}

impl A {
  /// Creates a new `A` record data.
  #[inline]
  pub const fn new(addr: Ipv4Addr) -> Self {
    Self(addr.octets())
  }

  /// Returns the IPv4 address of the `A` record data.
  #[inline]
  pub const fn addr(&self) -> Ipv4Addr {
    Ipv4Addr::new(self.0[0], self.0[1], self.0[2], self.0[3])
  }

  /// Returns the bytes format of the `A` record data.
  #[inline]
  pub const fn data(&self) -> &[u8] {
    &self.0
  }
}

impl From<Ipv4Addr> for A {
  #[inline]
  fn from(value: Ipv4Addr) -> Self {
    Self::new(value)
  }
}

impl From<A> for Ipv4Addr {
  #[inline]
  fn from(value: A) -> Self {
    value.addr()
  }
}

/// ```text
/// -- RFC 1886 -- IPv6 DNS Extensions              December 1995
///
/// 2.2 AAAA data format
///
///    A 128 bit IPv6 address is encoded in the data portion of an AAAA
///    resource record in network byte order (high-order byte first).
/// ```
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct AAAA([u8; IPV6_SIZE]);

impl FromStr for AAAA {
  type Err = <Ipv6Addr as FromStr>::Err;

  fn from_str(s: &str) -> Result<Self, Self::Err> {
    s.parse::<Ipv6Addr>().map(Into::into)
  }
}

impl AAAA {
  /// Creates a new `AAAA` record data.
  #[inline]
  pub const fn new(addr: Ipv6Addr) -> Self {
    Self(addr.octets())
  }

  /// Returns the IPv6 address of the `AAAA` record data.
  #[inline]
  pub fn addr(&self) -> Ipv6Addr {
    Ipv6Addr::from(self.0)
  }

  /// Returns the bytes format of the `AAAA` record data.
  #[inline]
  pub const fn data(&self) -> &[u8] {
    &self.0
  }
}

impl From<Ipv6Addr> for AAAA {
  #[inline]
  fn from(value: Ipv6Addr) -> Self {
    Self::new(value)
  }
}

impl From<AAAA> for Ipv6Addr {
  #[inline]
  fn from(value: AAAA) -> Self {
    value.addr()
  }
}

/// The data of an mDNS resource record.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RecordDataRef<'a> {
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
  /// "10.2.data.52" or "192.data.5.6").
  /// ```
  A(&'a A),
  /// ```text
  /// -- RFC 1886 -- IPv6 DNS Extensions              December 1995
  ///
  /// 2.2 AAAA data format
  ///
  ///    A 128 bit IPv6 address is encoded in the data portion of an AAAA
  ///    resource record in network byte order (high-order byte first).
  /// ```
  AAAA(&'a AAAA),
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
  PTR(&'a PTR),
  /// ```text
  /// RFC 2782                       DNS SRV RR                  February 2000
  ///
  /// The format of the SRV RR
  ///
  ///  _Service._Proto.Name TTL Class SRV Priority Weight Port Target
  /// ```
  SRV(&'a SRV),
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
  TXT(&'a TXT),
}

impl<'a> From<&'a A> for RecordDataRef<'a> {
  #[inline]
  fn from(value: &'a A) -> Self {
    Self::A(value)
  }
}

impl<'a> From<&'a AAAA> for RecordDataRef<'a> {
  #[inline]
  fn from(value: &'a AAAA) -> Self {
    Self::AAAA(value)
  }
}

impl<'a> From<&'a SRV> for RecordDataRef<'a> {
  #[inline]
  fn from(value: &'a SRV) -> Self {
    Self::SRV(value)
  }
}

impl<'a> From<&'a TXT> for RecordDataRef<'a> {
  #[inline]
  fn from(value: &'a TXT) -> Self {
    Self::TXT(value)
  }
}

impl<'a> From<&'a PTR> for RecordDataRef<'a> {
  #[inline]
  fn from(value: &'a PTR) -> Self {
    Self::PTR(value)
  }
}

impl RecordDataRef<'_> {
  /// Returns the type of the record data.
  #[inline]
  pub const fn ty(&self) -> ResourceType {
    match self {
      Self::A(_) => ResourceType::A,
      Self::AAAA(_) => ResourceType::AAAA,
      Self::PTR(_) => ResourceType::Ptr,
      Self::SRV(_) => ResourceType::Srv,
      Self::TXT(_) => ResourceType::Txt,
    }
  }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
#[allow(clippy::upper_case_acronyms)]
pub(crate) enum RecordData {
  A(Ipv4Addr),
  AAAA(Ipv6Addr),
  PTR(SmolStr),
  SRV {
    priority: u16,
    weight: u16,
    port: u16,
    target: SmolStr,
  },
  TXT(Arc<[SmolStr]>),
}

impl RecordData {
  /// Returns the type of the record data.
  #[inline]
  pub const fn ty(&self) -> ResourceType {
    match self {
      Self::A(_) => ResourceType::A,
      Self::AAAA(_) => ResourceType::AAAA,
      Self::PTR(_) => ResourceType::Ptr,
      Self::SRV { .. } => ResourceType::Srv,
      Self::TXT(_) => ResourceType::Txt,
    }
  }
}
