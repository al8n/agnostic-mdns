use std::str::FromStr;

use smol_str::SmolStr;

const AVALUE: u16 = 1;
const AAAAVALUE: u16 = 28;
const ANYVALUE: u16 = 255;
const PTRVALUE: u16 = 12;
const SRVVALUE: u16 = 33;
const TXTVALUE: u16 = 16;

/// Unknown record type string error.
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
  A = AVALUE,
  /// [RFC 3596](https://tools.ietf.org/html/rfc3596) IPv6 address record
  AAAA = AAAAVALUE,
  /// [RFC 1035](https://tools.ietf.org/html/rfc1035) All cached records, aka ANY
  ANY = ANYVALUE,
  /// [RFC 1035](https://tools.ietf.org/html/rfc1035) Pointer record
  PTR = PTRVALUE,
  /// [RFC 2782](https://tools.ietf.org/html/rfc2782) Service locator
  SRV = SRVVALUE,
  /// [RFC 1035](https://tools.ietf.org/html/rfc1035) Text record
  TXT = TXTVALUE,
  /// The value for the zero record type.
  UNKNOWN(u16),
}

impl RecordType {
  /// Returns the string representation of the record type.
  #[inline]
  pub const fn as_str(&self) -> &'static str {
    match self {
      Self::A => "A",
      Self::AAAA => "AAAA",
      Self::ANY => "ANY",
      Self::PTR => "PTR",
      Self::SRV => "SRV",
      Self::TXT => "TXT",
      Self::UNKNOWN(_) => "UNKNOWN",
    }
  }
}

impl From<RecordType> for u16 {
  #[inline]
  fn from(value: RecordType) -> u16 {
    match value {
      RecordType::A => AVALUE,
      RecordType::AAAA => AAAAVALUE,
      RecordType::ANY => ANYVALUE,
      RecordType::PTR => PTRVALUE,
      RecordType::SRV => SRVVALUE,
      RecordType::TXT => TXTVALUE,
      RecordType::UNKNOWN(v) => v,
    }
  }
}

impl From<RecordType> for &'static str {
  #[inline]
  fn from(value: RecordType) -> &'static str {
    value.as_str()
  }
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

impl From<u16> for RecordType {
  #[inline]
  fn from(value: u16) -> Self {
    match value {
      AVALUE => Self::A,
      AAAAVALUE => Self::AAAA,
      ANYVALUE => Self::ANY,
      PTRVALUE => Self::PTR,
      SRVVALUE => Self::SRV,
      TXTVALUE => Self::TXT,
      _ => Self::UNKNOWN(value),
    }
  }
}
