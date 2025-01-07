use std::collections::HashMap;

use smol_str::SmolStr;

mod answer;
mod srv;
mod name;
mod message;
mod query;
mod record;
mod record_data;
mod record_type;

pub use name::Name;
pub use srv::SRV;
pub use record::{Record, RecordHeader};
pub use record_data::RecordData;
pub use record_type::{RecordType, UnknownRecordType, UnknownRecordTypeStr};

pub(crate) use answer::Answer;
pub(crate) use message::Message;
pub(crate) use query::Query;

const MAX_COMPRESSION_OFFSET: usize = 2 << 13;
const COMPRESSION_POINTER_MASK: u16 = 0xC000;


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
pub enum DecodeError {}

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



