use super::{CompressionMap, DNSClass, EncodeError, Name, RecordData, RecordType};


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

  pub(crate) fn encode(&self, buf: &mut [u8], off: usize, cmap: &mut CompressionMap) -> Result<usize, EncodeError> {
    todo!()
  }

  pub(crate) fn encoded_len(&self, cmap: &mut CompressionMap) -> usize {
    todo!()
  }
}