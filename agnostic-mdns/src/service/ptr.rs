use mdns_proto::{
  error::ProtoError,
  proto::{Label, Serialize},
};
use smol_str::SmolStr;
use triomphe::Arc;

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
#[derive(Clone, PartialEq, Eq, Hash)]
#[allow(clippy::upper_case_acronyms)]
pub struct PTR {
  data: Arc<[u8]>,
  name: SmolStr,
}

impl core::fmt::Debug for PTR {
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    f.debug_tuple("PTR").field(&self.name).finish()
  }
}

impl PTR {
  /// Create a new Name.
  #[inline]
  pub fn new(name: SmolStr) -> Result<Self, ProtoError> {
    let label = Label::from(name.as_str());
    let len = label.serialized_len();
    let mut buf = vec![0; len];
    label.serialize(&mut buf).map(|size| {
      buf.truncate(size);
      Self {
        data: Arc::from(buf),
        name,
      }
    })
  }

  /// Returns the encoded bytes of the name.
  #[inline]
  pub fn data(&self) -> &[u8] {
    &self.data
  }

  /// Returns the name.
  #[inline]
  pub fn name(&self) -> &str {
    &self.name
  }
}
