use mdns_proto::{Label, Serialize};
use smol_str::SmolStr;
use triomphe::Arc;

use crate::ProtoError;

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
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PTR {
  data: Arc<[u8]>,
  name: SmolStr,
}

impl PTR {
  /// Create a new Name.
  #[inline]
  pub fn new(name: SmolStr) -> Result<Self, ProtoError> {
    let label = Label::from(name.as_str());
    let len = label.serialized_len();
    let mut buf = vec![0; len];
    label
      .serialize(&mut buf)
      .map(|size| {
        buf.truncate(size);
        Self {
          data: Arc::from(buf),
          name,
        }
      })
      .map_err(|_| ProtoError::NameTooLong)
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
