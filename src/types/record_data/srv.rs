use std::{
  ops::{Range, RangeFrom},
  sync::atomic::{AtomicU16, Ordering},
};

use smol_str::SmolStr;
use triomphe::Arc;

use dns_protocol::{Label, ResourceRecord, ResourceType, Serialize};

use crate::ProtoError;

/// [RFC 2782, DNS SRV RR, February 2000](https://tools.ietf.org/html/rfc2782)
///
/// ```text
/// Introductory example
///
///  If a SRV-cognizant LDAP client wants to discover a LDAP server that
///  supports TCP protocol and provides LDAP service for the domain
///  example.com., it does a lookup of
///
/// _ldap._tcp.example.com
///
///  as described in [ARM].  The example zone file near the end of this
///  memo contains answering RRs for an SRV query.
///
///  Note: LDAP is chosen as an example for illustrative purposes only,
///  and the LDAP examples used in this document should not be considered
///  a definitive statement on the recommended way for LDAP to use SRV
///  records. As described in the earlier applicability section, consult
///  the appropriate LDAP documents for the recommended procedures.
///
/// The format of the SRV RR
///
///  Here is the format of the SRV RR, whose DNS type code is 33:
///
/// _Service._Proto.Name TTL Class SRV Priority Weight Port Target
///
/// (There is an example near the end of this document.)
///
///  Service
/// The symbolic name of the desired service, as defined in Assigned
/// Numbers [STD 2] or locally.  An underscore (_) is prepended to
/// the service identifier to avoid collisions with DNS labels that
/// occur in nature.
///
/// Some widely used services, notably POP, don't have a single
/// universal name.  If Assigned Numbers names the service
/// indicated, that name is the only name which is legal for SRV
/// lookups.  The Service is case insensitive.
///
///  Proto
/// The symbolic name of the desired protocol, with an underscore
/// (_) prepended to prevent collisions with DNS labels that occur
/// in nature.  _TCP and _UDP are at present the most useful values
/// for this field, though any name defined by Assigned Numbers or
/// locally may be used (as for Service).  The Proto is case
/// insensitive.
///
///  Name
/// The domain this RR refers to.  The SRV RR is unique in that the
/// name one searches for is not this name; the example near the end
/// shows this clearly.
///
///  TTL
/// Standard DNS meaning [RFC 1035].
///
///  Class
/// Standard DNS meaning [RFC 1035].   SRV records occur in the IN
/// Class.
///
/// ```
// #[cfg_attr(feature = "serde-config", derive(Deserialize, Serialize))]
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
#[allow(clippy::upper_case_acronyms)]
pub struct SRV {
  data: Arc<[u8]>,
  target: SmolStr,
}

impl SRV {
  const PRIORITY_OFFSET: usize = 0;
  const WEIGHT_OFFSET: usize = 2;
  const PORT_OFFSET: usize = 4;
  const TARGET_OFFSET: usize = 6;

  const PRIORITY_END: usize = 2;
  const WEIGHT_END: usize = 4;
  const PORT_END: usize = 6;

  const PRIORITY_RANGE: Range<usize> = Self::PORT_OFFSET..Self::PRIORITY_END;
  const WEIGHT_RANGE: Range<usize> = Self::WEIGHT_OFFSET..Self::WEIGHT_END;
  const PORT_RANGE: Range<usize> = Self::PORT_OFFSET..Self::PORT_END;
  const TARGET_RANGE: RangeFrom<usize> = Self::TARGET_OFFSET..;

  /// Creates a new SRV record data.
  #[inline]
  pub fn new(priority: u16, weight: u16, port: u16, target: SmolStr) -> Result<Self, ProtoError> {
    let label = Label::from(target.as_str());
    let len = label.serialized_len();
    let mut buf = vec![0; Self::TARGET_OFFSET + len];
    buf[Self::PRIORITY_RANGE].copy_from_slice(priority.to_ne_bytes().as_ref());
    buf[Self::WEIGHT_RANGE].copy_from_slice(weight.to_ne_bytes().as_ref());
    buf[Self::PORT_RANGE].copy_from_slice(port.to_ne_bytes().as_ref());

    label
      .serialize(&mut buf[Self::TARGET_RANGE])
      .map_err(|_| ProtoError::NameTooLong)
      .map(|size| {
        buf.truncate(Self::TARGET_OFFSET + size);
        Self {
          data: Arc::from(buf),
          target,
        }
      })
  }

  /// Returns the bytes format of the SRV record data.
  ///
  /// The result is the encoded bytes of the SRV record data.
  ///
  /// This operation is O(1).
  #[inline]
  pub fn data(&self) -> &[u8] {
    &self.data
  }

  /// Returns a resource record from the `SRV`.
  #[inline]
  pub fn to_resource_record<'a>(
    &'a self,
    name: &'a str,
    ty: ResourceType,
    class: u16,
    ttl: u32,
  ) -> ResourceRecord<'a> {
    ResourceRecord::new(name, ty, class, ttl, self.data())
  }

  /// ```text
  ///  Priority
  /// The priority of this target host.  A client MUST attempt to
  /// contact the target host with the lowest-numbered priority it can
  /// reach; target hosts with the same priority SHOULD be tried in an
  /// order defined by the weight field.  The range is 0-65535.  This
  /// is a 16 bit unsigned integer in network byte order.
  /// ```
  #[inline]
  pub fn priority(&self) -> u16 {
    let val = unsafe { &*(self.data[Self::PRIORITY_RANGE].as_ptr() as *const AtomicU16) };
    val.load(Ordering::Acquire)
  }

  /// ```text
  ///  Weight
  /// A server selection mechanism.  The weight field specifies a
  /// relative weight for entries with the same priority. Larger
  /// weights SHOULD be given a proportionately higher probability of
  /// being selected. The range of this number is 0-65535.  This is a
  /// 16 bit unsigned integer in network byte order.  Domain
  /// administrators SHOULD use Weight 0 when there isn't any server
  /// selection to do, to make the RR easier to read for humans (less
  /// noisy).  In the presence of records containing weights greater
  /// than 0, records with weight 0 should have a very small chance of
  /// being selected.
  ///
  /// In the absence of a protocol whose specification calls for the
  /// use of other weighting information, a client arranges the SRV
  /// RRs of the same Priority in the order in which target hosts,
  /// specified by the SRV RRs, will be contacted. The following
  /// algorithm SHOULD be used to order the SRV RRs of the same
  /// priority:
  ///
  /// To select a target to be contacted next, arrange all SRV RRs
  /// (that have not been ordered yet) in any order, except that all
  /// those with weight 0 are placed at the beginning of the list.
  ///
  /// Compute the sum of the weights of those RRs, and with each RR
  /// associate the running sum in the selected order. Then choose a
  /// uniform random number between 0 and the sum computed
  /// (inclusive), and select the RR whose running sum value is the
  /// first in the selected order which is greater than or equal to
  /// the random number selected. The target host specified in the
  /// selected SRV RR is the next one to be contacted by the client.
  /// Remove this SRV RR from the set of the unordered SRV RRs and
  /// apply the described algorithm to the unordered SRV RRs to select
  /// the next target host.  Continue the ordering process until there
  /// are no unordered SRV RRs.  This process is repeated for each
  /// Priority.
  /// ```
  #[inline]
  pub fn weight(&self) -> u16 {
    let val = unsafe { &*(self.data[Self::WEIGHT_RANGE].as_ptr() as *const AtomicU16) };
    val.load(Ordering::Acquire)
  }

  /// ```text
  ///  Port
  /// The port on this target host of this service.  The range is 0-
  /// 65535.  This is a 16 bit unsigned integer in network byte order.
  /// This is often as specified in Assigned Numbers but need not be.
  ///
  /// ```
  #[inline]
  pub fn port(&self) -> u16 {
    let val = unsafe { &*(self.data[Self::PORT_RANGE].as_ptr() as *const AtomicU16) };
    val.load(Ordering::Acquire)
  }

  /// Sets the priority of the SRV record data.
  ///
  /// See [`priority`](#method.priority) for more information.
  #[inline]
  pub fn update_priority(&self, val: u16) {
    let priority = unsafe { &*(self.data[Self::PRIORITY_RANGE].as_ptr() as *const AtomicU16) };
    priority.store(val, Ordering::Release);
  }

  /// Sets the weight of the SRV record data.
  ///
  /// See [`weight`](#method.weight) for more information.
  #[inline]
  pub fn update_weight(&self, val: u16) {
    let weight = unsafe { &*(self.data[Self::WEIGHT_RANGE].as_ptr() as *const AtomicU16) };
    weight.store(val, Ordering::Release);
  }

  /// Updates the port of the SRV record data.
  ///
  /// See [`port`](#method.port) for more information.
  #[inline]
  pub fn set_port(&self, val: u16) {
    let port = unsafe { &*(self.data[Self::PORT_RANGE].as_ptr() as *const AtomicU16) };
    port.store(val, Ordering::Release);
  }

  /// ```text
  ///  Target
  /// The domain name of the target host.  There MUST be one or more
  /// address records for this name, the name MUST NOT be an alias (in
  /// the sense of RFC 1034 or RFC 2181).  Implementors are urged, but
  /// not required, to return the address record(s) in the Additional
  /// Data section.  Unless and until permitted by future standards
  /// action, name compression is not to be used for this field.
  ///
  /// A Target of "." means that the service is decidedly not
  /// available at this domain.
  /// ```
  #[inline]
  pub fn target(&self) -> &str {
    &self.target
  }
}
