#![cfg_attr(not(feature = "std"), no_std)]

use core::{
  marker::PhantomData,
  net::{Ipv4Addr, Ipv6Addr, SocketAddr},
};

use error::*;

pub use dns_protocol::{
  Cursor, Deserialize, Flags, Header, Label, LabelSegment, Message, MessageType, Opcode, Question,
  ResourceRecord, ResourceType, ResponseCode, Serialize,
};
#[cfg(feature = "slab")]
pub use slab;
pub use srv::*;
pub use txt::*;

/// The error type for the mDNS protocol
pub mod error;

mod srv;
mod txt;

const FORCE_UNICAST_RESPONSES: bool = false;

/// An endpoint for handling mDNS queries and responses.
///
/// This `Endpoint` is using a slab for managing connections and queries.
#[cfg(feature = "slab")]
#[cfg_attr(docsrs, doc(cfg(feature = "slab")))]
pub type SlabEndpoint = Endpoint<slab::Slab<slab::Slab<u16>>, slab::Slab<u16>>;

#[derive(Clone, Copy, PartialEq, Eq, derive_more::IsVariant)]
enum Side {
  Client,
  Server,
}

impl core::fmt::Display for Side {
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    match self {
      Side::Client => write!(f, "client"),
      Side::Server => write!(f, "server"),
    }
  }
}

/// Internal identifier for a `Connection` currently associated with an endpoint
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct ConnectionHandle(pub usize);

impl From<ConnectionHandle> for usize {
  fn from(x: ConnectionHandle) -> Self {
    x.0
  }
}

impl core::fmt::Display for ConnectionHandle {
  fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    write!(f, "{}", self.0)
  }
}

/// Internal identifier for a `Connection` currently associated with an endpoint
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub struct QueryHandle {
  qid: usize, // the query id
  mid: u16,   // the message id
  cid: usize, // the connection id
}

impl QueryHandle {
  #[inline]
  const fn new(cid: usize, qid: usize, mid: u16) -> Self {
    Self { cid, qid, mid }
  }

  /// Returns the message id associated with the query handle.
  #[inline]
  pub const fn message_id(&self) -> u16 {
    self.mid
  }

  /// Returns the query id associated with the query handle.
  #[inline]
  pub const fn query_id(&self) -> usize {
    self.qid
  }

  /// Returns the connection id associated with the query handle.
  #[inline]
  pub const fn connection_id(&self) -> usize {
    self.cid
  }
}

/// Pre-allocated storage for a uniform data type.
pub trait Pool<V> {
  /// The type of the errors that can occur when interacting with the slab.
  type Error: core::error::Error;

  /// The iterator type for the slab.
  type Iter<'a>: Iterator<Item = (usize, &'a V)>
  where
    Self: 'a,
    V: 'a;

  /// Returns a new, empty slab.
  fn new() -> Self;

  /// Returns a new slab with the specified capacity.
  ///
  /// Returns an error if the slab cannot hold the specified number of entries.
  fn with_capacity(capacity: usize) -> Result<Self, Self::Error>
  where
    Self: Sized;

  /// Returns the key of the next vacant entry.
  ///
  /// If the slab cannot hold any more entries, an error is returned.
  fn vacant_key(&self) -> Result<usize, Self::Error>;

  /// Returns `true` if the slab is empty.
  fn is_empty(&self) -> bool;

  /// Returns the number of entries in the slab.
  fn len(&self) -> usize;

  /// Return a reference to the value associated with the given key.
  ///
  /// If the given key is not associated with a value, then `None` is
  /// returned.
  fn get(&self, key: usize) -> Option<&V>;

  /// Return a mutable reference to the value associated with the given key.
  ///
  /// If the given key is not associated with a value, then `None` is
  /// returned.
  fn get_mut(&mut self, key: usize) -> Option<&mut V>;

  /// Insert a value in the slab, returning key assigned to the value.
  ///
  /// The returned key can later be used to retrieve or remove the value using indexed
  /// lookup and `remove`.
  ///
  /// Returns an error if the slab cannot hold any more entries.
  fn insert(&mut self, value: V) -> Result<usize, Self::Error>;

  /// Tries to remove the value associated with the given key,
  /// returning the value if the key existed.
  ///
  /// The key is then released and may be associated with future stored
  /// values.
  fn try_remove(&mut self, key: usize) -> Option<V>;

  /// Returns an iterator over the slab.
  fn iter(&self) -> Self::Iter<'_>;
}

/// A query event
#[derive(Debug, Eq, PartialEq)]
pub struct Query<'container, 'innards> {
  msg: Message<'container, 'innards>,
  query_handle: QueryHandle,
}

impl<'container, 'innards> Query<'container, 'innards> {
  #[inline]
  const fn new(msg: Message<'container, 'innards>, query_handle: QueryHandle) -> Self {
    Self { msg, query_handle }
  }

  /// Returns the question associated with the query event.
  #[inline]
  pub fn questions(&self) -> &[Question<'innards>] {
    self.msg.questions()
  }

  /// Returns the query handle associated with the query event.
  #[inline]
  pub const fn query_handle(&self) -> QueryHandle {
    self.query_handle
  }
}

/// A response event
#[derive(Debug, Eq, PartialEq)]
pub struct Response<'innards> {
  query_handle: QueryHandle,
  question: Question<'innards>,
}

impl<'innards> Response<'innards> {
  /// Creates a new response event.
  #[inline]
  pub const fn new(query_handle: QueryHandle, question: Question<'innards>) -> Self {
    Self {
      query_handle,
      question,
    }
  }

  /// Returns the query handle associated with the response event.
  #[inline]
  pub const fn query_handle(&self) -> QueryHandle {
    self.query_handle
  }

  /// Returns the question associated with the response event.
  #[inline]
  pub const fn question(&self) -> &Question<'innards> {
    &self.question
  }
}

#[derive(Debug, Eq, PartialEq)]
pub struct Incoming<'container, 'innards> {
  connection_handle: ConnectionHandle,
  message: Message<'container, 'innards>,
}

impl<'container, 'innards> Incoming<'container, 'innards> {
  /// Creates a new incoming event.
  #[inline]
  pub const fn new(
    connection_handle: ConnectionHandle,
    message: Message<'container, 'innards>,
  ) -> Self {
    Self {
      connection_handle,
      message,
    }
  }

  /// Returns the connection handle associated with the incoming event.
  #[inline]
  pub const fn connection_handle(&self) -> ConnectionHandle {
    self.connection_handle
  }

  /// Returns the data associated with the incoming event.
  #[inline]
  pub const fn message(&self) -> &Message<'container, 'innards> {
    &self.message
  }
}

pub struct Outgoing {
  flags: Flags,
  unicast: bool,
  id: u16,
}

impl Outgoing {
  /// Creates a new outgoing event.
  #[inline]
  const fn new(flags: Flags, unicast: bool, id: u16) -> Self {
    Self { flags, unicast, id }
  }

  /// Returns the message flags should be used for the outgoing [`Message`].
  #[inline]
  pub const fn flags(&self) -> Flags {
    self.flags
  }

  /// Returns `true` if the outgoing event is unicast.
  #[inline]
  pub const fn is_unicast(&self) -> bool {
    self.unicast
  }

  /// Returns the message id should be used for the outgoing [`Message`].
  #[inline]
  pub const fn id(&self) -> u16 {
    self.id
  }
}

/// Events sent from an Endpoint to a Connection
pub enum ConnectionEvent<'container, 'innards, Q> {
  Query(Query<'container, 'innards>),
  QueryCompleted(QueryHandle),
  Outgoing(Outgoing),
  Closed {
    /// The remaining queries associated with the connection, if any.
    remainings: Q,
    /// The closed connection handle.
    connection_handle: ConnectionHandle,
  },
}

/// Events reacted to incoming responses
pub enum ResponseEvent<'a> {
  /// Service entry is complete
  Complete(ServiceEntry<'a>),
  /// The question should retry
  Retry(Question<'a>),
}

/// The main entry point to the library
///
/// This object performs no I/O whatsoever. Instead, it consumes incoming packets and
/// connection-generated events via `handle` and `handle_event`.
pub struct Endpoint<S, Q> {
  connections: S,
  side: Side,
  _q: PhantomData<Q>,
}

impl<S, Q> Endpoint<S, Q>
where
  S: Pool<Q>,
  Q: Pool<u16>,
{
  /// Create a new server endpoint
  pub fn server() -> Self {
    Self {
      connections: S::new(),
      side: Side::Server,
      _q: PhantomData,
    }
  }

  /// Create a new client endpoint
  pub fn client() -> Self {
    Self {
      connections: S::new(),
      side: Side::Client,
      _q: PhantomData,
    }
  }

  /// Create a new server endpoint with a specific capacity
  pub fn server_with_capacity(capacity: usize) -> Result<Self, S::Error> {
    Ok(Self {
      connections: S::with_capacity(capacity)?,
      side: Side::Server,
      _q: PhantomData,
    })
  }

  /// Create a new client endpoint with a specific capacity
  pub fn client_with_capacity(capacity: usize) -> Result<Self, S::Error> {
    Ok(Self {
      connections: S::with_capacity(capacity)?,
      side: Side::Client,
      _q: PhantomData,
    })
  }

  /// Close the endpoint
  pub fn close(&mut self) {
    self.connections.iter().for_each(|(idx, conn)| {
      if !conn.is_empty() {
        #[cfg(feature = "tracing")]
        tracing::warn!(
          type=%self.side,
          "mdns endpoint: connection {} closed with {} remaining queries",
          idx,
          conn.len()
        );
      }
    });
  }

  /// Accept a new connection
  pub fn accept(&mut self) -> Result<ConnectionHandle, Error<S::Error, Q::Error>> {
    self.check_direction(Side::Server)?;

    let key = self
      .connections
      .insert(Q::new())
      .map_err(Error::Connection)?;
    Ok(ConnectionHandle(key))
  }

  /// Open a new connection
  pub fn connect(&mut self) -> Result<ConnectionHandle, Error<S::Error, Q::Error>> {
    self.check_direction(Side::Client)?;

    let key = self
      .connections
      .insert(Q::new())
      .map_err(Error::Connection)?;
    Ok(ConnectionHandle(key))
  }

  /// Handle an incoming query message
  pub fn recv_query<'container, 'innards>(
    &mut self,
    ch: ConnectionHandle,
    msg: Message<'container, 'innards>,
  ) -> Result<Query<'container, 'innards>, Error<S::Error, Q::Error>> {
    self.check_direction(Side::Server)?;

    let id = msg.id();
    let flags = msg.flags();
    let opcode = flags.opcode();

    if opcode != Opcode::Query {
      // "In both multicast query and multicast response messages, the OPCODE MUST
      // be zero on transmission (only standard queries are currently supported
      // over multicast).  Multicast DNS messages received with an OPCODE other
      // than zero MUST be silently ignored."  Note: OpcodeQuery == 0
      #[cfg(feature = "tracing")]
      tracing::error!(type=%self.side, opcode = ?opcode, "mdns endpoint: received query with non-zero OpCode");
      return Err(Error::InvalidOpcode(opcode));
    }

    let resp_code = flags.response_code();
    if resp_code != ResponseCode::NoError {
      // "In both multicast query and multicast response messages, the Response
      // Code MUST be zero on transmission.  Multicast DNS messages received with
      // non-zero Response Codes MUST be silently ignored."
      #[cfg(feature = "tracing")]
      tracing::error!(type=%self.side, rcode = ?resp_code, "mdns endpoint: received query with non-zero response_code");
      return Err(Error::InvalidResponseCode(resp_code));
    }

    // TODO(reddaly): Handle "TC (Truncated) Bit":
    //    In query messages, if the TC bit is set, it means that additional
    //    Known-Answer records may be following shortly.  A responder SHOULD
    //    record this fact, and wait for those additional Known-Answer records,
    //    before deciding whether to respond.  If the TC bit is clear, it means
    //    that the querying host has no additional Known Answers.
    if flags.truncated() {
      #[cfg(feature = "tracing")]
      tracing::error!(
        type=%self.side, "mdns endpoint: support for DNS requests with high truncated bit not implemented"
      );
      return Err(Error::TrancatedQuery);
    }

    if let Some(conn) = self.connections.get_mut(ch.0) {
      let qid = conn.insert(id).map_err(Error::Query)?;
      return Ok(Query::new(msg, QueryHandle::new(ch.into(), qid, id)));
    }

    Err(Error::ConnectionNotFound(ch))
  }

  /// Handle a response
  pub fn prepare_response(
    &mut self,
    qh: QueryHandle,
    question: Question<'_>,
  ) -> Result<Outgoing, Error<S::Error, Q::Error>> {
    self.check_direction(Side::Server)?;

    let mut flags = Flags::new();
    flags
      .set_response_code(ResponseCode::NoError)
      .set_authoritative(true);

    // Handle unicast and multicast responses.
    // TODO(reddaly): The decision about sending over unicast vs. multicast is not
    // yet fully compliant with RFC 6762.  For example, the unicast bit should be
    // ignored if the records in question are close to TTL expiration.  For now,
    // we just use the unicast bit to make the decision, as per the spec:
    //     RFC 6762, section 18.12.  Repurposing of Top Bit of qclass in Query
    //     Section
    //
    //     In the Query Section of a Multicast DNS query, the top bit of the
    //     qclass field is used to indicate that unicast responses are preferred
    //     for this particular question.  (See Section 5.4.)
    let qc = question.class();
    let unicast = (qc & (1 << 15)) != 0 || FORCE_UNICAST_RESPONSES;

    // 18.1: ID (Query Identifier)
    // 0 for multicast response, query.Id for unicast response
    let mut id = 0;
    if unicast {
      id = qh.message_id();
    }

    Ok(Outgoing::new(flags, unicast, id))
  }

  /// Prepare a query for client to send out
  pub fn prepare_query<'innards>(
    &mut self,
    name: Label<'innards>,
    unicast_response: bool,
  ) -> Result<Question<'innards>, Error<S::Error, Q::Error>> {
    self.check_direction(Side::Client)?;

    // RFC 6762, section 18.12.  Repurposing of Top Bit of qclass in Query
    // Section
    //
    // In the Query Section of a Multicast DNS query, the top bit of the qclass
    // field is used to indicate that unicast responses are preferred for this
    // particular question.  (See Section 5.4.)
    let qclass = if unicast_response {
      let base: u16 = 1;
      base | (1 << 15)
    } else {
      1
    };

    Ok(Question::new(name, ResourceType::Ptr, qclass))
  }

  /// Handle an incoming response
  pub fn recv_response<'container, 'innards, C, A, M>(
    &mut self,
    from: SocketAddr,
    cache: &mut InprogressCache<'innards, C, A>,
    msg: Message<'container, 'innards>,
  ) -> Result<impl Iterator<Item = ResponseEvent<'innards>>, Error<S::Error, Q::Error>>
  where
    C: for<'b> Cache<Label<'b>, ServiceEntry<'b>>,
    A: for<'b> Cache<Label<'b>, Label<'b>>,
    M: for<'b> Cache<Label<'b>, ()>,
  {
    self.check_direction(Side::Client)?;

    let mut modified_entries = M::new();

    for record in msg.answers().iter().chain(msg.additional().iter()) {
      let record_name = record.name();
      match record.ty() {
        ResourceType::A => {
          let src = record.data();
          let res: Result<[u8; 4], _> = src.try_into();

          match res {
            Ok(ip) => {
              let entry = cache.get_or_create_entry(&record_name);
              entry.ipv4 = Some(Ipv4Addr::from(ip));
              modified_entries.insert(record_name, ());
            }
            Err(_) => {
              #[cfg(feature = "tracing")]
              tracing::error!(type=%self.side, "mdns endpoint: invalid A record data");
              return Err(proto_error_parse("A").into());
            }
          }
        }
        ResourceType::AAAA => {
          let src = record.data();
          let res: Result<[u8; 16], _> = src.try_into();

          match res {
            Ok(ip) => {
              let entry = cache.get_or_create_entry(&record_name);
              let ip = Ipv6Addr::from(ip);
              entry.ipv6 = Some(ip);

              // link-local IPv6 addresses must be qualified with a zone (interface). Zone is
              // specific to this machine/network-namespace and so won't be carried in the
              // mDNS message itself. We borrow the zone from the source address of the UDP
              // packet, as the link-local address should be valid on that interface.
              if Ipv6AddrExt::is_unicast_link_local(&ip) || ip.is_multicast_link_local() {
                if let SocketAddr::V6(addr) = from {
                  entry.zone = Some(addr.scope_id());
                }
              }

              modified_entries.insert(record_name, ());
            }
            Err(_) => {
              #[cfg(feature = "tracing")]
              tracing::error!(type=%self.side, "mdns endpoint: invalid AAAA record data");
              return Err(proto_error_parse("AAAA").into());
            }
          }
        }
        ResourceType::Ptr => {
          cache.get_or_create_entry(&record_name);
          modified_entries.insert(record_name, ());
        }
        ResourceType::Srv => {
          let data = record.data();
          let srv = Srv::from_bytes(data)?;

          // Check for a target mismatch
          let target = srv.target();
          if target != record_name {
            cache.create_alias(&record_name, &target);
          }

          // Update the entry
          let entry = cache.get_or_create_entry(&record_name);
          entry.host = target;
          entry.port = srv.port();
          modified_entries.insert(record_name, ());
        }
        ResourceType::Txt => {
          let data = record.data();
          let entry = cache.get_or_create_entry(&record_name);
          entry.txts = Txt::from_bytes(data, 0, data.len());
          entry.has_txt = true;
          modified_entries.insert(record_name, ());
        }
        _ => continue,
      }
    }

    // Process all modified entries
    Ok(modified_entries.into_iter().filter_map(|(name, _)| {
      let canonical_name = cache.resolve_name(&name);

      if let Some(entry) = cache.entries.get_mut(&canonical_name) {
        if entry.complete() && !entry.sent {
          entry.sent = true;
          return Some(ResponseEvent::Complete(*entry));
        } else if !entry.sent {
          // Fire off a node-specific query for incomplete entries

          // RFC 6762, section 18.12.  Repurposing of Top Bit of qclass in Query
          // Section
          //
          // In the Query Section of a Multicast DNS query, the top bit of the qclass
          // field is used to indicate that unicast responses are preferred for this
          // particular question.  (See Section 5.4.)
          let question = Question::new(name, ResourceType::Ptr, 1);

          return Some(ResponseEvent::Retry(question));
        }
      }

      None
    }))
  }

  /// Handle a query drain event
  pub fn drain_query<'container, 'innards>(
    &mut self,
    qh: QueryHandle,
  ) -> Result<ConnectionEvent<'container, 'innards, Q>, Error<S::Error, Q::Error>> {
    match self.connections.get_mut(qh.cid) {
      Some(q) => match q.try_remove(qh.qid) {
        Some(_) => Ok(ConnectionEvent::QueryCompleted(qh)),
        None => Err(Error::QueryNotFound(qh)),
      },
      None => Err(Error::ConnectionNotFound(ConnectionHandle(qh.cid))),
    }
  }

  /// Handle a connection drain event
  pub fn drain_connection<'container, 'innards>(
    &mut self,
    ch: ConnectionHandle,
  ) -> Result<ConnectionEvent<'container, 'innards, Q>, Error<S::Error, Q::Error>> {
    match self.connections.try_remove(ch.into()) {
      Some(queries) => {
        #[cfg(feature = "tracing")]
        if !queries.is_empty() {
          tracing::warn!(
            type=%self.side,
            "mdns endpoint: connection {} closed with {} remaining queries",
            ch,
            queries.len()
          );
        }
        Ok(ConnectionEvent::Closed {
          remainings: queries,
          connection_handle: ch,
        })
      }
      None => Err(Error::ConnectionNotFound(ch)),
    }
  }

  #[inline]
  fn check_direction(&self, side: Side) -> Result<(), Error<S::Error, Q::Error>> {
    if self.side.ne(&side) {
      return Err(Error::WrongDirection);
    }
    Ok(())
  }
}

/// Returned after we query for a service.
#[derive(Debug, Clone, Copy)]
pub struct ServiceEntry<'a> {
  name: Label<'a>,
  host: Label<'a>,
  port: u16,
  ipv4: Option<Ipv4Addr>,
  ipv6: Option<Ipv6Addr>,
  zone: Option<u32>,
  txts: Txt<'a, 'a>,
  has_txt: bool,
  sent: bool,
}

impl Default for ServiceEntry<'_> {
  #[inline]
  fn default() -> Self {
    Self {
      name: Label::default(),
      host: Label::default(),
      port: 0,
      ipv4: None,
      ipv6: None,
      zone: None,
      has_txt: false,
      sent: false,
      txts: Txt::default(),
    }
  }
}

impl<'a> ServiceEntry<'a> {
  fn complete(&self) -> bool {
    (self.ipv4.is_some() || self.ipv6.is_some()) && self.port != 0 && self.has_txt
  }

  #[inline]
  fn with_name(mut self, name: Label<'a>) -> Self {
    self.name = name;
    self
  }

  /// Returns the name of the service.
  #[inline]
  pub const fn name(&self) -> &Label<'a> {
    &self.name
  }

  /// Returns the host of the service.
  #[inline]
  pub const fn host(&self) -> &Label<'a> {
    &self.host
  }

  /// Returns the port of the service.
  #[inline]
  pub const fn port(&self) -> u16 {
    self.port
  }

  /// Returns the IPv4 address of the service, if any.
  #[inline]
  pub const fn ipv4(&self) -> Option<&Ipv4Addr> {
    self.ipv4.as_ref()
  }

  /// Returns the IPv6 address of the service, if any.
  #[inline]
  pub const fn ipv6(&self) -> Option<&Ipv6Addr> {
    self.ipv6.as_ref()
  }

  /// Returns the zone of the service, if any.
  #[inline]
  pub const fn zone(&self) -> Option<u32> {
    self.zone
  }

  /// Returns the TXT record of the service.
  ///
  /// See [`Txt`] for more information.
  #[inline]
  pub const fn txt(&self) -> &Txt<'a, 'a> {
    &self.txts
  }
}

/// Track the state of service entries and their aliases for a single mDNS query.
pub struct InprogressCache<'a, C, A> {
  // The actual entries being built
  entries: C,
  // Maps alias names to their canonical name
  aliases: A,
  _m: PhantomData<&'a ()>,
}

impl<C, A> Default for InprogressCache<'_, C, A>
where
  C: Default,
  A: Default,
{
  #[inline]
  fn default() -> Self {
    Self {
      entries: C::default(),
      aliases: A::default(),
      _m: PhantomData,
    }
  }
}

impl<'a, C, A> InprogressCache<'a, C, A>
where
  C: for<'b> Cache<Label<'b>, ServiceEntry<'b>>,
  A: for<'b> Cache<Label<'b>, Label<'b>>,
{
  /// Create a new inprogress cache for a query
  pub fn new() -> Self {
    Self {
      entries: C::new(),
      aliases: A::new(),
      _m: PhantomData,
    }
  }

  // Get the canonical name for a given name (following aliases if needed)
  fn resolve_name(&self, name: &Label<'a>) -> Label<'a> {
    let mut current = name;
    let mut seen = A::new();

    while let Some(target) = self.aliases.get(current) {
      if seen.contains_key(target) {
        // Circular reference detected, break the cycle
        break;
      }
      seen.insert(*current, Label::default());
      current = target;
    }

    *current
  }

  // Get a mutable reference to an entry, creating it if it doesn't exist
  fn get_or_create_entry(&mut self, name: &Label<'a>) -> &mut ServiceEntry {
    let canonical_name = self.resolve_name(name);

    if !self.entries.contains_key(&canonical_name) {
      let builder = ServiceEntry::default().with_name(canonical_name);
      self.entries.insert(canonical_name, builder);
    }

    self.entries.get_mut(&canonical_name).unwrap()
  }

  // Create an alias from one name to another
  fn create_alias(&mut self, from: &Label<'a>, to: &Label<'a>) {
    let canonical_to = self.resolve_name(to);

    // If the 'from' exists as an entry, merge it into 'to'
    if let Some(from_entry) = self.entries.remove(from) {
      let to_entry = self.get_or_create_entry(&canonical_to);

      // Merge the entries, keeping non-None values from the original entry
      if to_entry.port == 0 {
        to_entry.port = from_entry.port;
      }

      if to_entry.ipv4.is_none() {
        to_entry.ipv4 = from_entry.ipv4;
      }

      if to_entry.ipv6.is_none() {
        to_entry.ipv6 = from_entry.ipv6;
        to_entry.zone = from_entry.zone;
      }

      if !to_entry.has_txt {
        to_entry.has_txt = from_entry.has_txt;
        to_entry.txts = from_entry.txts;
      }
    }

    // Create the alias
    self.aliases.insert(*from, canonical_to);
  }
}

pub trait Cache<K, V> {
  fn new() -> Self;

  fn get(&self, key: &K) -> Option<&V>;

  fn get_mut(&mut self, key: &K) -> Option<&mut V>;

  fn contains_key(&self, key: &K) -> bool;

  fn insert(&mut self, key: K, value: V);

  fn remove(&mut self, key: &K) -> Option<V>;

  fn into_iter(self) -> impl Iterator<Item = (K, V)>;
}

#[cfg(feature = "std")]
const _: () = {
  use std::collections::HashMap;

  impl<K, V, S> Cache<K, V> for HashMap<K, V, S>
  where
    K: core::hash::Hash + Eq,
    S: core::hash::BuildHasher + Default,
  {
    fn new() -> Self {
      HashMap::with_hasher(Default::default())
    }

    fn get(&self, key: &K) -> Option<&V> {
      HashMap::get(self, key)
    }

    fn get_mut(&mut self, key: &K) -> Option<&mut V> {
      HashMap::get_mut(self, key)
    }

    fn contains_key(&self, key: &K) -> bool {
      HashMap::contains_key(self, key)
    }

    fn insert(&mut self, key: K, value: V) {
      HashMap::insert(self, key, value);
    }

    fn remove(&mut self, key: &K) -> Option<V> {
      HashMap::remove(self, key)
    }

    fn into_iter(self) -> impl Iterator<Item = (K, V)> {
      std::iter::IntoIterator::into_iter(self)
    }
  }  
};

#[cfg(feature = "slab")]
impl<T> Pool<T> for slab::Slab<T> {
  type Error = core::convert::Infallible;

  type Iter<'a>
    = slab::Iter<'a, T>
  where
    Self: 'a;

  fn new() -> Self {
    slab::Slab::new()
  }

  fn with_capacity(capacity: usize) -> Result<Self, Self::Error>
  where
    Self: Sized,
  {
    Ok(slab::Slab::with_capacity(capacity))
  }

  fn vacant_key(&self) -> Result<usize, Self::Error> {
    Ok(slab::Slab::vacant_key(self))
  }

  fn is_empty(&self) -> bool {
    slab::Slab::is_empty(self)
  }

  fn len(&self) -> usize {
    slab::Slab::len(self)
  }

  fn get(&self, key: usize) -> Option<&T> {
    slab::Slab::get(self, key)
  }

  fn get_mut(&mut self, key: usize) -> Option<&mut T> {
    slab::Slab::get_mut(self, key)
  }

  fn insert(&mut self, value: T) -> Result<usize, Self::Error> {
    Ok(slab::Slab::insert(self, value))
  }

  fn try_remove(&mut self, key: usize) -> Option<T> {
    slab::Slab::try_remove(self, key)
  }

  fn iter(&self) -> Self::Iter<'_> {
    slab::Slab::iter(self)
  }
}

trait Ipv6AddrExt {
  fn is_unicast_link_local(&self) -> bool;
  fn is_multicast_link_local(&self) -> bool;
}

impl Ipv6AddrExt for Ipv6Addr {
  #[inline]
  fn is_unicast_link_local(&self) -> bool {
    let octets = self.octets();
    octets[0] == 0xfe && (octets[1] & 0xc0) == 0x80
  }

  #[inline]
  fn is_multicast_link_local(&self) -> bool {
    let octets = self.octets();
    octets[0] == 0xff && (octets[1] & 0x0f) == 0x02
  }
}
