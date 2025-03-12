use core::marker::PhantomData;
use dns_protocol::{Error as ProtoError, Flags, Message, Opcode, Question, ResponseCode};

const FORCE_UNICAST_RESPONSES: bool = false;

#[cfg(feature = "slab")]
pub use slab;

pub use dns_protocol as proto;

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

/// The error type for the server.
#[derive(Debug, thiserror::Error)]
pub enum ServerError<S, Q> {
  /// The server is full and cannot hold any more connections.
  #[error(transparent)]
  Connection(S),
  /// The connection is full and cannot hold any more queries.
  #[error(transparent)]
  Query(Q),
  /// The connection is not found.
  #[error("connection not found: {0:?}")]
  ConnectionNotFound(ConnectionHandle),
  /// The query is not found.
  #[error("query {qid} not found on connection {cid}", qid = _0.qid, cid = _0.cid)]
  QueryNotFound(QueryHandle),
  /// The error occurred while encoding/decoding the message.
  #[error(transparent)]
  Proto(#[from] ProtoError),
  /// Returned when the a query has an invalid opcode.
  #[error("invalid opcode: {0:?}")]
  InvalidOpcode(Opcode),
  /// Returned when the a query has an invalid response code.
  #[error("invalid response code: {0:?}")]
  InvalidResponseCode(ResponseCode),
  /// Returned when a query with a high truncated bit is received.
  #[error("support for DNS requests with high truncated bit not implemented")]
  TrancatedQuery,
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
pub trait Slab<V> {
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

/// Events sent from a Connection to an Endpoint
pub enum EndpointEvent<'container, 'innards> {
  Incoming(Incoming<'container, 'innards>),
  Response(Response<'innards>),
  DrainConnection(ConnectionHandle),
  DrainQuery(QueryHandle),
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
  S: Slab<Q>,
  Q: Slab<u16>,
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
  pub fn accept(&mut self) -> Result<ConnectionHandle, ServerError<S::Error, Q::Error>> {
    let key = self
      .connections
      .insert(Q::new())
      .map_err(ServerError::Connection)?;
    Ok(ConnectionHandle(key))
  }

  /// Process `EndpointEvent`s emitted from related `Connection`s
  ///
  /// In turn, processing this event may return a `ConnectionEvent` for the same `Connection`.
  ///
  /// # Errors
  ///
  /// - [`Error::Proto(ProtoError::NotEnoughReadBytes)`] if the buffer is not large enough to hold the entire structure.
  ///   You may need to read more data before calling this function again.
  /// - [`Error::Proto(ProtoError::NotEnoughWriteSpace)`] if the buffers provided are not large enough to hold the
  ///   entire structure. You may need to allocate larger buffers before calling this function.
  pub fn handle_event<'container, 'innards>(
    &mut self,
    event: EndpointEvent<'container, 'innards>,
  ) -> Result<ConnectionEvent<'container, 'innards, Q>, ServerError<S::Error, Q::Error>> {
    match event {
      EndpointEvent::Incoming(Incoming {
        connection_handle,
        message,
      }) => self
        .handle_incoming(connection_handle, message)
        .map(ConnectionEvent::Query),
      EndpointEvent::Response(Response {
        query_handle,
        question,
      }) => self
        .handle_response(query_handle, question)
        .map(ConnectionEvent::Outgoing),
      EndpointEvent::DrainConnection(ch) => self.handle_drain_connection(ch),
      EndpointEvent::DrainQuery(qh) => self.handle_drain_query(qh),
    }
  }

  /// Handle an incoming message
  pub fn handle_incoming<'container, 'innards>(
    &mut self,
    ch: ConnectionHandle,
    msg: Message<'container, 'innards>,
  ) -> Result<Query<'container, 'innards>, ServerError<S::Error, Q::Error>> {
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
      return Err(ServerError::InvalidOpcode(opcode));
    }

    let resp_code = flags.response_code();
    if resp_code != ResponseCode::NoError {
      // "In both multicast query and multicast response messages, the Response
      // Code MUST be zero on transmission.  Multicast DNS messages received with
      // non-zero Response Codes MUST be silently ignored."
      #[cfg(feature = "tracing")]
      tracing::error!(type=%self.side, rcode = ?resp_code, "mdns endpoint: received query with non-zero response_code");
      return Err(ServerError::InvalidResponseCode(resp_code));
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
      return Err(ServerError::TrancatedQuery);
    }

    if let Some(conn) = self.connections.get_mut(ch.0) {
      let qid = conn.insert(id).map_err(ServerError::Query)?;
      return Ok(Query::new(msg, QueryHandle::new(ch.into(), qid, id)));
    }

    Err(ServerError::ConnectionNotFound(ch))
  }

  /// Handle a response
  pub fn handle_response(
    &mut self,
    qh: QueryHandle,
    question: Question<'_>,
  ) -> Result<Outgoing, ServerError<S::Error, Q::Error>> {
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

  /// Handle a query drain event
  pub fn handle_drain_query<'container, 'innards>(
    &mut self,
    qh: QueryHandle,
  ) -> Result<ConnectionEvent<'container, 'innards, Q>, ServerError<S::Error, Q::Error>> {
    match self.connections.get_mut(qh.cid) {
      Some(q) => match q.try_remove(qh.qid) {
        Some(_) => Ok(ConnectionEvent::QueryCompleted(qh)),
        None => Err(ServerError::QueryNotFound(qh)),
      },
      None => Err(ServerError::ConnectionNotFound(ConnectionHandle(qh.cid))),
    }
  }

  /// Handle a connection drain event
  pub fn handle_drain_connection<'container, 'innards>(
    &mut self,
    ch: ConnectionHandle,
  ) -> Result<ConnectionEvent<'container, 'innards, Q>, ServerError<S::Error, Q::Error>> {
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
      None => Err(ServerError::ConnectionNotFound(ch)),
    }
  }
}

#[cfg(feature = "slab")]
impl<T> Slab<T> for slab::Slab<T> {
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
