use core::marker::PhantomData;

use super::{
  ConnectionHandle, Pool,
  error::ProtoError,
  proto::{Flags, Message, Opcode, Question, ResponseCode},
};

const FORCE_UNICAST_RESPONSES: bool = false;

/// An endpoint for handling mDNS queries and responses.
///
/// This `Endpoint` is using a slab for managing connections and queries.
#[cfg(feature = "slab")]
#[cfg_attr(docsrs, doc(cfg(feature = "slab")))]
pub type SlabEndpoint = Endpoint<slab::Slab<slab::Slab<u16>>, slab::Slab<u16>>;

/// The error type for the server.
#[derive(Debug, thiserror::Error)]
pub enum Error<S, Q> {
  /// The server is full and cannot hold any more connections.
  #[error(transparent)]
  Connection(S),
  /// The connection is full and cannot hold any more queries.
  #[error(transparent)]
  Query(Q),
  /// The connection is not found.
  #[error("connection not found: {0}")]
  ConnectionNotFound(ConnectionHandle),
  /// The query is not found.
  #[error("query {qid} not found on connection {cid}", qid = _0.qid, cid = _0.cid)]
  QueryNotFound(QueryHandle),
  /// Returned when the a query has an invalid opcode.
  #[error("invalid opcode: {0:?}")]
  InvalidOpcode(Opcode),
  /// Returned when the a query has an invalid response code.
  #[error("invalid response code: {0:?}")]
  InvalidResponseCode(ResponseCode),
  /// Returned when a query with a high truncated bit is received.
  #[error("support for DNS requests with high truncated bit not implemented")]
  TrancatedQuery,
  /// Protocol error
  #[error(transparent)]
  Proto(#[from] ProtoError),
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
  ///
  /// - `0` for multicast response
  /// - other values for unicast response
  #[inline]
  pub const fn id(&self) -> u16 {
    self.id
  }
}

/// The result of a connection is closed
#[derive(Debug, Eq, PartialEq, Clone, Copy)]
pub struct Closed<Q> {
  /// The remaining queries associated with the connection, if any.
  pub remainings: Q,
  /// The closed connection handle.
  pub connection_handle: ConnectionHandle,
}

/// The main entry point to the library
///
/// This object performs no I/O whatsoever. Instead, it consumes incoming packets and
/// connection-generated events via `handle` and `handle_event`.
pub struct Endpoint<S, Q> {
  connections: S,
  _q: PhantomData<Q>,
}

impl<S, Q> Default for Endpoint<S, Q>
where
  S: Pool<Q>,
  Q: Pool<u16>,
{
  fn default() -> Self {
    Self::new()
  }
}

impl<S, Q> Endpoint<S, Q>
where
  S: Pool<Q>,
  Q: Pool<u16>,
{
  /// Create a new server endpoint
  pub fn new() -> Self {
    Self {
      connections: S::new(),
      _q: PhantomData,
    }
  }

  /// Create a new server endpoint with a specific capacity
  pub fn with_capacity(capacity: usize) -> Result<Self, S::Error> {
    Ok(Self {
      connections: S::with_capacity(capacity)?,
      _q: PhantomData,
    })
  }

  /// Close the endpoint
  pub fn close(&mut self) {
    self.connections.iter().for_each(|(_idx, conn)| {
      if !conn.is_empty() {
        #[cfg(feature = "tracing")]
        tracing::warn!(
          "mdns endpoint: connection {} closed with {} remaining queries",
          _idx,
          conn.len()
        );
      }
    });
  }

  /// Accept a new connection
  pub fn accept(&mut self) -> Result<ConnectionHandle, Error<S::Error, Q::Error>> {
    let key = self
      .connections
      .insert(Q::new())
      .map_err(Error::Connection)?;
    Ok(ConnectionHandle(key))
  }

  /// Handle an incoming query message
  pub fn recv<'container, 'innards>(
    &mut self,
    ch: ConnectionHandle,
    msg: Message<'container, 'innards>,
  ) -> Result<Query<'container, 'innards>, Error<S::Error, Q::Error>> {
    let id = msg.id();
    let flags = msg.flags();
    let opcode = flags.opcode();

    if opcode != Opcode::Query {
      // "In both multicast query and multicast response messages, the OPCODE MUST
      // be zero on transmission (only standard queries are currently supported
      // over multicast).  Multicast DNS messages received with an OPCODE other
      // than zero MUST be silently ignored."  Note: OpcodeQuery == 0
      #[cfg(feature = "tracing")]
      tracing::error!(opcode = ?opcode, "mdns endpoint: received query with non-zero OpCode");
      return Err(Error::InvalidOpcode(opcode));
    }

    let resp_code = flags.response_code();
    if resp_code != ResponseCode::NoError {
      // "In both multicast query and multicast response messages, the Response
      // Code MUST be zero on transmission.  Multicast DNS messages received with
      // non-zero Response Codes MUST be silently ignored."
      #[cfg(feature = "tracing")]
      tracing::error!(rcode = ?resp_code, "mdns endpoint: received query with non-zero response code");
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
        "mdns endpoint: support for mDNS requests with high truncated bit not implemented"
      );
      return Err(Error::TrancatedQuery);
    }

    if let Some(conn) = self.connections.get_mut(ch.0) {
      let qid = conn.insert(id).map_err(Error::Query)?;
      return Ok(Query::new(msg, QueryHandle::new(ch.into(), qid, id)));
    }

    Err(Error::ConnectionNotFound(ch))
  }

  /// Generate a response for a question
  pub fn response(
    &mut self,
    qh: QueryHandle,
    question: Question<'_>,
  ) -> Result<Outgoing, Error<S::Error, Q::Error>> {
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
  pub fn drain_query(&mut self, qh: QueryHandle) -> Result<(), Error<S::Error, Q::Error>> {
    match self.connections.get_mut(qh.cid) {
      Some(q) => match q.try_remove(qh.qid) {
        Some(_) => Ok(()),
        None => Err(Error::QueryNotFound(qh)),
      },
      None => Err(Error::ConnectionNotFound(ConnectionHandle(qh.cid))),
    }
  }

  /// Handle a connection drain event
  pub fn drain_connection(
    &mut self,
    ch: ConnectionHandle,
  ) -> Result<Closed<Q>, Error<S::Error, Q::Error>> {
    match self.connections.try_remove(ch.into()) {
      Some(queries) => {
        #[cfg(feature = "tracing")]
        if !queries.is_empty() {
          tracing::warn!(
            "mdns endpoint: connection {} closed with {} remaining queries",
            ch,
            queries.len()
          );
        }
        Ok(Closed {
          remainings: queries,
          connection_handle: ch,
        })
      }
      None => Err(Error::ConnectionNotFound(ch)),
    }
  }
}
