use std::{collections::HashMap, ops::{Index, IndexMut}};

use dns_protocol::{Error as ProtoError, Flags, Label, Message, Opcode, Question, ResourceRecord, ResourceType, ResponseCode};


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


/// Internal identifier for a `Connection` currently associated with an endpoint
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub struct QueryHandle {
  qid: usize, // the query id
  mid: u16, // the message id
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

// impl Index<ConnectionHandle> for Slab<ConnectionMeta> {
//     type Output = ConnectionMeta;
//     fn index(&self, ch: ConnectionHandle) -> &ConnectionMeta {
//         &self[ch.0]
//     }
// }

// impl IndexMut<ConnectionHandle> for Slab<ConnectionMeta> {
//     fn index_mut(&mut self, ch: ConnectionHandle) -> &mut ConnectionMeta {
//         &mut self[ch.0]
//     }
// }

trait Zone {
  fn records<'a>(&'a self, name: Label<'_>, ty: ResourceType) -> impl Iterator<Item = ResourceRecord<'a>> + 'a;
}

/// Pre-allocated storage for a uniform data type.
pub trait Slab {
  /// The type of the errors that can occur when interacting with the slab.
  type Error: core::error::Error;

  /// The type of the values stored in the slab.
  type Value;

  /// The iterator type for the slab.
  type Iter<'a> where Self: 'a;

  /// Returns a new, empty slab.
  fn new() -> Self;

  /// Returns a new slab with the specified capacity.
  /// 
  /// Returns an error if the slab cannot hold the specified number of entries.
  fn with_capacity(capacity: usize) -> Result<Self, Self::Error> where Self: Sized;

  /// Returns the key of the next vacant entry.
  /// 
  /// If the slab cannot hold any more entries, an error is returned.
  fn vacant_key(&mut self) -> Result<usize, Self::Error>;

  /// Return a reference to the value associated with the given key.
  ///
  /// If the given key is not associated with a value, then `None` is
  /// returned.
  fn get(&self, key: usize) -> Option<&Self::Value>;

  /// Return a mutable reference to the value associated with the given key.
  /// 
  /// If the given key is not associated with a value, then `None` is
  /// returned.
  fn get_mut(&mut self, key: usize) -> Option<&mut Self::Value>;

  /// Insert a value in the slab, returning key assigned to the value.
  ///
  /// The returned key can later be used to retrieve or remove the value using indexed
  /// lookup and `remove`.
  /// 
  /// Returns an error if the slab cannot hold any more entries.
  fn insert(&mut self, value: Self::Value) -> Result<usize, Self::Error>;

  /// Tries to remove the value associated with the given key,
  /// returning the value if the key existed.
  ///
  /// The key is then released and may be associated with future stored
  /// values.
  fn try_remove(&mut self, key: usize) -> Option<Self::Value>;

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
pub struct Response<'container, 'innards> {
  query_handle: QueryHandle,
  question: Question<'innards>,
  records: &'container [ResourceRecord<'innards>],
}

impl<'container, 'innards> Response<'container, 'innards> {
  /// Creates a new response event.
  #[inline]
  pub const fn new(
    query_handle: QueryHandle,
    records: &'container mut [ResourceRecord<'innards>],
    question: Question<'innards>,
  ) -> Self {
    Self { query_handle, question, records }
  }

  /// Returns the query handle associated with the response event.
  #[inline]
  pub const fn query_handle(&self) -> QueryHandle {
    self.query_handle
  }

  /// Returns the answers associated with the response event.
  #[inline]
  pub const fn records(&mut self) -> &[ResourceRecord<'innards>] {
    self.records
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
  pub const fn new(connection_handle: ConnectionHandle, message: Message<'container, 'innards>) -> Self {
    Self { connection_handle, message }
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
}

impl Outgoing {
  /// Creates a new outgoing event.
  #[inline]
  const fn new(
    query_handle: QueryHandle,
    buffer: &'a [u8],
    len: usize,
  ) -> Self {
    Self { query_handle, buffer, len }
  }

  /// Returns the query handle associated with the outgoing event.
  #[inline]
  pub const fn query_handle(&self) -> QueryHandle {
    self.query_handle
  }

  /// Returns the data associated with the outgoing event.
  #[inline]
  pub fn data(&self) -> &'a [u8] {
    &self.buffer[..self.len]
  }

  /// Returns the underlying buffer associated with the outgoing event.
  /// 
  /// ## Warning
  /// 
  /// The buffer may contain more data than the outgoing event, if you
  /// need to access the data, use [`data`] instead.
  #[inline]
  pub const fn buffer(&self) -> &'a [u8] {
    self.buffer
  }

  /// Returns the length of the data associated with the outgoing event.
  #[inline]
  pub const fn len(&self) -> usize {
    self.len
  }
}

/// Events sent from a Connection to an Endpoint
pub enum EndpointEvent<'container, 'innards> {
  Incoming(Incoming<'container, 'innards>),
  Response(Response<'container, 'innards>),
  DrainConnection(ConnectionHandle),
  DrainQuery(QueryHandle),
}

/// Events sent from an Endpoint to a Connection
pub enum ConnectionEvent<'container, 'innards, Q> {
  Query(Query<'container, 'innards>),
  QueryCompleted(QueryHandle),
  Outgoing(Outgoing<'container>),
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
  _q: core::marker::PhantomData<Q>,
}

impl<S, Q> Endpoint<S, Q>
where
  S: Slab<Value = Q>,
  Q: Slab<Value = u16>,
{
  fn accept(&mut self) -> Result<ConnectionHandle, ServerError<S::Error, Q::Error>> {
    let key = self.connections.insert(Q::new()).map_err(ServerError::Connection)?;
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
  pub fn handle_event<'container, 'innards>(&mut self, event: EndpointEvent<'container, 'innards>) -> Result<ConnectionEvent<'container, 'innards, Q>, ServerError<S::Error, Q::Error>> {
    match event {
      EndpointEvent::Incoming(Incoming { connection_handle, message }) => {
        self.handle_incoming(connection_handle, message)
      }
      EndpointEvent::Response(Response { query_handle, records, question }) => {
        self.handle_response(query_handle, records, question)
        todo!()
      }
      EndpointEvent::DrainConnection(ch) => {
        self.handle_drain_connection(ch)
      }
      EndpointEvent::DrainQuery(qh) => self.handle_drain_query(qh),
    }
  }

  fn handle_incoming<'container, 'innards>(
    &mut self,
    ch: ConnectionHandle,
    msg: Message<'container, 'innards>,
  ) -> Result<ConnectionEvent<'container, 'innards, Q>, ServerError<S::Error, Q::Error>> {
    let id = msg.id();
    let flags = msg.flags();
    let opcode = flags.opcode();

    if opcode != Opcode::Query {
      // "In both multicast query and multicast response messages, the OPCODE MUST
      // be zero on transmission (only standard queries are currently supported
      // over multicast).  Multicast DNS messages received with an OPCODE other
      // than zero MUST be silently ignored."  Note: OpcodeQuery == 0
      tracing::error!(opcode = ?opcode, "mdns server: received query with non-zero OpCode");
      return Err(ServerError::InvalidOpcode(opcode));
    }

    let resp_code = flags.response_code();
    if resp_code != ResponseCode::NoError {
      // "In both multicast query and multicast response messages, the Response
      // Code MUST be zero on transmission.  Multicast DNS messages received with
      // non-zero Response Codes MUST be silently ignored."
      tracing::error!(rcode = ?resp_code, "mdns server: received query with non-zero response_code");
      return Err(ServerError::InvalidResponseCode(resp_code));
    }

    // TODO(reddaly): Handle "TC (Truncated) Bit":
    //    In query messages, if the TC bit is set, it means that additional
    //    Known-Answer records may be following shortly.  A responder SHOULD
    //    record this fact, and wait for those additional Known-Answer records,
    //    before deciding whether to respond.  If the TC bit is clear, it means
    //    that the querying host has no additional Known Answers.
    if flags.truncated() {
      tracing::error!(
        "mdns server: support for DNS requests with high truncated bit not implemented"
      );
      return Err(ServerError::TrancatedQuery);
    }

    if let Some(conn) = self.connections.get_mut(ch.0) {
      let qid = conn.insert(id).map_err(ServerError::Query)?;
      return Ok(ConnectionEvent::Query(Query::new(msg, QueryHandle::new(ch.into(), qid, id))));
    }

    Err(ServerError::ConnectionNotFound(ch))
  }

  fn handle_response<'container, 'innards>(
    &mut self,
    qh: QueryHandle,
    records: &'container [ResourceRecord<'innards>],
    question: Question<'innards>,
  ) -> Result<ConnectionEvent<'container, 'innards, Q>, ServerError<S::Error, Q::Error>> {
    let mut flags = Flags::new();
    flags
      .set_response_code(ResponseCode::NoError)
      .set_authoritative(true);
    let msg = Message::new(qh.message_id(), flags, &mut [], answers, &mut [], additionals);
    let len = msg.write(buffer)?;

    Ok(ConnectionEvent::Outgoing(Outgoing::new(qh, buffer, len)))
  }

  fn handle_drain_query<'container, 'innards>(&mut self, qh: QueryHandle) -> Result<ConnectionEvent<'container, 'innards, Q>, ServerError<S::Error, Q::Error>> {
    match self.connections.get_mut(qh.cid) {
      Some(q) => match q.try_remove(qh.qid) {
        Some(_) => Ok(ConnectionEvent::QueryCompleted(qh)),
        None => Err(ServerError::QueryNotFound(qh)),
      },
      None => Err(ServerError::ConnectionNotFound(ConnectionHandle(qh.cid))),
    }
  }

  fn handle_drain_connection<'container, 'innards>(&mut self, ch: ConnectionHandle) -> Result<ConnectionEvent<'container, 'innards, Q>, ServerError<S::Error, Q::Error>> {
    match self.connections.try_remove(ch.into()) {
      Some(queries) => Ok(ConnectionEvent::Closed {
        remainings: queries,
        connection_handle: ch,
      }),
      None => Err(ServerError::ConnectionNotFound(ch)),
    }
  }
}

// #[cfg(test)]
// mod tests {
//   use std::net::UdpSocket;

//   use super::Endpoint;

//   #[test]
//   fn endpoint() {
//     let socket = UdpSocket::bind("").unwrap();
//     let mut ep = Endpoint {};
    
//     loop {
//       let mut buf = [0; 1024];
//       let len = socket.recv(&mut buf).unwrap();
//       // ep.handle_event(&buf[..len]);
//     }
//   }
// }