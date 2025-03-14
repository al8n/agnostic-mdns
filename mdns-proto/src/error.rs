use super::{ConnectionHandle, Opcode, QueryHandle, ResponseCode};
use core::num::NonZeroUsize;

pub use dns_protocol::{BufferType, Error as ProtoError};

#[inline]
pub(super) const fn not_enough_read_data(tried_to_read: usize, available: usize) -> ProtoError {
  ProtoError::NotEnoughReadBytes {
    tried_to_read: NonZeroUsize::new(tried_to_read).unwrap(),
    available,
  }
}

#[inline]
pub(super) const fn proto_error_parse(name: &'static str) -> ProtoError {
  ProtoError::Parse { name }
}

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
  /// Returned when invoking a handle method on wrong endpoint direction.
  ///
  /// e.g. invoking accept on a client endpoint.
  #[error("invoking handle method on wrong endpoint direction")]
  WrongDirection,

  /// Protocol error
  #[error(transparent)]
  Proto(#[from] ProtoError),
}
