#![doc = include_str!("../README.md")]
#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![allow(unexpected_cfgs)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(docsrs, allow(unused_attributes))]
#![allow(clippy::needless_return)]
#![allow(unreachable_code)]

#[cfg(feature = "slab")]
pub use slab;
pub use srv::*;
pub use txt::*;

/// The error type for the mDNS protocol
pub mod error;

/// The server endpoint
pub mod server;

/// The client endpoint
pub mod client;

/// An implementation of the mDNS protocol
pub mod proto {
  pub use super::srv::Srv;
  pub use super::txt::{Str, Strings, Txt};
  pub use dns_protocol::{
    Cursor, Deserialize, Flags, Header, Label, LabelSegment, Message, MessageType, Opcode,
    Question, ResourceRecord, ResourceType, ResponseCode, Serialize,
  };
}

mod srv;
mod txt;

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
