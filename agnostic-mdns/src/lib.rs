#![doc = include_str!("../../README.md")]
// #![forbid(unsafe_code)]
#![deny(missing_docs)]
#![allow(unexpected_cfgs)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(docsrs, allow(unused_attributes))]
#![allow(clippy::needless_return)]
#![allow(unreachable_code)]

#[cfg(test)]
mod tests;

use std::{
  io,
  net::{Ipv4Addr, Ipv6Addr},
};

const IPV4_MDNS: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
const IPV6_MDNS: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb);
const IPV4_SIZE: usize = core::mem::size_of::<Ipv4Addr>();
const IPV6_SIZE: usize = core::mem::size_of::<Ipv6Addr>();
const MDNS_PORT: u16 = 5353;
// See RFC 6762, https://datatracker.ietf.org/doc/rfc6762/
const MAX_PAYLOAD_SIZE: usize = 9000;
const MAX_INLINE_PACKET_SIZE: usize = 512;

/// mDNS client
mod client;
mod types;

/// synchronous mDNS implementation
pub mod sync;

/// Generic asynchronous mDNS implementation for work stealing runtimes
#[cfg(any(feature = "tokio", feature = "async-std", feature = "smol",))]
#[cfg_attr(
  docsrs,
  doc(cfg(any(feature = "tokio", feature = "async-std", feature = "smol")))
)]
pub mod worksteal;

/// A builtin service that can be used with the mDNS server
pub mod service;

pub use client::*;
pub use iprobe as netprobe;
pub use smol_str::{SmolStr, format_smolstr};
pub use types::*;

/// The options for [`Server`].
#[derive(Clone, Debug)]
pub struct ServerOptions {
  pub(crate) ipv4_interface: Option<Ipv4Addr>,
  pub(crate) ipv6_interface: Option<u32>,
  pub(crate) log_empty_responses: bool,
}

impl Default for ServerOptions {
  #[inline]
  fn default() -> Self {
    Self::new()
  }
}

impl ServerOptions {
  /// Returns a new instance of [`ServerOptions`].
  #[inline]
  pub const fn new() -> Self {
    Self {
      ipv4_interface: None,
      ipv6_interface: None,
      log_empty_responses: false,
    }
  }

  /// Returns the Ipv4 interface to bind the multicast listener to.
  ///
  /// ## Example
  ///
  /// ```rust
  /// use agnostic_mdns::ServerOptions;
  /// use std::net::Ipv4Addr;
  ///
  /// let opts = ServerOptions::new().with_ipv4_interface(Ipv4Addr::new(192, 168, 1, 1));
  /// assert_eq!(opts.ipv4_interface(), Some(&Ipv4Addr::new(192, 168, 1, 1)));
  /// ```
  #[inline]
  pub const fn ipv4_interface(&self) -> Option<&Ipv4Addr> {
    self.ipv4_interface.as_ref()
  }

  /// Sets the IPv4 interface to bind the multicast listener to.
  ///
  /// ## Example
  ///
  /// ```rust
  /// use agnostic_mdns::ServerOptions;
  /// use std::net::Ipv4Addr;
  ///
  /// let opts = ServerOptions::new().with_ipv4_interface(Ipv4Addr::new(192, 168, 1, 1));
  /// ```
  #[inline]
  pub fn with_ipv4_interface(mut self, iface: Ipv4Addr) -> Self {
    self.ipv4_interface = Some(iface);
    self
  }

  /// Returns the Ipv6 interface to bind the multicast listener to.
  ///
  /// ## Example
  ///
  /// ```rust
  /// use agnostic_mdns::ServerOptions;
  ///
  /// let opts = ServerOptions::new().with_ipv6_interface(1);
  /// assert_eq!(opts.ipv6_interface(), Some(1));
  /// ```
  #[inline]
  pub const fn ipv6_interface(&self) -> Option<u32> {
    self.ipv6_interface
  }

  /// Sets the IPv6 interface to bind the multicast listener to.
  ///
  /// ## Example
  ///
  /// ```rust
  /// use agnostic_mdns::ServerOptions;
  ///
  /// let opts = ServerOptions::new().with_ipv6_interface(1);
  /// ```
  #[inline]
  pub fn with_ipv6_interface(mut self, index: u32) -> Self {
    self.ipv6_interface = Some(index);
    self
  }

  /// Sets whether the server should print an informative message
  /// when there is an mDNS query for which the server has no response.
  ///
  /// Default is `false`.
  ///
  /// ## Example
  ///
  /// ```rust
  /// use agnostic_mdns::ServerOptions;
  ///
  /// let opts = ServerOptions::new().with_log_empty_responses(true);
  /// assert_eq!(opts.log_empty_responses(), true);
  /// ```
  #[inline]
  pub fn with_log_empty_responses(mut self, log_empty_responses: bool) -> Self {
    self.log_empty_responses = log_empty_responses;
    self
  }

  /// Returns whether the server should print an informative message
  /// when there is an mDNS query for which the server has no response.
  ///
  /// ## Example
  ///
  /// ```rust
  /// use agnostic_mdns::ServerOptions;
  ///
  /// let opts = ServerOptions::new().with_log_empty_responses(true);
  /// assert_eq!(opts.log_empty_responses(), true);
  /// ```
  #[inline]
  pub const fn log_empty_responses(&self) -> bool {
    self.log_empty_responses
  }
}

/// Types for `tokio` runtime
#[cfg(feature = "tokio")]
#[cfg_attr(docsrs, doc(cfg(feature = "tokio")))]
pub mod tokio {
  use std::io;

  use super::{Lookup, QueryParam, service::Service};
  pub use agnostic_net::{runtime::tokio::TokioRuntime as Runtime, tokio::Net};
  use smol_str::SmolStr;

  /// A server that can be used with `tokio` runtime
  pub type Server = super::worksteal::Server<Net, Service>;

  /// Looks up a given service, in a domain, waiting at most
  /// for a timeout before finishing the query. The results are streamed
  /// to a channel. Sends will not block, so clients should make sure to
  /// either read or buffer. This method will attempt to stop the query
  /// on cancellation.
  #[inline]
  pub async fn query_with(params: QueryParam) -> io::Result<Lookup> {
    super::client::query_with::<Net>(params).await
  }

  /// Similar to [`query_with`], however it uses all the default parameters
  #[inline]
  pub async fn lookup(service: SmolStr) -> io::Result<Lookup> {
    query_with(QueryParam::new(service)).await
  }
}

/// Types for `smol` runtime
#[cfg(feature = "smol")]
#[cfg_attr(docsrs, doc(cfg(feature = "smol")))]
pub mod smol {
  use super::{Lookup, QueryParam, service::Service};
  use std::io;

  pub use agnostic_net::{runtime::smol::SmolRuntime as Runtime, smol::Net};
  use smol_str::SmolStr;

  /// A server that can be used with `smol` runtime
  pub type Server = super::worksteal::Server<Net, Service>;

  /// Looks up a given service, in a domain, waiting at most
  /// for a timeout before finishing the query. The results are streamed
  /// to a channel. Sends will not block, so clients should make sure to
  /// either read or buffer. This method will attempt to stop the query
  /// on cancellation.
  #[inline]
  pub async fn query_with(params: QueryParam) -> io::Result<Lookup> {
    super::client::query_with::<Net>(params).await
  }

  /// Similar to [`query_with`], however it uses all the default parameters
  #[inline]
  pub async fn lookup(service: SmolStr) -> io::Result<Lookup> {
    query_with(QueryParam::new(service)).await
  }
}

/// Types for `async-std` runtime
#[cfg(feature = "async-std")]
#[cfg_attr(docsrs, doc(cfg(feature = "async-std")))]
pub mod async_std {
  use super::{Lookup, QueryParam, service::Service};
  use std::io;

  pub use agnostic_net::{async_std::Net, runtime::async_std::AsyncStdRuntime as Runtime};
  use smol_str::SmolStr;

  /// A server that can be used with `async-std` runtime
  pub type Server = super::worksteal::Server<Net, Service>;

  /// Looks up a given service, in a domain, waiting at most
  /// for a timeout before finishing the query. The results are streamed
  /// to a channel. Sends will not block, so clients should make sure to
  /// either read or buffer. This method will attempt to stop the query
  /// on cancellation.
  #[inline]
  pub async fn query_with(params: QueryParam) -> io::Result<Lookup> {
    super::client::query_with::<Net>(params).await
  }

  /// Similar to [`query_with`], however it uses all the default parameters
  #[inline]
  pub async fn lookup(service: SmolStr) -> io::Result<Lookup> {
    query_with(QueryParam::new(service)).await
  }
}

mod utils;

/// Returns `true` if a domain name is fully qualified domain name
#[inline]
pub fn is_fqdn(s: &str) -> bool {
  let len = s.len();
  if s.is_empty() || !s.ends_with('.') {
    return false;
  }

  let s = &s[..len - 1];

  if s.is_empty() || !s.ends_with('\\') {
    return true;
  }

  // Count backslashes at the end
  let last_non_backslash = s.rfind(|c| c != '\\').unwrap_or(0);

  (len - last_non_backslash) % 2 == 0
}

/// Returns the hostname of the current machine.
///
/// On wasm target, this function always returns `None`.
///
/// ## Examples
///
/// ```
/// use agnostic_mdns::hostname;
///
/// let hostname = hostname();
/// println!("hostname: {hostname:?}");
/// ```
#[allow(unreachable_code)]
pub fn hostname() -> io::Result<SmolStr> {
  #[cfg(not(any(windows, target_os = "wasi")))]
  return {
    let name = rustix::system::uname();
    let name = name.nodename().to_string_lossy();
    Ok(SmolStr::from(name.as_ref()))
  };

  #[cfg(windows)]
  return {
    match ::hostname::get() {
      Ok(name) => {
        let name = name.to_string_lossy();
        Ok(SmolStr::from(name.as_ref()))
      }
      Err(e) => Err(e),
    }
  };

  Err(io::Error::new(
    io::ErrorKind::Unsupported,
    "hostname is not supported on this platform",
  ))
}

fn hostname_fqdn() -> io::Result<SmolStr> {
  #[cfg(not(any(windows, target_os = "wasi")))]
  return {
    let name = rustix::system::uname();
    let name = name.nodename().to_string_lossy();
    Ok(format_smolstr!("{}.", name.as_ref()))
  };

  #[cfg(windows)]
  return {
    match ::hostname::get() {
      Ok(name) => {
        let name = name.to_string_lossy();
        Ok(format_smolstr!("{}.", name.as_ref()))
      }
      Err(e) => Err(e),
    }
  };

  Err(io::Error::new(
    io::ErrorKind::Unsupported,
    "hostname is not supported on this platform",
  ))
}

fn invalid_input_err<E>(e: E) -> io::Error
where
  E: Into<Box<dyn std::error::Error + Send + Sync>>,
{
  io::Error::new(io::ErrorKind::InvalidInput, e)
}

fn invalid_data_err<E>(e: E) -> io::Error
where
  E: Into<Box<dyn std::error::Error + Send + Sync>>,
{
  io::Error::new(io::ErrorKind::InvalidData, e)
}

#[allow(clippy::large_enum_variant)]
enum Buffer {
  Heap(Vec<u8>),
  Stack([u8; MAX_INLINE_PACKET_SIZE]),
}

impl Buffer {
  fn zerod(cap: usize) -> Self {
    if cap <= MAX_INLINE_PACKET_SIZE {
      Buffer::Stack([0; MAX_INLINE_PACKET_SIZE])
    } else {
      Buffer::Heap(vec![0; cap])
    }
  }
}

impl From<usize> for Buffer {
  fn from(size: usize) -> Self {
    if size <= MAX_INLINE_PACKET_SIZE {
      Buffer::Stack([0; MAX_INLINE_PACKET_SIZE])
    } else {
      Buffer::Heap(vec![0; size])
    }
  }
}

impl core::ops::Deref for Buffer {
  type Target = [u8];

  fn deref(&self) -> &[u8] {
    match self {
      Buffer::Heap(v) => v,
      Buffer::Stack(v) => v,
    }
  }
}

impl core::ops::DerefMut for Buffer {
  fn deref_mut(&mut self) -> &mut [u8] {
    match self {
      Buffer::Heap(v) => v,
      Buffer::Stack(v) => v,
    }
  }
}

#[test]
fn test_label() {
  use mdns_proto::{Flags, Label, Message, Question, ResourceType};

  let label = Label::from("My server");
  println!("label: {}", label);

  let mut q = [Question::new(label, ResourceType::Ptr, 0)];
  let msg = Message::new(0, Flags::new(), &mut q, &mut [], &mut [], &mut []);
  let mut buf = [0; 1024];
  let len = msg.write(&mut buf).unwrap();
  println!("msg: {:?}", &buf[..len]);
}
