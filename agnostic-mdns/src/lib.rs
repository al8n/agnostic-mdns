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
  time::Duration,
};

const IPV4_MDNS: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
const IPV6_MDNS: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb);
const IPV4_SIZE: usize = core::mem::size_of::<Ipv4Addr>();
const IPV6_SIZE: usize = core::mem::size_of::<Ipv6Addr>();
const MDNS_PORT: u16 = 5353;
// See RFC 6762, https://datatracker.ietf.org/doc/rfc6762/
const MAX_PAYLOAD_SIZE: usize = 9000;
const MAX_INLINE_PACKET_SIZE: usize = 512;

pub use mdns_proto::{proto::Label, error};

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

pub use iprobe as netprobe;
pub use smol_str::{SmolStr, format_smolstr};

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

/// How a lookup is performed.
#[derive(Clone, Debug)]
pub struct QueryParam<'a> {
  service: Label<'a>,
  domain: Label<'a>,
  timeout: Duration,
  ipv4_interface: Option<Ipv4Addr>,
  ipv6_interface: Option<u32>,
  cap: Option<usize>,
  want_unicast_response: bool, // Unicast response desired, as per 5.4 in RFC
  // Whether to disable usage of IPv4 for MDNS operations. Does not affect discovered addresses.
  disable_ipv4: bool,
  // Whether to disable usage of IPv6 for MDNS operations. Does not affect discovered addresses.
  disable_ipv6: bool,
}

impl<'a> QueryParam<'a> {
  /// Creates a new query parameter with default values.
  #[inline]
  pub fn new(service: Label<'a>) -> Self {
    Self {
      service,
      domain: Label::from("local"),
      timeout: Duration::from_secs(1),
      ipv4_interface: None,
      ipv6_interface: None,
      want_unicast_response: false,
      disable_ipv4: false,
      disable_ipv6: false,
      cap: None,
    }
  }

  /// Sets the domain to search in.
  ///
  /// ## Example
  ///
  /// ```rust
  /// use agnostic_mdns::QueryParam;
  ///
  /// let params = QueryParam::new("service._tcp".into())
  ///   .with_domain("local.".into());
  /// ```
  pub fn with_domain(mut self, domain: Label<'a>) -> Self {
    self.domain = domain;
    self
  }

  /// Returns the domain to search in.
  ///
  /// ## Example
  ///
  /// ```rust
  /// use agnostic_mdns::{QueryParam, proto::Label};
  ///
  /// let params = QueryParam::new("service._tcp".into())
  ///   .with_domain("local.".into());
  ///
  /// assert_eq!(params.domain(), Label::from("local"));
  pub const fn domain(&self) -> &Label<'a> {
    &self.domain
  }

  /// Sets the service to search for.
  ///
  /// ## Example
  ///
  /// ```rust
  /// use agnostic_mdns::QueryParam;
  ///
  /// let params = QueryParam::new("service._tcp".into())
  ///   .with_service("service._udp".into());
  /// ```
  pub fn with_service(mut self, service: Label<'a>) -> Self {
    self.service = service;
    self
  }

  /// Returns the service to search for.
  ///
  /// ## Example
  ///
  /// ```rust
  /// use agnostic_mdns::QueryParam;
  ///
  /// let params = QueryParam::new("service._tcp".into())
  ///   .with_service("service._udp".into());
  ///
  /// assert_eq!(params.service().as_str(), "service._udp");
  pub const fn service(&self) -> &Label<'a> {
    &self.service
  }

  /// Sets the timeout for the query.
  ///
  /// ## Example
  ///
  /// ```rust
  /// use agnostic_mdns::QueryParam;
  ///
  /// let params = QueryParam::new("service._tcp".into())
  ///   .with_timeout(std::time::Duration::from_secs(1));
  /// ```
  pub fn with_timeout(mut self, timeout: Duration) -> Self {
    self.timeout = timeout;
    self
  }

  /// Returns the timeout for the query.
  ///
  /// ## Example
  ///
  /// ```rust
  /// use agnostic_mdns::QueryParam;
  ///
  /// let params = QueryParam::new("service._tcp".into())
  ///   .with_timeout(std::time::Duration::from_secs(1));
  ///
  /// assert_eq!(params.timeout(), std::time::Duration::from_secs(1));
  /// ```
  pub const fn timeout(&self) -> Duration {
    self.timeout
  }

  /// Sets the IPv4 interface to use for queries.
  ///
  /// ## Example
  ///
  /// ```rust
  /// use agnostic_mdns::QueryParam;
  ///
  /// let params = QueryParam::new("service._tcp".into())
  ///   .with_ipv4_interface("0.0.0.0".parse().unwrap());
  /// ```
  pub fn with_ipv4_interface(mut self, ipv4_interface: Ipv4Addr) -> Self {
    self.ipv4_interface = Some(ipv4_interface);
    self
  }

  /// Returns the IPv4 interface to use for queries.
  ///
  /// ## Example
  ///
  /// ```rust
  /// use agnostic_mdns::QueryParam;
  ///
  /// let params = QueryParam::new("service._tcp".into())
  ///  .with_ipv4_interface("0.0.0.0".parse().unwrap());
  ///
  /// assert_eq!(params.ipv4_interface().unwrap(), &"0.0.0.0".parse::<std::net::Ipv4Addr>().unwrap());
  /// ```
  pub const fn ipv4_interface(&self) -> Option<&Ipv4Addr> {
    self.ipv4_interface.as_ref()
  }

  /// Sets the IPv6 interface to use for queries.
  ///
  /// ## Example
  ///
  /// ```rust
  /// use agnostic_mdns::QueryParam;
  ///
  /// let params = QueryParam::new("service._tcp".into())
  ///   .with_ipv6_interface(1);
  /// ```
  pub fn with_ipv6_interface(mut self, ipv6_interface: u32) -> Self {
    self.ipv6_interface = Some(ipv6_interface);
    self
  }

  /// Returns the IPv6 interface to use for queries.
  ///
  /// ## Example
  ///
  /// ```rust
  /// use agnostic_mdns::QueryParam;
  ///
  /// let params = QueryParam::new("service._tcp".into())
  ///   .with_ipv6_interface(1);
  /// assert_eq!(params.ipv6_interface().unwrap(), 1);
  /// ```
  pub const fn ipv6_interface(&self) -> Option<u32> {
    self.ipv6_interface
  }

  /// Sets whether to request unicast responses.
  ///
  /// ## Example
  ///
  /// ```rust
  /// use agnostic_mdns::QueryParam;
  ///
  /// let params = QueryParam::new("service._tcp".into())
  ///   .with_unicast_response(true);
  /// ```
  pub fn with_unicast_response(mut self, want_unicast_response: bool) -> Self {
    self.want_unicast_response = want_unicast_response;
    self
  }

  /// Returns whether to request unicast responses.
  ///
  /// ## Example
  ///
  /// ```rust
  /// use agnostic_mdns::QueryParam;
  ///
  /// let params = QueryParam::new("service._tcp".into())
  ///   .with_unicast_response(true);
  ///
  /// assert_eq!(params.want_unicast_response(), true);
  /// ```
  pub const fn want_unicast_response(&self) -> bool {
    self.want_unicast_response
  }

  /// Sets whether to disable IPv4 for MDNS operations.
  ///
  /// ## Example
  ///
  /// ```rust
  /// use agnostic_mdns::QueryParam;
  ///
  /// let params = QueryParam::new("service._tcp".into())
  ///   .with_disable_ipv4(true);
  /// ```
  pub fn with_disable_ipv4(mut self, disable_ipv4: bool) -> Self {
    self.disable_ipv4 = disable_ipv4;
    self
  }

  /// Returns whether to disable IPv4 for MDNS operations.
  ///
  /// ## Example
  ///
  /// ```rust
  /// use agnostic_mdns::QueryParam;
  ///
  /// let params = QueryParam::new("service._tcp".into())
  ///   .with_disable_ipv4(true);
  ///
  /// assert_eq!(params.disable_ipv4(), true);
  /// ```
  pub const fn disable_ipv4(&self) -> bool {
    self.disable_ipv4
  }

  /// Sets whether to disable IPv6 for MDNS operations.
  ///
  /// ## Example
  ///
  /// ```rust
  /// use agnostic_mdns::QueryParam;
  ///
  /// let params = QueryParam::new("service._tcp".into())
  ///   .with_disable_ipv6(true);
  /// ```
  pub fn with_disable_ipv6(mut self, disable_ipv6: bool) -> Self {
    self.disable_ipv6 = disable_ipv6;
    self
  }

  /// Returns whether to disable IPv6 for MDNS operations.
  ///
  /// ## Example
  ///
  /// ```rust
  /// use agnostic_mdns::QueryParam;
  ///
  /// let params = QueryParam::new("service._tcp".into())
  ///   .with_disable_ipv6(true);
  ///
  /// assert_eq!(params.disable_ipv6(), true);
  /// ```
  pub const fn disable_ipv6(&self) -> bool {
    self.disable_ipv6
  }

  /// Returns the channel capacity for the [`Lookup`] stream.
  ///
  /// If `None`, the channel is unbounded.
  ///
  /// Default is `None`.
  ///
  /// ## Example
  ///
  /// ```rust
  /// use agnostic_mdns::QueryParam;
  ///
  /// let params = QueryParam::new("service._tcp".into())
  ///   .with_capacity(Some(10));
  ///
  /// assert_eq!(params.capacity().unwrap(), 10);
  /// ```
  #[inline]
  pub const fn capacity(&self) -> Option<usize> {
    self.cap
  }

  /// Sets the channel capacity for the [`Lookup`] stream.
  ///
  /// If `None`, the channel is unbounded.
  ///
  /// Default is `None`.
  ///
  /// ## Example
  ///
  /// ```rust
  /// use agnostic_mdns::QueryParam;
  ///
  /// let params = QueryParam::new("service._tcp".into())
  ///  .with_capacity(Some(10));
  /// ```
  #[inline]
  pub fn with_capacity(mut self, cap: Option<usize>) -> Self {
    self.cap = cap;
    self
  }
}

/// Types for `tokio` runtime
#[cfg(feature = "tokio")]
#[cfg_attr(docsrs, doc(cfg(feature = "tokio")))]
pub mod tokio {
  use std::io;

  use super::{worksteal::Lookup, QueryParam, service::Service};
  pub use agnostic_net::{runtime::tokio::TokioRuntime as Runtime, tokio::Net};
  use mdns_proto::proto::Label;

  /// A server that can be used with `tokio` runtime
  pub type Server = super::worksteal::Server<Net, Service>;

  /// Looks up a given service, in a domain, waiting at most
  /// for a timeout before finishing the query. The results are streamed
  /// to a channel. Sends will not block, so clients should make sure to
  /// either read or buffer. This method will attempt to stop the query
  /// on cancellation.
  #[inline]
  pub async fn query_with(params: QueryParam<'_>) -> io::Result<Lookup> {
    super::worksteal::query_with::<Net>(params).await
  }

  /// Similar to [`query_with`], however it uses all the default parameters
  #[inline]
  pub async fn lookup(service: Label<'_>) -> io::Result<Lookup> {
    super::worksteal::lookup::<Net>(service).await
  }
}

/// Types for `smol` runtime
#[cfg(feature = "smol")]
#[cfg_attr(docsrs, doc(cfg(feature = "smol")))]
pub mod smol {
  use super::{worksteal::Lookup, QueryParam, Label, service::Service};
  use std::io;

  pub use agnostic_net::{runtime::smol::SmolRuntime as Runtime, smol::Net};

  /// A server that can be used with `smol` runtime
  pub type Server = super::worksteal::Server<Net, Service>;

  /// Looks up a given service, in a domain, waiting at most
  /// for a timeout before finishing the query. The results are streamed
  /// to a channel. Sends will not block, so clients should make sure to
  /// either read or buffer. This method will attempt to stop the query
  /// on cancellation.
  #[inline]
  pub async fn query_with(params: QueryParam<'_>) -> io::Result<Lookup> {
    super::worksteal::query_with::<Net>(params).await
  }

  /// Similar to [`query_with`], however it uses all the default parameters
  #[inline]
  pub async fn lookup(service: Label<'_>) -> io::Result<Lookup> {
    super::worksteal::lookup::<Net>(service).await
  }
}

/// Types for `async-std` runtime
#[cfg(feature = "async-std")]
#[cfg_attr(docsrs, doc(cfg(feature = "async-std")))]
pub mod async_std {
  use super::{worksteal::Lookup, QueryParam, Label, service::Service};
  use std::io;

  pub use agnostic_net::{async_std::Net, runtime::async_std::AsyncStdRuntime as Runtime};

  /// A server that can be used with `async-std` runtime
  pub type Server = super::worksteal::Server<Net, Service>;

  /// Looks up a given service, in a domain, waiting at most
  /// for a timeout before finishing the query. The results are streamed
  /// to a channel. Sends will not block, so clients should make sure to
  /// either read or buffer. This method will attempt to stop the query
  /// on cancellation.
  #[inline]
  pub async fn query_with(params: QueryParam<'_>) -> io::Result<Lookup> {
    super::worksteal::query_with::<Net>(params).await
  }

  /// Similar to [`query_with`], however it uses all the default parameters
  #[inline]
  pub async fn lookup(service: Label<'_>) -> io::Result<Lookup> {
    super::worksteal::lookup::<Net>(service).await
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
    Ok(format_smolstr!("{}.", Label::from(name.as_ref())))
  };

  #[cfg(windows)]
  return {
    match ::hostname::get() {
      Ok(name) => {
        let name = name.to_string_lossy();
        Ok(format_smolstr!("{}.", Label::from(name.as_ref())))
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


#[allow(clippy::large_enum_variant)]
#[derive(Clone)]
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
