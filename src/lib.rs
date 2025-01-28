#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]
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
const MDNS_PORT: u16 = 5353;
// See RFC 6762, https://datatracker.ietf.org/doc/rfc6762/
const MAX_PAYLOAD_SIZE: usize = 9000;

/// mDNS client
mod client;
pub use client::*;

/// mDNS server
mod server;
pub use server::*;

mod types;
use smol_str::format_smolstr;

pub use iprobe as netprobe;
pub use smol_str::SmolStr;
pub use types::*;

/// Types for `tokio` runtime
#[cfg(feature = "tokio")]
#[cfg_attr(docsrs, doc(cfg(feature = "tokio")))]
pub mod tokio {
  use std::io;

  pub use agnostic_net::{runtime::tokio::TokioRuntime as Runtime, tokio::Net};

  use super::{Lookup, Name, QueryParam};

  /// A service that can be used with `tokio` runtime
  pub type Service = super::Service<Runtime>;

  /// A server that can be used with `tokio` runtime
  pub type Server = super::server::Server<Net, Service>;

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
  pub async fn lookup(service: Name) -> io::Result<Lookup> {
    query_with(QueryParam::new(service)).await
  }
}

/// Types for `smol` runtime
#[cfg(feature = "smol")]
#[cfg_attr(docsrs, doc(cfg(feature = "smol")))]
pub mod smol {
  use super::{Lookup, Name, QueryParam};
  use std::io;

  pub use agnostic_net::{runtime::smol::SmolRuntime as Runtime, smol::Net};

  /// A service that can be used with `smol` runtime
  pub type Service = super::Service<Runtime>;

  /// A server that can be used with `smol` runtime
  pub type Server = super::server::Server<Net, Service>;

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
  pub async fn lookup(service: Name) -> io::Result<Lookup> {
    query_with(QueryParam::new(service)).await
  }
}

/// Types for `async-std` runtime
#[cfg(feature = "async-std")]
#[cfg_attr(docsrs, doc(cfg(feature = "async-std")))]
pub mod async_std {
  use super::{Lookup, Name, QueryParam};
  use std::io;

  pub use agnostic_net::{async_std::Net, runtime::async_std::AsyncStdRuntime as Runtime};

  /// A service that can be used with `async-std` runtime
  pub type Service = super::Service<Runtime>;

  /// A server that can be used with `async-std` runtime
  pub type Server = super::server::Server<Net, Service>;

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
  pub async fn lookup(service: Name) -> io::Result<Lookup> {
    query_with(QueryParam::new(service)).await
  }
}

pub use agnostic_net as net;

mod zone;
pub use zone::*;

mod utils;

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
