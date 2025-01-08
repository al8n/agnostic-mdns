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
pub mod client;
/// mDNS server
pub mod server;

mod types;
use smol_str::format_smolstr;
pub use smol_str::SmolStr;
pub use types::{DNSClass, Name, RecordData, RecordHeader, UnknownRecordTypeStr};

/// Types for `tokio` runtime
#[cfg(feature = "tokio")]
pub mod tokio {
  pub use agnostic::tokio::TokioRuntime;

  /// A service that can be used with `tokio` runtime
  pub type TokioService = super::Service<TokioRuntime>;
}

/// Types for `smol` runtime
#[cfg(feature = "smol")]
pub mod smol {
  pub use agnostic::smol::SmolRuntime;

  /// A service that
  /// can be used with `smol` runtime
  pub type SmolService = super::Service<SmolRuntime>;
}

/// Types for `async-std` runtime
#[cfg(feature = "async-std")]
pub mod async_std {
  pub use agnostic::async_std::AsyncStdRuntime;

  /// A service that can be used with `async-std` runtime
  pub type AsyncStdService = super::Service<AsyncStdRuntime>;
}

pub use agnostic::{self, Runtime, RuntimeLite};

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
