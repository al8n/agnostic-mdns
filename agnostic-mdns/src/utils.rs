use std::{
  io,
  net::{Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket as StdUdpSocket},
};

use crate::{IPV4_MDNS, IPV6_MDNS};

#[cfg(unix)]
pub(crate) use unix_impl::*;

#[cfg(unix)]
mod unix_impl {
  use super::*;
  use rustix::net::{AddressFamily, SocketType, bind, ipproto, socket, sockopt};
  use std::net::UdpSocket;

  pub(crate) fn unicast_udp4_socket(ifi: Option<Ipv4Addr>) -> io::Result<UdpSocket> {
    let sock = socket(AddressFamily::INET, SocketType::DGRAM, Some(ipproto::UDP))?;
    let addr: SocketAddr = (Ipv4Addr::UNSPECIFIED, 0).into();
    bind(&sock, &addr)?;

    if let Some(ifi) = ifi {
      if !ifi.is_unspecified() {
        sockopt::set_ip_multicast_if(&sock, &ifi)?;
      }
    }

    let sock = StdUdpSocket::from(sock);
    sock.set_nonblocking(true)?;
    Ok(sock)
  }

  pub(crate) fn unicast_udp6_socket(ifi: Option<u32>) -> io::Result<UdpSocket> {
    let sock = socket(AddressFamily::INET6, SocketType::DGRAM, Some(ipproto::UDP))?;
    sockopt::set_ipv6_v6only(&sock, true)?;

    let addr: SocketAddr = (Ipv6Addr::UNSPECIFIED, 0).into();
    bind(&sock, &addr)?;

    if let Some(ifi) = ifi {
      if ifi != 0 {
        sockopt::set_ipv6_multicast_if(&sock, ifi)?;
      }
    }

    let sock = StdUdpSocket::from(sock);
    sock.set_nonblocking(true)?;
    Ok(sock)
  }

  pub(crate) fn multicast_udp4_socket(ifi: Option<Ipv4Addr>, port: u16) -> io::Result<UdpSocket> {
    let sock = socket(AddressFamily::INET, SocketType::DGRAM, Some(ipproto::UDP))?;
    sockopt::set_socket_reuseaddr(&sock, true)?;
    sockopt::set_socket_reuseport(&sock, true)?;

    let addr: SocketAddr = (Ipv4Addr::UNSPECIFIED, port).into();
    bind(&sock, &addr)?;

    if let Some(ifi) = ifi {
      if !ifi.is_unspecified() {
        sockopt::set_ip_multicast_if(&sock, &ifi)?;
      }
    }

    let sock = StdUdpSocket::from(sock);
    sock.set_nonblocking(true)?;
    sock.join_multicast_v4(&IPV4_MDNS, &ifi.unwrap_or(Ipv4Addr::UNSPECIFIED))?;
    sock.set_multicast_loop_v4(true)?;
    Ok(sock)
  }

  pub(crate) fn multicast_udp6_socket(ifi: Option<u32>, port: u16) -> io::Result<UdpSocket> {
    let sock = socket(AddressFamily::INET6, SocketType::DGRAM, Some(ipproto::UDP))?;
    sockopt::set_socket_reuseaddr(&sock, true)?;
    sockopt::set_socket_reuseport(&sock, true)?;
    sockopt::set_ipv6_v6only(&sock, true)?;

    let addr: SocketAddr = (Ipv6Addr::UNSPECIFIED, port).into();
    bind(&sock, &addr)?;

    if let Some(ifi) = ifi {
      if ifi != 0 {
        sockopt::set_ipv6_multicast_if(&sock, ifi)?;
      }
    }

    let sock = StdUdpSocket::from(sock);
    sock.join_multicast_v6(&IPV6_MDNS, ifi.unwrap_or(0))?;
    sock.set_multicast_loop_v6(true)?;
    sock.set_nonblocking(true)?;
    Ok(sock)
  }
}

#[cfg(windows)]
pub(crate) use windows_impl::*;

#[cfg(windows)]
mod windows_impl {
  use super::*;
  use socket2::{Domain, Protocol, Socket, Type};
  use std::net::UdpSocket;

  pub(crate) fn unicast_udp4_socket(ifi: Option<Ipv4Addr>) -> io::Result<UdpSocket> {
    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    let addr: SocketAddr = (Ipv4Addr::UNSPECIFIED, 0).into();
    sock.bind(&addr.into())?;

    if let Some(ifi) = ifi {
      if !ifi.is_unspecified() {
        sock.set_multicast_if_v4(&ifi)?;
      }
    }

    let sock = StdUdpSocket::from(sock);
    sock.set_nonblocking(true)?;
    Ok(sock)
  }

  pub(crate) fn unicast_udp6_socket(ifi: Option<u32>) -> io::Result<UdpSocket> {
    let sock = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
    sock.set_only_v6(true)?;
    let addr: SocketAddr = (Ipv6Addr::UNSPECIFIED, 0).into();
    sock.bind(&addr.into())?;

    if let Some(ifi) = ifi {
      if ifi != 0 {
        sock.set_multicast_if_v6(ifi)?;
      }
    }

    let sock = StdUdpSocket::from(sock);
    sock.set_nonblocking(true)?;
    Ok(sock)
  }

  pub(crate) fn multicast_udp4_socket(ifi: Option<Ipv4Addr>, port: u16) -> io::Result<UdpSocket> {
    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    sock.set_reuse_address(true)?;
    let addr: SocketAddr = (Ipv4Addr::UNSPECIFIED, port).into();
    sock.bind(&addr.into())?;

    if let Some(ifi) = ifi {
      if !ifi.is_unspecified() {
        sock.set_multicast_if_v4(&ifi)?;
      }
    }

    let sock = StdUdpSocket::from(sock);
    sock.set_nonblocking(true)?;
    sock.join_multicast_v4(&IPV4_MDNS, &ifi.unwrap_or(Ipv4Addr::UNSPECIFIED))?;
    sock.set_multicast_loop_v4(true)?;

    Ok(sock)
  }

  pub(crate) fn multicast_udp6_socket(ifi: Option<u32>, port: u16) -> io::Result<UdpSocket> {
    let sock = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
    sock.set_reuse_address(true)?;
    sock.set_only_v6(true)?;
    let addr: SocketAddr = (Ipv6Addr::UNSPECIFIED, port).into();
    sock.bind(&addr.into())?;

    if let Some(ifi) = ifi {
      if ifi != 0 {
        sock.set_multicast_if_v6(ifi)?;
      }
    }

    let sock = StdUdpSocket::from(sock);
    sock.join_multicast_v6(&IPV6_MDNS, ifi.unwrap_or(0))?;
    sock.set_multicast_loop_v6(true)?;
    sock.set_nonblocking(true)?;

    Ok(sock)
  }
}
