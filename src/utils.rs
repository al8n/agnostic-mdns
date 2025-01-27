use agnostic_net::Net;
use socket2::{Domain, Protocol, Socket, Type};
use std::{
  io,
  net::{Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket as StdUdpSocket},
};

use crate::{IPV4_MDNS, IPV6_MDNS};

pub(crate) fn unicast_udp4_socket<N: Net>(ifi: Option<Ipv4Addr>) -> io::Result<N::UdpSocket> {
  let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
  let addr: SocketAddr = (Ipv4Addr::UNSPECIFIED, 0).into();
  sock.bind(&addr.into())?;

  if let Some(ifi) = ifi {
    if !ifi.is_unspecified() {
      sock.set_multicast_if_v4(&ifi)?;
    }
  }
  sock.set_nonblocking(true)?;

  let sock = StdUdpSocket::from(sock);
  <N::UdpSocket as TryFrom<_>>::try_from(sock)
}

pub(crate) fn unicast_udp6_socket<N>(ifi: Option<u32>) -> io::Result<N::UdpSocket>
where
  N: Net,
{
  let sock = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
  sock.set_only_v6(true)?;
  let addr: SocketAddr = (Ipv6Addr::UNSPECIFIED, 0).into();
  sock.bind(&addr.into())?;

  if let Some(ifi) = ifi {
    if ifi != 0 {
      sock.set_multicast_if_v6(ifi)?;
    }
  }

  sock.set_nonblocking(true)?;
  let sock = StdUdpSocket::from(sock);
  <N::UdpSocket as TryFrom<_>>::try_from(sock)
}

pub(crate) fn multicast_udp4_socket<N>(ifi: Option<Ipv4Addr>, port: u16) -> io::Result<N::UdpSocket>
where
  N: Net,
{
  let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
  sock.set_reuse_address(true)?;
  #[cfg(not(windows))]
  sock.set_reuse_port(true)?;
  let addr: SocketAddr = (Ipv4Addr::UNSPECIFIED, port).into();
  sock.bind(&addr.into())?;

  if let Some(ifi) = ifi {
    if !ifi.is_unspecified() {
      sock.set_multicast_if_v4(&ifi)?;
    }
  }

  sock.set_multicast_loop_v4(true)?;
  sock.join_multicast_v4(&IPV4_MDNS, &ifi.unwrap_or(Ipv4Addr::UNSPECIFIED))?;
  sock.set_nonblocking(true)?;

  let sock = StdUdpSocket::from(sock);
  <N::UdpSocket as TryFrom<_>>::try_from(sock)
}

pub(crate) fn multicast_udp6_socket<N>(ifi: Option<u32>, port: u16) -> io::Result<N::UdpSocket>
where
  N: Net,
{
  let sock = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
  sock.set_reuse_address(true)?;
  #[cfg(not(windows))]
  sock.set_reuse_port(true)?;
  sock.set_only_v6(true)?;
  let addr: SocketAddr = (Ipv6Addr::UNSPECIFIED, port).into();
  sock.bind(&addr.into())?;

  if let Some(ifi) = ifi {
    if ifi != 0 {
      sock.set_multicast_if_v6(ifi)?;
    }
  }

  sock.set_multicast_loop_v6(true)?;
  sock.join_multicast_v6(&IPV6_MDNS, ifi.unwrap_or(0))?;
  sock.set_nonblocking(true)?;

  let sock = StdUdpSocket::from(sock);
  <N::UdpSocket as TryFrom<_>>::try_from(sock)
}
