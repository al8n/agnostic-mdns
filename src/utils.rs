use agnostic::{net::Net, Runtime};
use socket2::{Domain, Protocol, Socket, Type};
use std::{
  io,
  net::{Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket as StdUdpSocket},
};

pub(crate) fn multicast_udp4_socket<R: Runtime>(
  port: u16,
) -> io::Result<<R::Net as Net>::UdpSocket> {
  let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
  sock.set_reuse_address(true)?;
  sock.set_reuse_port(true)?;
  // sock.set_nonblocking(true)?;
  let addr: SocketAddr = (Ipv4Addr::UNSPECIFIED, port).into();
  sock.bind(&addr.into()).and_then(|_| {
    let sock = StdUdpSocket::from(sock);
    <<R::Net as Net>::UdpSocket as TryFrom<_>>::try_from(sock)
  })
}

pub(crate) fn multicast_udp6_socket<R: Runtime>(
  port: u16,
) -> io::Result<<R::Net as Net>::UdpSocket> {
  let sock = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
  sock.set_reuse_address(true)?;
  sock.set_reuse_port(true)?;
  // sock.set_nonblocking(true)?;
  sock.set_only_v6(true)?;
  let addr: SocketAddr = (Ipv6Addr::UNSPECIFIED, port).into();
  sock.bind(&addr.into()).and_then(|_| {
    let sock = StdUdpSocket::from(sock);
    <<R::Net as Net>::UdpSocket as TryFrom<_>>::try_from(sock)
  })
}
