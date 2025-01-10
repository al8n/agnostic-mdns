use core::{
  net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
  time::Duration,
};
use std::{
  collections::{hash_map::Entry, HashMap},
  io,
  pin::Pin,
  task::{Context, Poll},
};

use agnostic::{
  net::{Net, UdpSocket},
  Runtime,
};
use async_channel::{Receiver, Sender};
use atomic_refcell::AtomicRefCell;
use futures::{FutureExt, Stream};
use iprobe::{ipv4, ipv6};
use smol_str::SmolStr;
use triomphe::Arc;

use crate::{
  types::{Message, Name, Query, RecordData},
  utils::{multicast_udp4_socket, multicast_udp6_socket, unicast_udp4_socket, unicast_udp6_socket},
  IPV4_MDNS, IPV6_MDNS, MAX_PAYLOAD_SIZE, MDNS_PORT,
};

/// Returned after we query for a service.
#[derive(Debug, Clone)]
pub struct ServiceEntry {
  name: Name,
  host: Name,
  socket_v4: Option<SocketAddrV4>,
  socket_v6: Option<SocketAddrV6>,
  infos: Arc<[SmolStr]>,
}

impl ServiceEntry {
  /// Returns the name of the service.
  #[inline]
  pub fn name(&self) -> &Name {
    &self.name
  }

  /// Returns the host of the service.
  #[inline]
  pub fn host(&self) -> &Name {
    &self.host
  }

  /// Returns the IPv4 address of the service.
  #[inline]
  pub const fn socket_v4(&self) -> Option<SocketAddrV4> {
    self.socket_v4
  }

  /// Returns the IPv6 address of the service.
  #[inline]
  pub const fn socket_v6(&self) -> Option<SocketAddrV6> {
    self.socket_v6
  }

  /// Returns the port of the service.
  #[inline]
  pub fn port(&self) -> u16 {
    if let Some(ref addr) = self.socket_v4 {
      return addr.port();
    }

    if let Some(ref addr) = self.socket_v6 {
      return addr.port();
    }

    unreachable!("must have a socket address")
  }

  /// Returns the additional information of the service.
  #[inline]
  pub fn infos(&self) -> &[SmolStr] {
    &self.infos
  }
}

/// Returned after we query for a service.
#[derive(Clone)]
struct ServiceEntryBuilder {
  name: Name,
  host: Name,
  port: u16,
  ipv4: Option<Ipv4Addr>,
  ipv6: Option<Ipv6Addr>,
  zone: Option<u32>,
  infos: Arc<[SmolStr]>,
  has_txt: bool,
  sent: bool,
}

impl Default for ServiceEntryBuilder {
  #[inline]
  fn default() -> Self {
    Self {
      name: Name::default(),
      host: Name::default(),
      port: 0,
      ipv4: None,
      ipv6: None,
      zone: None,
      has_txt: false,
      sent: false,
      infos: Arc::from_iter([]),
    }
  }
}

impl ServiceEntryBuilder {
  fn complete(&self) -> bool {
    (self.ipv4.is_some() || self.ipv6.is_some()) && self.port != 0 && self.has_txt
  }

  #[inline]
  fn with_name(mut self, name: Name) -> Self {
    self.name = name;
    self
  }

  #[inline]
  fn finalize(&self) -> ServiceEntry {
    ServiceEntry {
      name: self.name.clone(),
      host: self.host.clone(),
      socket_v4: self.ipv4.map(|ip| SocketAddrV4::new(ip, self.port)),
      socket_v6: self
        .ipv6
        .map(|ip| SocketAddrV6::new(ip, self.port, 0, self.zone.unwrap_or(0))),
      infos: self.infos.clone(),
    }
  }
}

/// How a lookup is performed.
#[derive(Clone, Debug)]
pub struct QueryParam {
  service: Name,
  domain: Name,
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

impl QueryParam {
  /// Creates a new query parameter with default values.
  #[inline]
  pub fn new(service: Name) -> Self {
    Self {
      service,
      domain: Name::local(),
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
  pub fn with_domain(mut self, domain: Name) -> Self {
    self.domain = domain;
    self
  }

  /// Returns the domain to search in.
  pub const fn domain(&self) -> &Name {
    &self.domain
  }

  /// Sets the service to search for.
  pub fn with_service(mut self, service: Name) -> Self {
    self.service = service;
    self
  }

  /// Returns the service to search for.
  pub const fn service(&self) -> &Name {
    &self.service
  }

  /// Sets the timeout for the query.
  pub fn with_timeout(mut self, timeout: Duration) -> Self {
    self.timeout = timeout;
    self
  }

  /// Returns the timeout for the query.
  pub const fn timeout(&self) -> Duration {
    self.timeout
  }

  /// Sets the IPv4 interface to use for queries.
  pub fn with_ipv4_interface(mut self, ipv4_interface: Ipv4Addr) -> Self {
    self.ipv4_interface = Some(ipv4_interface);
    self
  }

  /// Returns the IPv4 interface to use for queries.
  pub const fn ipv4_interface(&self) -> Option<&Ipv4Addr> {
    self.ipv4_interface.as_ref()
  }

  /// Sets the IPv6 interface to use for queries.
  pub fn with_ipv6_interface(mut self, ipv6_interface: u32) -> Self {
    self.ipv6_interface = Some(ipv6_interface);
    self
  }

  /// Returns the IPv6 interface to use for queries.
  pub const fn ipv6_interface(&self) -> Option<u32> {
    self.ipv6_interface
  }

  /// Sets whether to request unicast responses.
  pub fn with_unicast_response(mut self, want_unicast_response: bool) -> Self {
    self.want_unicast_response = want_unicast_response;
    self
  }

  /// Returns whether to request unicast responses.
  pub const fn want_unicast_response(&self) -> bool {
    self.want_unicast_response
  }

  /// Sets whether to disable IPv4 for MDNS operations.
  pub fn with_disable_ipv4(mut self, disable_ipv4: bool) -> Self {
    self.disable_ipv4 = disable_ipv4;
    self
  }

  /// Returns whether to disable IPv4 for MDNS operations.
  pub const fn disable_ipv4(&self) -> bool {
    self.disable_ipv4
  }

  /// Sets whether to disable IPv6 for MDNS operations.
  pub fn with_disable_ipv6(mut self, disable_ipv6: bool) -> Self {
    self.disable_ipv6 = disable_ipv6;
    self
  }

  /// Returns whether to disable IPv6 for MDNS operations.
  pub const fn disable_ipv6(&self) -> bool {
    self.disable_ipv6
  }

  /// Returns the channel capacity for the [`Lookup`] stream.
  ///
  /// If `None`, the channel is unbounded.
  ///
  /// Default is `None`.
  #[inline]
  pub const fn capacity(&self) -> Option<usize> {
    self.cap
  }

  /// Sets the channel capacity for the [`Lookup`] stream.
  ///
  /// If `None`, the channel is unbounded.
  ///
  /// Default is `None`.
  #[inline]
  pub fn with_capacity(mut self, cap: Option<usize>) -> Self {
    self.cap = cap;
    self
  }
}

/// A handle to cancel a lookup.
#[derive(Debug, Clone)]
pub struct Canceller(Sender<()>);

impl Canceller {
  /// Cancels the lookup.
  ///
  /// Returns `true` if the lookup was cancelled, `false` if it was already cancelled.
  #[inline]
  pub fn cancel(&self) -> bool {
    self.0.close()
  }
}

pin_project_lite::pin_project! {
  /// A stream of service entries returned from a lookup.
  pub struct Lookup {
    shutdown_tx: Sender<()>,
    has_err: bool,
    #[pin]
    entry_rx: Receiver<io::Result<ServiceEntry>>,
  }
}

impl Lookup {
  /// Returns a handle to cancel the lookup.
  #[inline]
  pub fn canceller(&self) -> Canceller {
    Canceller(self.shutdown_tx.clone())
  }
}

impl Stream for Lookup {
  type Item = io::Result<<Receiver<ServiceEntry> as Stream>::Item>;

  fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
    let this = self.project();

    if *this.has_err {
      return Poll::Ready(None);
    }

    this.entry_rx.poll_next(cx).map(|res| match res {
      Some(Ok(entry)) => Some(Ok(entry)),
      Some(Err(e)) => {
        *this.has_err = true;
        Some(Err(e))
      }
      None => None,
    })
  }
}

/// Looks up a given service, in a domain, waiting at most
/// for a timeout before finishing the query. The results are streamed
/// to a channel. Sends will not block, so clients should make sure to
/// either read or buffer. This method will attempt to stop the query
/// on cancellation.
pub async fn query_with<R>(params: QueryParam) -> io::Result<Lookup>
where
  R: Runtime,
{
  let (shutdown_tx, shutdown_rx) = async_channel::bounded::<()>(1);
  let (entry_tx, entry_rx) = match params.capacity() {
    Some(cap) => async_channel::bounded(cap),
    None => async_channel::unbounded(),
  };

  let lookup = Lookup {
    shutdown_tx: shutdown_tx.clone(),
    entry_rx,
    has_err: false,
  };

  // create a new client
  let client = Client::<R>::new(
    !params.disable_ipv4 && ipv4(),
    !params.disable_ipv6 && ipv6(),
    params.ipv4_interface,
    params.ipv6_interface,
  )
  .await?;

  R::spawn_detach(async move {
    match client
      .query_in(
        params.service.append_fqdn(&params.domain),
        params.want_unicast_response,
        params.timeout,
        entry_tx.clone(),
        shutdown_rx,
      )
      .await
    {
      Ok(_) => {
        if shutdown_tx.close() {
          tracing::info!("mdns client: closing");
        }
      }
      Err(e) => {
        if shutdown_tx.close() {
          tracing::error!(err=%e, "mdns client: closing");
        }
        let _ = entry_tx.send(Err(e)).await;
      }
    }
  });

  Ok(lookup)
}

/// Similar to [`query_with`], however it uses all the default parameters
pub async fn lookup<R>(service: Name) -> io::Result<Lookup>
where
  R: Runtime,
{
  query_with::<R>(QueryParam::new(service)).await
}

/// Provides a query interface that can be used to
/// search for service providers using mDNS
struct Client<R: Runtime> {
  use_ipv4: bool,
  use_ipv6: bool,

  ipv4_unicast_conn: Option<(SocketAddr, Arc<<R::Net as Net>::UdpSocket>)>,
  ipv6_unicast_conn: Option<(SocketAddr, Arc<<R::Net as Net>::UdpSocket>)>,

  ipv4_multicast_conn: Option<(SocketAddr, Arc<<R::Net as Net>::UdpSocket>)>,
  ipv6_multicast_conn: Option<(SocketAddr, Arc<<R::Net as Net>::UdpSocket>)>,
}

impl<R: Runtime> Client<R> {
  async fn query_in(
    self,
    service: Name,
    want_unicast_response: bool,
    timeout: Duration,
    tx: Sender<io::Result<ServiceEntry>>,
    shutdown_rx: Receiver<()>,
  ) -> io::Result<()> {
    // Start listening for response packets
    let (msg_tx, msg_rx) = async_channel::bounded::<(Message, SocketAddr)>(32);

    if self.use_ipv4 {
      if let Some((addr, conn)) = &self.ipv4_unicast_conn {
        tracing::info!(local_addr=%addr,"mdns client: starting to listen to unicast on IPv4");
        R::spawn_detach(
          PacketReceiver::<R>::new(
            *addr,
            false,
            conn.clone(),
            msg_tx.clone(),
            shutdown_rx.clone(),
          )
          .run(),
        );
      }

      if let Some((addr, conn)) = &self.ipv4_multicast_conn {
        tracing::info!(local_addr=%addr,"mdns client: starting to listen to multicast on IPv4");
        R::spawn_detach(
          PacketReceiver::<R>::new(
            *addr,
            false,
            conn.clone(),
            msg_tx.clone(),
            shutdown_rx.clone(),
          )
          .run(),
        );
      }
    }

    if self.use_ipv6 {
      if let Some((addr, conn)) = &self.ipv6_unicast_conn {
        tracing::info!(local_addr=%addr,"mdns client: starting to listen to unicast on IPv6");
        R::spawn_detach(
          PacketReceiver::<R>::new(
            *addr,
            true,
            conn.clone(),
            msg_tx.clone(),
            shutdown_rx.clone(),
          )
          .run(),
        );
      }

      if let Some((addr, conn)) = &self.ipv6_multicast_conn {
        tracing::info!(local_addr=%addr,"mdns client: starting to listen to multicast on IPv6");
        R::spawn_detach(
          PacketReceiver::<R>::new(
            *addr,
            true,
            conn.clone(),
            msg_tx.clone(),
            shutdown_rx.clone(),
          )
          .run(),
        );
      }
    }

    // Send the query
    let q = Query::new(service, want_unicast_response);

    self.send_query(q).await?;

    // Map the in-progress responses
    let mut inprogress: HashMap<Name, Arc<AtomicRefCell<ServiceEntryBuilder>>> = HashMap::new();

    // Listen until we reach the timeout
    let finish = R::sleep(timeout);
    futures::pin_mut!(finish);

    loop {
      futures::select! {
        resp = msg_rx.recv().fuse() => {
          match resp {
            Err(e) => {
              tracing::error!(err=%e, "mdns client: failed to receive packet");
            },
            Ok((msg, src_addr)) => {
              let records = msg.into_iter();
              let mut inp = None;
              for record in records {
                // TODO(reddaly): Check that response corresponds to serviceAddr?
                let (header, data) = record.into_components();
                match data {
                  RecordData::PTR(data) => {
                    // Create new entry for this
                    let ent = ensure_name(&mut inprogress, data);
                    inp = Some(ent);
                  },
                  RecordData::SRV(data) => {
                    let name = header.name().clone();
                    // Check for a target mismatch
                    if data.target().ne(&name) {
                      alias(&mut inprogress, name.clone(), data.target().clone());

                      // Get the port
                      let ent = ensure_name(&mut inprogress, name);
                      let mut ref_mut = ent.borrow_mut();
                      ref_mut.host = data.target().clone();
                      ref_mut.port = data.port();
                    } else {
                      // Get the port
                      let ent = ensure_name(&mut inprogress, name.clone());
                      let mut ref_mut = ent.borrow_mut();
                      ref_mut.port = data.port();
                      ref_mut.host = data.into_target();
                    }
                  },
                  RecordData::TXT(data) => {
                    let name = header.name().clone();
                    // Pull out the txt
                    let ent = ensure_name(&mut inprogress, name);
                    let mut ref_mut = ent.borrow_mut();
                    ref_mut.infos = data.clone();
                    ref_mut.has_txt = true;
                    drop(ref_mut);
                    inp = Some(ent);
                  },
                  RecordData::A(data) => {
                    let name = header.name().clone();
                    // Pull out the IP
                    let ent = ensure_name(&mut inprogress, name);
                    let mut ref_mut = ent.borrow_mut();
                    ref_mut.ipv4 = Some(data);
                    drop(ref_mut);
                    inp = Some(ent);
                  },
                  RecordData::AAAA(data) => {
                    let name = header.name().clone();
                    // Pull out the IP
                    let ent = ensure_name(&mut inprogress, name);
                    let mut ref_mut = ent.borrow_mut();
                    ref_mut.ipv6 = Some(data);
                    // link-local IPv6 addresses must be qualified with a zone (interface). Zone is
                    // specific to this machine/network-namespace and so won't be carried in the
                    // mDNS message itself. We borrow the zone from the source address of the UDP
                    // packet, as the link-local address should be valid on that interface.
                    if Ipv6AddrExt::is_unicast_link_local(&data) || data.is_multicast_link_local() {
                      if let SocketAddr::V6(addr) = src_addr {
                        let zone = addr.scope_id();
                        ref_mut.zone = Some(zone);
                      }
                    }
                    drop(ref_mut);
                    inp = Some(ent);
                  },
                }

                match inp {
                  None => continue,
                  Some(ref ent) => {
                    // Check if this entry is complete
                    let mut ref_mut = ent.borrow_mut();
                    if ref_mut.complete() {
                      if ref_mut.sent {
                        continue;
                      }
                      ref_mut.sent = true;
                      let entry = ref_mut.finalize();

                      futures::select! {
                        _ = tx.send(Ok(entry)).fuse() => {},
                        default => {},
                      }
                    } else {
                      // Fire off a node specific query
                      let question = Query::new(ref_mut.name.clone(), false);
                      self.send_query(question).await.inspect_err(|e| {
                        tracing::error!(err=%e, "mdns client: failed to query instance {}", ref_mut.name);
                      })?;
                    }

                    drop(ref_mut);
                  }
                }
              }
            },
          }
        },
        _ = (&mut finish).fuse() => return Ok(()),
      }
    }
  }

  async fn send_query(&self, question: Query) -> io::Result<()> {
    let buf = question
      .encode()
      .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    if let Some((addr, conn)) = &self.ipv4_unicast_conn {
      tracing::trace!(from=%addr, data=?buf.as_slice(), "mdns client: sending query by unicast on IPv4");
      conn.send_to(&buf, (IPV4_MDNS, MDNS_PORT)).await?;
    }

    if let Some((addr, conn)) = &self.ipv6_unicast_conn {
      tracing::trace!(from=%addr, data=?buf.as_slice(), "mdns client: sending query by unicast on IPv6");
      conn.send_to(&buf, (IPV6_MDNS, MDNS_PORT)).await?;
    }

    Ok(())
  }

  async fn new(
    mut v4: bool,
    mut v6: bool,
    ipv4_interface: Option<Ipv4Addr>,
    ipv6_interface: Option<u32>,
  ) -> io::Result<Self> {
    if !v4 && !v6 {
      return Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        "must enable at least one of IPv4 or IPv6 querying",
      ));
    }

    // Establish unicast connections
    let mut uconn4 = if v4 {
      match unicast_udp4_socket::<R>(ipv4_interface) {
        Err(e) => {
          tracing::error!(err=%e, "mdns client: failed to bind to udp4 port");
          None
        }
        Ok(conn) => {
          let addr = conn.local_addr()?;
          Some((addr, Arc::new(conn)))
        }
      }
    } else {
      None
    };

    let mut uconn6 = if v6 {
      match unicast_udp6_socket::<R>(ipv6_interface) {
        Err(e) => {
          tracing::error!(err=%e, "mdns client: failed to bind to udp6 port");
          None
        }
        Ok(conn) => {
          let addr = conn.local_addr()?;
          Some((addr, Arc::new(conn)))
        }
      }
    } else {
      None
    };

    // Establish multicast connections
    let mut mconn4 = if v4 {
      match multicast_udp4_socket::<R>(ipv4_interface, MDNS_PORT) {
        Err(e) => {
          tracing::error!(err=%e, "mdns client: failed to bind to udp4 port");
          None
        }
        Ok(conn) => {
          let addr = conn.local_addr()?;
          Some((addr, Arc::new(conn)))
        }
      }
    } else {
      None
    };

    let mut mconn6 = if v6 {
      match multicast_udp6_socket::<R>(ipv6_interface, MDNS_PORT) {
        Err(e) => {
          tracing::error!(err=%e, "mdns client: failed to bind to udp6 port");
          None
        }
        Ok(conn) => {
          let addr = conn.local_addr()?;
          Some((addr, Arc::new(conn)))
        }
      }
    } else {
      None
    };

    // Check that unicast and multicast connections have been made for IPv4 and IPv6
    // and disable the respective protocol if not.
    if uconn4.is_none() || mconn4.is_none() {
      if v4 {
        tracing::info!("mdns client: failed to listen to both unicast and multicast on IPv4");
      }
      v4 = false;
      uconn4 = None;
      mconn4 = None;
    }

    if uconn6.is_none() || mconn6.is_none() {
      if v6 {
        tracing::info!("mdns client: failed to listen to both unicast and multicast on IPv6");
      }
      v6 = false;
      uconn6 = None;
      mconn6 = None;
    }

    if !v4 && !v6 {
      return Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        "at least one of IPv4 and IPv6 must be enabled for querying",
      ));
    }

    Ok(Self {
      use_ipv4: v4,
      use_ipv6: v6,
      ipv4_unicast_conn: uconn4,
      ipv6_unicast_conn: uconn6,
      ipv4_multicast_conn: mconn4,
      ipv6_multicast_conn: mconn6,
    })
  }
}

struct PacketReceiver<R: Runtime> {
  conn: Arc<<R::Net as Net>::UdpSocket>,
  tx: Sender<(Message, SocketAddr)>,
  shutdown_rx: Receiver<()>,
  local_addr: SocketAddr,
  multicast: bool,
}

impl<R: Runtime> PacketReceiver<R> {
  #[inline]
  const fn new(
    local_addr: SocketAddr,
    multicast: bool,
    conn: Arc<<R::Net as Net>::UdpSocket>,
    tx: Sender<(Message, SocketAddr)>,
    shutdown_rx: Receiver<()>,
  ) -> Self {
    Self {
      conn,
      tx,
      shutdown_rx,
      local_addr,
      multicast,
    }
  }

  async fn run(self) {
    let mut buf = vec![0; MAX_PAYLOAD_SIZE];
    loop {
      futures::select! {
        _ = self.shutdown_rx.recv().fuse() => {
          return;
        },
        res = self.conn.recv_from(&mut buf).fuse() => {
          match res {
            Ok((size, src)) => {
              let data = &buf[..size];
              tracing::trace!(local_addr=%self.local_addr, from=%src, multicast=%self.multicast, data=?data, "mdns client: received packet");

              let msg = match Message::decode(data) {
                Ok(msg) => msg,
                Err(e) => {
                  tracing::error!(local_addr=%self.local_addr, from=%src, multicast=%self.multicast, err=%e, "mdns client: failed to deserialize packet");
                  continue;
                }
              };

              futures::select! {
                e = self.tx.send((msg, src)).fuse() => {
                  if let Err(e) = e {
                    tracing::error!(err=%e, "mdns client: failed to pass packet");
                    return;
                  }
                },
                _ = self.shutdown_rx.recv().fuse() => return,
              }
            },
            Err(e) => {
              tracing::error!(err=%e, "mdns client: failed to receive packet");
            }
          }
        }
      }
    }
  }
}

fn ensure_name(
  inprogress: &mut HashMap<Name, Arc<AtomicRefCell<ServiceEntryBuilder>>>,
  name: Name,
) -> Arc<AtomicRefCell<ServiceEntryBuilder>> {
  match inprogress.entry(name.clone()) {
    Entry::Occupied(occupied_entry) => occupied_entry.into_mut().clone(),
    Entry::Vacant(vacant_entry) => vacant_entry
      .insert(Arc::new(AtomicRefCell::new(
        ServiceEntryBuilder::default().with_name(name),
      )))
      .clone(),
  }
}

fn alias(
  inprogress: &mut HashMap<Name, Arc<AtomicRefCell<ServiceEntryBuilder>>>,
  src: Name,
  dst: Name,
) {
  let src_ent = match inprogress.entry(src.clone()) {
    Entry::Occupied(occupied_entry) => occupied_entry.into_mut(),
    Entry::Vacant(vacant_entry) => vacant_entry.insert(Arc::new(AtomicRefCell::new(
      ServiceEntryBuilder::default().with_name(src),
    ))),
  }
  .clone();

  inprogress.insert(dst, src_ent);
}

trait Ipv6AddrExt {
  fn is_unicast_link_local(&self) -> bool;
  fn is_multicast_link_local(&self) -> bool;
}

impl Ipv6AddrExt for Ipv6Addr {
  #[inline]
  fn is_unicast_link_local(&self) -> bool {
    let octets = self.octets();
    octets[0] == 0xfe && (octets[1] & 0xc0) == 0x80
  }

  #[inline]
  fn is_multicast_link_local(&self) -> bool {
    let octets = self.octets();
    octets[0] == 0xff && (octets[1] & 0x0f) == 0x02
  }
}
