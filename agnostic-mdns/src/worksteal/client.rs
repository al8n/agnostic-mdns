use core::{
  net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
  time::Duration,
};
use std::{
  collections::{HashMap, hash_map::Entry},
  io,
  net::IpAddr,
  pin::Pin,
  task::{Context, Poll},
};

use agnostic_net::{Net, UdpSocket, runtime::RuntimeLite};
use async_channel::{Receiver, Sender};
use either::Either;
use futures::{FutureExt, Stream};
use iprobe::{ipv4, ipv6};
use mdns_proto::{
  client::{Endpoint, Response},
  error::BufferType,
  proto::{Flags, Label, Message, Question, ResourceRecord},
};
use parking_lot::Mutex;
use smallvec_wrapper::SmallVec;
use smol_str::{SmolStr, ToSmolStr, format_smolstr};
use triomphe::Arc;

use crate::{
  Buffer, IPV4_MDNS, IPV6_MDNS, MDNS_PORT, QueryParam,
  utils::{multicast_udp4_socket, multicast_udp6_socket, unicast_udp4_socket, unicast_udp6_socket},
};

/// Returned after we query for a service.
#[derive(Debug, Clone)]
pub struct ServiceEntry {
  name: SmolStr,
  host: SmolStr,
  socket_v4: Option<SocketAddrV4>,
  socket_v6: Option<SocketAddrV6>,
  txt: Arc<[SmolStr]>,
}

impl ServiceEntry {
  /// Returns the name of the service.
  #[inline]
  pub fn name(&self) -> &SmolStr {
    &self.name
  }

  /// Returns the host of the service.
  #[inline]
  pub fn host(&self) -> &SmolStr {
    &self.host
  }

  /// Returns the IPv4 address of the service.
  #[inline]
  pub fn ipv4_addr(&self) -> Option<&Ipv4Addr> {
    self.socket_v4.as_ref().map(|addr| addr.ip())
  }

  /// Returns the IPv6 address of the service.
  #[inline]
  pub fn ipv6_addr(&self) -> Option<&Ipv6Addr> {
    self.socket_v6.as_ref().map(|addr| addr.ip())
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
  pub fn txt(&self) -> &[SmolStr] {
    &self.txt
  }
}

/// Returned after we query for a service.
#[derive(Clone, Debug)]
struct ServiceEntryBuilder {
  name: SmolStr,
  host: SmolStr,
  port: u16,
  ipv4: Option<Ipv4Addr>,
  ipv6: Option<Ipv6Addr>,
  zone: Option<u32>,
  txts: Option<Arc<[SmolStr]>>,
  sent: bool,
  queried: bool,
}

impl Default for ServiceEntryBuilder {
  #[inline]
  fn default() -> Self {
    Self {
      name: SmolStr::default(),
      host: SmolStr::default(),
      port: 0,
      ipv4: None,
      ipv6: None,
      zone: None,
      txts: None,
      sent: false,
      queried: false,
    }
  }
}

impl ServiceEntryBuilder {
  fn complete(&self) -> bool {
    (self.ipv4.is_some() || self.ipv6.is_some()) && self.port != 0 && self.txts.is_some()
  }

  #[inline]
  fn with_name(mut self, name: SmolStr) -> Self {
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
      txt: self.txts.as_ref().unwrap().clone(),
    }
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
pub async fn query_with<N>(params: QueryParam<'_>) -> io::Result<Lookup>
where
  N: Net,
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
  let client = Clients::<N>::new(
    !params.disable_ipv4 && ipv4(),
    !params.disable_ipv6 && ipv6(),
    params.ipv4_interface,
    params.ipv6_interface,
  )
  .await?;

  let name = format_smolstr!("{}.{}", params.service, params.domain);
  tracing::info!("mdns client: starting query for {}", name);
  <N::Runtime as RuntimeLite>::spawn_detach(async move {
    match client
      .query_in(
        name,
        params.want_unicast_response,
        params.timeout,
        entry_tx.clone(),
        shutdown_rx,
        params.max_payload_size,
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
pub async fn lookup<N>(service: Label<'_>) -> io::Result<Lookup>
where
  N: Net,
{
  query_with::<N>(QueryParam::new(service)).await
}

/// Provides a query interface that can be used to
/// search for service providers using mDNS
struct Clients<N: Net> {
  v4: Option<Client<N>>,
  v6: Option<Client<N>>,
}

impl<N: Net> Clients<N> {
  async fn query_in(
    self,
    service: SmolStr,
    want_unicast_response: bool,
    timeout: Duration,
    tx: Sender<io::Result<ServiceEntry>>,
    shutdown_rx: Receiver<()>,
    max_payload_size: usize,
  ) -> io::Result<()> {
    // Start listening for response packets
    let (msg_tx, msg_rx) = async_channel::bounded::<Either<ServiceEntry, SmolStr>>(32);

    let q = Endpoint::prepare_question(Label::from(service.as_str()), want_unicast_response);

    let mut qs = [q];
    let msg = Message::new(0, Flags::new(), &mut qs, &mut [], &mut [], &mut []);
    let space_needed = msg.space_needed();
    let mut buf = Buffer::zerod(space_needed);
    let len = msg
      .write(&mut buf)
      .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    // Map the in-progress responses
    let inprogress = Arc::new(Mutex::new(InprogressCache::new()));

    if let Some(ref client) = self.v4 {
      let tx = msg_tx.clone();
      let shutdown_rx = shutdown_rx.clone();
      let buf = buf.clone();
      client.query(
        inprogress.clone(),
        tx,
        shutdown_rx,
        max_payload_size,
        buf,
        len,
      );
    }

    if let Some(ref client) = self.v6 {
      let tx = msg_tx.clone();
      let shutdown_rx = shutdown_rx.clone();
      client.query(
        inprogress.clone(),
        tx,
        shutdown_rx,
        max_payload_size,
        buf,
        len,
      );
    }

    // Listen until we reach the timeout
    let finish = <N::Runtime as RuntimeLite>::sleep(timeout);
    futures::pin_mut!(finish);

    loop {
      futures::select! {
        _ = (&mut finish).fuse() => {
          break Ok(());
        },
        res = msg_rx.recv().fuse() => {
          match res {
            Ok(entry) => {
              match entry {
                Either::Left(entry) => {
                  if let Err(e) = tx.send(Ok(entry)).await {
                    tracing::error!(err=%e, "mdns client: failed to send service entry");
                  }
                },
                Either::Right(name) => {
                  let q = Endpoint::prepare_question(Label::from(name.as_str()), false);
                  let mut qs = [q];
                  let msg = Message::new(0, Flags::new(), &mut qs, &mut [], &mut [], &mut []);
                  let space_needed = msg.space_needed();
                  let mut buf = Buffer::zerod(space_needed);
                  let len = match msg.write(&mut buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e)) {
                    Ok(len) => len,
                    Err(e) => {
                      tracing::error!(err=%e, "mdns client: failed to encode message");
                      if let Err(e) = tx.send(Err(e)).await {
                        tracing::error!(err=%e, "mdns client: failed to send result");
                      }

                      continue;
                    }
                  };

                  if let Some(ref client) = self.v4 {
                    if let Some((_, ref conn)) = client.unicast_conn {
                      conn.send_to(&buf[..len], (IPV4_MDNS, MDNS_PORT)).await?;
                    }
                  }

                  if let Some(ref client) = self.v6 {
                    if let Some((_, ref conn)) = client.unicast_conn {
                      conn.send_to(&buf[..len], (IPV6_MDNS, MDNS_PORT)).await?;
                    }
                  }
                }
              }
            }
            Err(e) => {
              tracing::error!(err=%e, "mdns client: failed to receive packet");
            }
          }
        }
      }
    }
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
      match unicast_udp4_socket(ipv4_interface).and_then(<N::UdpSocket as TryFrom<_>>::try_from) {
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
      match unicast_udp6_socket(ipv6_interface).and_then(<N::UdpSocket as TryFrom<_>>::try_from) {
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
      match multicast_udp4_socket(ipv4_interface, MDNS_PORT)
        .and_then(<N::UdpSocket as TryFrom<_>>::try_from)
      {
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
      match multicast_udp6_socket(ipv6_interface, MDNS_PORT)
        .and_then(<N::UdpSocket as TryFrom<_>>::try_from)
      {
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

    let v4_client = if uconn4.is_some() || mconn4.is_some() {
      Some(Client {
        unicast_conn: uconn4,
        multicast_conn: mconn4,
      })
    } else {
      None
    };

    let v6_client = if uconn6.is_some() || mconn6.is_some() {
      Some(Client {
        unicast_conn: uconn6,
        multicast_conn: mconn6,
      })
    } else {
      None
    };

    Ok(Self {
      v4: v4_client,
      v6: v6_client,
    })
  }
}

struct Client<N: Net> {
  unicast_conn: Option<(SocketAddr, Arc<N::UdpSocket>)>,
  multicast_conn: Option<(SocketAddr, Arc<N::UdpSocket>)>,
}

impl<N: Net> Client<N> {
  fn query(
    &self,
    cache: Arc<Mutex<InprogressCache>>,
    tx: Sender<Either<ServiceEntry, SmolStr>>,
    shutdown_rx: Receiver<()>,
    max_payload_size: usize,
    buf: Buffer,
    len: usize,
  ) {
    if let Some((addr, conn)) = &self.multicast_conn {
      N::Runtime::spawn_detach(Self::listen(
        *addr,
        conn.clone(),
        cache.clone(),
        tx.clone(),
        shutdown_rx.clone(),
        max_payload_size,
      ));
    }

    if let Some((addr, conn)) = &self.unicast_conn {
      let conn = conn.clone();
      let addr = *addr;
      let tx = tx.clone();
      let shutdown_rx = shutdown_rx.clone();

      N::Runtime::spawn_detach(async move {
        tracing::trace!(from=%addr, data=?&buf[..len], "mdns client: sending query by unicast");
        let target: IpAddr = match addr.ip().is_ipv4() {
          true => IPV4_MDNS.into(),
          false => IPV6_MDNS.into(),
        };

        if let Err(e) = conn.send_to(&buf[..len], (target, MDNS_PORT)).await {
          tracing::error!(err=%e, "mdns client: failed to send query by unicast");
        }

        Self::listen(addr, conn.clone(), cache, tx, shutdown_rx, max_payload_size).await
      });
    }
  }

  async fn listen(
    local_addr: SocketAddr,
    conn: Arc<N::UdpSocket>,
    cache: Arc<Mutex<InprogressCache>>,
    tx: Sender<Either<ServiceEntry, SmolStr>>,
    shutdown_rx: Receiver<()>,
    max_payload_size: usize,
  ) {
    let mut buf = Buffer::zerod(max_payload_size);

    tracing::debug!(local_addr=%local_addr, "mdns client: starting to listen response");

    scopeguard::defer!({
      tracing::debug!(local_addr=%local_addr, "mdns client: stopping to listen response");
    });

    loop {
      futures::select! {
        _ = shutdown_rx.recv().fuse() => return,
        res = conn.recv_from(&mut buf).fuse() => {
          let (size, src) = match res {
            Ok((size, src)) => (size, src),
            Err(e) => {
              tracing::error!(err=%e, "mdns client: failed to receive packet");
              continue;
            }
          };

          let data = &buf[..size];

          tracing::trace!(local_addr=%local_addr, from=%src, data=?data, "mdns client: received packet");

          let mut questions = SmallVec::new();
          let mut answers = SmallVec::from([ResourceRecord::default(); 4]);
          let mut authorities = SmallVec::new();
          let mut additionals = SmallVec::from([ResourceRecord::default(); 4]);

          let msg = loop {
            match Message::read(
              data,
              &mut questions,
              &mut answers,
              &mut authorities,
              &mut additionals,
            ) {
              Ok(msg) => break msg,
              Err(e) => match e {
                mdns_proto::error::ProtoError::NotEnoughWriteSpace {
                  tried_to_write,
                  buffer_type,
                  ..
                } => match buffer_type {
                  BufferType::Question => {
                    questions.resize(tried_to_write.into(), Question::default())
                  }
                  BufferType::Answer => {
                    answers.resize(tried_to_write.into(), ResourceRecord::default())
                  }
                  BufferType::Authority => {
                    authorities.resize(tried_to_write.into(), ResourceRecord::default())
                  }
                  BufferType::Additional => {
                    additionals.resize(tried_to_write.into(), ResourceRecord::default())
                  }
                },
                e => {
                  tracing::error!(err=%e, "mdns client: failed to read message");
                  continue;
                }
              },
            }
          };

          for record in Endpoint::recv(src, &msg) {
            match record {
              Err(e) => {
                tracing::error!(err=%e, "mdns client: failed to parse record");
              }
              Ok(record) => {
                match record {
                  Response::A { name, addr } => {
                    let name = name.to_smolstr();
                    cache.lock().entry(name, |entry| {
                      entry.ipv4 = Some(addr);
                    });
                  },
                  Response::AAAA { name, addr, zone } => {
                    let name = name.to_smolstr();
                    cache.lock().entry(name, |entry| {
                      entry.ipv6 = Some(addr);
                      entry.zone = zone;
                    });
                  },
                  Response::Ptr(name) => {
                    cache.lock().entry(name.to_smolstr(), |_| {});
                  },
                  Response::Txt { name, txt } => {
                    let name = name.to_smolstr();
                    match txt.strings().map(|res| {
                      res.map(|s| s.to_smolstr())
                    }).collect::<Result<Arc<[_]>, _>>()
                    {
                      Ok(txt) => {
                        cache.lock().entry(name, |entry| {
                          entry.txts = Some(txt);
                        });
                      },
                      Err(e) => {
                        tracing::error!(err=%e, "mdns client: failed to parse txt record");
                      }
                    }
                  },
                  Response::Srv { name, srv } => {
                    let target = srv.target();
                    let mut cache = cache.lock();
                    let (name, target) = if target != name {
                      cache.create_alias(&name, &target)
                    } else {
                      (name.to_smolstr(), target.to_smolstr())
                    };

                    // Update the entry
                    cache.entry(name, |entry| {
                      entry.host = target;
                      entry.port = srv.port();
                    });
                  },
                }
              }
            }
          }

          let entries = {
            let mut cache = cache.lock();
            cache.entries.iter_mut().filter_map(|(name, ent)| {
              // Check if this entry is complete
              if ent.complete() {
                ent.queried = true;
                if ent.sent {
                  return None;
                }
                ent.sent = true;
                Some(Either::Left(ent.finalize()))
              } else {
                if ent.queried {
                  return None;
                }

                ent.queried = true;
                Some(Either::Right(name.clone()))
              }
            }).collect::<SmallVec<_>>()
          };

          for ent in entries {
            if let Err(e) = tx.send(ent).await {
              tracing::error!(err=%e, "mdns client: failed to send service entry");
            }
          }
        }
      }
    }
  }
}

struct InprogressCache {
  entries: HashMap<SmolStr, ServiceEntryBuilder>,
  aliases: HashMap<SmolStr, SmolStr>,
}

impl InprogressCache {
  fn new() -> Self {
    Self {
      entries: HashMap::new(),
      aliases: HashMap::new(),
    }
  }

  /// Get a mutable reference to an entry, creating it if it doesn't exist.
  ///
  /// The entry is then passed to the closure for modification.
  fn entry<F>(&mut self, name: SmolStr, op: F)
  where
    F: FnOnce(&mut ServiceEntryBuilder),
  {
    let name = match self.aliases.get(&name) {
      Some(target) => target,
      None => &name,
    };

    match self.entries.entry(name.clone()) {
      Entry::Occupied(occupied_entry) => {
        op(occupied_entry.into_mut());
      }
      Entry::Vacant(vacant_entry) => {
        let mut builder = ServiceEntryBuilder::default().with_name(vacant_entry.key().clone());
        op(&mut builder);
        vacant_entry.insert(builder);
      }
    }
  }

  // Create an alias from one name to another
  fn create_alias(&mut self, from: &Label<'_>, to: &Label<'_>) -> (SmolStr, SmolStr) {
    let to = to.to_smolstr();
    let from = from.to_smolstr();

    // Create the alias
    self.aliases.insert(to.clone(), from.clone());
    (from, to)
  }
}
