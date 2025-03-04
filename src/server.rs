use core::net::{Ipv4Addr, SocketAddr};
use std::{io, ops::ControlFlow};

use agnostic_net::{
  Net, UdpSocket,
  runtime::{AsyncSpawner, RuntimeLite},
};
use async_channel::{Receiver, Sender};
use atomic_refcell::AtomicRefCell;
use dns_protocol::{Flags, Message, Opcode, Question, ResourceRecord, ResponseCode, Serialize};
use futures::{FutureExt, StreamExt as _, stream::FuturesUnordered};
use iprobe::{ipv4, ipv6};
use smallvec_wrapper::TinyVec;
use triomphe::Arc;

use crate::invalid_data_err;

use super::{
  MAX_INLINE_PACKET_SIZE, MAX_PAYLOAD_SIZE, MDNS_PORT, Zone,
  types::RecordRef,
  utils::{multicast_udp4_socket, multicast_udp6_socket},
};

const FORCE_UNICAST_RESPONSES: bool = false;
const RECORD_BUFSIZE: usize = 16;

/// The options for [`Server`].
#[derive(Clone, Debug)]
pub struct ServerOptions {
  ipv4_interface: Option<Ipv4Addr>,
  ipv6_interface: Option<u32>,
  log_empty_responses: bool,
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

/// The builder for [`Server`].
pub struct Server<N, Z>
where
  N: Net,
  Z: Zone<Runtime = N::Runtime>,
{
  zone: Arc<Z>,
  opts: ServerOptions,
  handles: AtomicRefCell<
    FuturesUnordered<<<Z::Runtime as RuntimeLite>::Spawner as AsyncSpawner>::JoinHandle<()>>,
  >,
  shutdown_tx: Sender<()>,
  _m: std::marker::PhantomData<N>,
}

impl<N, Z> Drop for Server<N, Z>
where
  N: Net,
  Z: Zone<Runtime = N::Runtime>,
{
  fn drop(&mut self) {
    self.shutdown_tx.close();
  }
}

impl<N, Z> Server<N, Z>
where
  N: Net,
  Z: Zone<Runtime = N::Runtime>,
{
  /// Creates a new mDNS server.
  pub async fn new(zone: Z, opts: ServerOptions) -> io::Result<Self> {
    let (shutdown_tx, shutdown_rx) = async_channel::bounded(1);

    let zone = Arc::new(zone);
    let handles = FuturesUnordered::new();

    let v4 = if ipv4() {
      match multicast_udp4_socket::<N>(opts.ipv4_interface, MDNS_PORT) {
        Ok(conn) => Some(Processor::<N, Z>::new(
          conn,
          zone.clone(),
          opts.log_empty_responses,
          shutdown_rx.clone(),
        )?),
        Err(e) => {
          tracing::error!(err=%e, "mdns server: failed to bind to IPv4");
          None
        }
      }
    } else {
      None
    };

    let v6 = if ipv6() {
      match multicast_udp6_socket::<N>(opts.ipv6_interface, MDNS_PORT) {
        Ok(conn) => Some(Processor::<N, Z>::new(
          conn,
          zone.clone(),
          opts.log_empty_responses,
          shutdown_rx.clone(),
        )?),
        Err(e) => {
          tracing::error!(err=%e, "mdns server: failed to bind to IPv6");
          None
        }
      }
    } else {
      None
    };

    match (v4, v6) {
      (Some(v4), Some(v6)) => {
        handles.push(<N::Runtime as RuntimeLite>::Spawner::spawn(v4.process()));
        handles.push(<N::Runtime as RuntimeLite>::Spawner::spawn(v6.process()));
      }
      (Some(v4), None) => {
        handles.push(<N::Runtime as RuntimeLite>::Spawner::spawn(v4.process()));
      }
      (None, Some(v6)) => {
        handles.push(<N::Runtime as RuntimeLite>::Spawner::spawn(v6.process()));
      }
      (None, None) => {
        return Err(io::Error::new(
          io::ErrorKind::InvalidInput,
          "no multicast listeners could be started",
        ));
      }
    }

    Ok(Self {
      zone,
      opts,
      handles: AtomicRefCell::new(handles),
      shutdown_tx,
      _m: std::marker::PhantomData,
    })
  }

  /// Returns the zone of the server.
  #[inline]
  pub fn zone(&self) -> &Z {
    &self.zone
  }

  /// Returns the options of the server.
  #[inline]
  pub fn options(&self) -> &ServerOptions {
    &self.opts
  }

  /// Shuts down the mDNS server.
  ///
  /// This method is concurrent safe and can be called multiple times, but only the first call
  /// will have an effect.
  pub async fn shutdown(&self) {
    if !self.shutdown_tx.close() {
      return;
    }

    let mut handles = core::mem::take(&mut *self.handles.borrow_mut());
    while handles.next().await.is_some() {}
  }
}

struct Processor<N, Z>
where
  N: Net,
  Z: Zone,
{
  zone: Arc<Z>,
  conn: N::UdpSocket,
  #[allow(dead_code)]
  local_addr: SocketAddr,
  /// Indicates the server should print an informative message
  /// when there is an mDNS query for which the server has no response.
  log_empty_responses: bool,
  shutdown_rx: Receiver<()>,
}

impl<N, Z> Processor<N, Z>
where
  N: Net,
  Z: Zone,
{
  fn new(
    conn: N::UdpSocket,
    zone: Arc<Z>,
    log_empty_responses: bool,
    shutdown_rx: Receiver<()>,
  ) -> io::Result<Self> {
    conn.local_addr().map(|local_addr| Self {
      conn,
      zone,
      local_addr,
      log_empty_responses,
      shutdown_rx,
    })
  }

  async fn process(self) {
    let mut buf = vec![0; MAX_PAYLOAD_SIZE];

    loop {
      let shutdown_fut = self.shutdown_rx.recv().fuse();
      let recv_fut = async {
        match self.conn.recv_from(&mut buf).await {
          Err(_err) => {
            #[cfg(target_os = "linux")]
            tracing::error!(err=%_err, local=%self.local_addr, "mdns server: failed to receive data from UDP socket");
            return ControlFlow::<(), bool>::Continue(true);
          }
          Ok((len, addr)) => {
            if len == 0 {
              return ControlFlow::Continue(false);
            }

            let data = &buf[..len];
            tracing::trace!(from=%addr, data=?data, "mdns server: received packet");

            let mut q_buf = [Question::default(); 1];
            let mut answers = [ResourceRecord::default(); RECORD_BUFSIZE];
            let mut authorities = [ResourceRecord::default(); RECORD_BUFSIZE];
            let mut additional = [ResourceRecord::default(); RECORD_BUFSIZE];

            let msg = match dns_protocol::Message::read(
              data,
              &mut q_buf,
              &mut answers,
              &mut authorities,
              &mut additional,
            ) {
              Ok(msg) => msg,
              Err(e) => {
                tracing::error!(from=%addr, err=%e, "mdns server: failed to deserialize packet");
                return ControlFlow::Continue(false);
              }
            };
            self.handle_query(addr, msg).await;
            buf.clear();
            ControlFlow::Continue(false)
          }
        }
      };
      futures::pin_mut!(shutdown_fut);
      futures::pin_mut!(recv_fut);

      match futures::future::select(shutdown_fut, recv_fut).await {
        futures::future::Either::Left(_) => {
          tracing::info!("mdns server: shutting down server packet processor");
          return;
        }
        futures::future::Either::Right((res, _)) => {
          if let ControlFlow::Continue(true) = res {
            <N::Runtime as RuntimeLite>::yield_now().await;
          }
        }
      }
    }
  }

  async fn handle_query(&self, from: SocketAddr, query: dns_protocol::Message<'_, '_>) {
    let opcode = query.flags().opcode();
    if opcode != Opcode::Query {
      // "In both multicast query and multicast response messages, the OPCODE MUST
      // be zero on transmission (only standard queries are currently supported
      // over multicast).  Multicast DNS messages received with an OPCODE other
      // than zero MUST be silently ignored."  Note: OpcodeQuery == 0
      tracing::error!(opcode = ?opcode, "mdns server: received query with non-zero OpCode");
      return;
    }

    let resp_code = query.flags().response_code();
    if resp_code != ResponseCode::NoError {
      // "In both multicast query and multicast response messages, the Response
      // Code MUST be zero on transmission.  Multicast DNS messages received with
      // non-zero Response Codes MUST be silently ignored."
      tracing::error!(rcode = ?resp_code, "mdns server: received query with non-zero response_code");
      return;
    }

    // TODO(reddaly): Handle "TC (Truncated) Bit":
    //    In query messages, if the TC bit is set, it means that additional
    //    Known-Answer records may be following shortly.  A responder SHOULD
    //    record this fact, and wait for those additional Known-Answer records,
    //    before deciding whether to respond.  If the TC bit is clear, it means
    //    that the querying host has no additional Known Answers.
    if query.flags().truncated() {
      tracing::error!(
        "mdns server: support for DNS requests with high truncated bit not implemented"
      );
      return;
    }

    let mut multicast_answers = TinyVec::new();
    let mut unicast_answers = TinyVec::new();

    // Handle each query
    let queries = query.questions();
    for query in queries {
      match self
        .handle_query_message(*query, &mut multicast_answers, &mut unicast_answers)
        .await
      {
        Ok(()) => {}
        Err(e) => {
          // query=%query,
          tracing::error!(query=?query, err=%e, "mdns server: fail to handle query");
        }
      }
    }

    if self.log_empty_responses && multicast_answers.is_empty() && unicast_answers.is_empty() {
      for query in queries {
        tracing::info!(
          class=%query.class(),
          type=?query.ty(),
          name=%query.name(),
          "mdns server: no responses for query with question",
        );
      }
    }

    if let Err(e) = self
      .send_response(query.id(), from, false, &multicast_answers)
      .await
    {
      tracing::error!(err=%e, "mdns server: error sending multicast response");
      return;
    }

    if let Err(e) = self
      .send_response(query.id(), from, true, &multicast_answers)
      .await
    {
      tracing::error!(err=%e, "mdns server: error sending unicast response");
    }
  }

  async fn handle_query_message<'a>(
    &'a self,
    question: Question<'a>,
    mrecs: &mut TinyVec<RecordRef<'a>>,
    urecs: &mut TinyVec<RecordRef<'a>>,
  ) -> Result<(), Z::Error> {
    let records = self.zone.records(question.name(), question.ty()).await?;

    if records.is_empty() {
      return Ok(());
    }

    // Handle unicast and multicast responses.
    // TODO(reddaly): The decision about sending over unicast vs. multicast is not
    // yet fully compliant with RFC 6762.  For example, the unicast bit should be
    // ignored if the records in question are close to TTL expiration.  For now,
    // we just use the unicast bit to make the decision, as per the spec:
    //     RFC 6762, section 18.12.  Repurposing of Top Bit of qclass in Query
    //     Section
    //
    //     In the Query Section of a Multicast DNS query, the top bit of the
    //     qclass field is used to indicate that unicast responses are preferred
    //     for this particular question.  (See Section 5.4.)
    let qc = question.class();
    if (qc & (1 << 15)) != 0 || FORCE_UNICAST_RESPONSES {
      urecs.extend(records);
    } else {
      mrecs.extend(records);
    }

    Ok(())
  }

  async fn send_response<'a>(
    &'a self,
    qid: u16,
    from: SocketAddr,
    unicast: bool,
    records: &[RecordRef<'a>],
  ) -> Result<usize, io::Error> {
    // 18.1: ID (Query Identifier)
    // 0 for multicast response, query.Id for unicast response
    let mut id = 0;
    if unicast {
      id = qid;
    }

    if records.is_empty() {
      return Ok(0);
    }

    // See section 18 of RFC 6762 for rules about DNS headers.

    let mut flag = Flags::new();
    flag
      .set_response_code(ResponseCode::NoError)
      .set_authoritative(true);

    let mut records: TinyVec<ResourceRecord<'a>> = records.iter().map(Into::into).collect();
    let msg = Message::new(id, flag, &mut [], &mut records, &mut [], &mut []);
    let len = msg.serialized_len();

    if len <= MAX_INLINE_PACKET_SIZE {
      let mut buf = [0; MAX_INLINE_PACKET_SIZE];
      let written = msg.write(&mut buf).map_err(invalid_data_err)?;
      // TODO(reddaly): Respect the unicast argument, and allow sending responses
      // over multicast.
      self.conn.send_to(&buf[..written], from).await
    } else {
      let mut buf = vec![0; len];
      msg.write(&mut buf).map_err(invalid_data_err)?;
      // TODO(reddaly): Respect the unicast argument, and allow sending responses
      // over multicast.
      self.conn.send_to(&buf, from).await
    }
  }
}

#[allow(clippy::large_enum_variant)]
enum Buffer {
  Heap(Vec<u8>),
  Stack([u8; MAX_INLINE_PACKET_SIZE]),
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
