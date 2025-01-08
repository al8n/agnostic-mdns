use core::net::{Ipv4Addr, SocketAddr};
use std::io;

use agnostic::{
  net::{Net, UdpSocket},
  AsyncSpawner, Runtime,
};
use async_channel::{Receiver, Sender};
use atomic_refcell::AtomicRefCell;
use either::Either;
use futures_util::{stream::FuturesUnordered, FutureExt, StreamExt as _};
use smallvec_wrapper::{MediumVec, OneOrMore};
use triomphe::Arc;

use super::{
  types::{Answer, Message, ProtoError, Query, Record, OP_CODE_QUERY, RESPONSE_CODE_NO_ERROR},
  utils::{multicast_udp4_socket, multicast_udp6_socket},
  Service, Zone, IPV4_MDNS, IPV6_MDNS, MAX_PAYLOAD_SIZE, MDNS_PORT,
};

const FORCE_UNICAST_RESPONSES: bool = false;

/// The options for [`Server`].
#[derive(Clone, Debug)]
pub struct ServerOptions {
  ipv4_interface: Ipv4Addr,
  ipv6_interface: u32,
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
      ipv4_interface: Ipv4Addr::UNSPECIFIED,
      ipv6_interface: 0,
      log_empty_responses: false,
    }
  }

  /// Returns the Ipv4 interface to bind the multicast listener to.
  #[inline]
  pub const fn ipv4_interface(&self) -> &Ipv4Addr {
    &self.ipv4_interface
  }

  /// Sets the IPv4 interface to bind the multicast listener to.
  #[inline]
  pub fn with_ipv4_interface(mut self, iface: Ipv4Addr) -> Self {
    self.ipv4_interface = iface;
    self
  }

  /// Returns the Ipv6 interface to bind the multicast listener to.
  #[inline]
  pub const fn ipv6_interface(&self) -> u32 {
    self.ipv6_interface
  }

  /// Sets the IPv6 interface to bind the multicast listener to.
  #[inline]
  pub fn with_ipv6_interface(mut self, index: u32) -> Self {
    self.ipv6_interface = index;
    self
  }

  /// Sets whether the server should print an informative message
  /// when there is an mDNS query for which the server has no response.
  ///
  /// Default is `false`.
  #[inline]
  pub fn with_log_empty_responses(mut self, log_empty_responses: bool) -> Self {
    self.log_empty_responses = log_empty_responses;
    self
  }
}

/// The builder for [`Server`].
pub struct Server<R: Runtime, Z: Zone = Service<R>> {
  zone: Arc<Z>,
  opts: ServerOptions,
  handles: AtomicRefCell<FuturesUnordered<<R::Spawner as AsyncSpawner>::JoinHandle<()>>>,
  shutdown_tx: Sender<()>,
}

impl<R, Z> Drop for Server<R, Z>
where
  R: Runtime,
  Z: Zone,
{
  fn drop(&mut self) {
    self.shutdown_tx.close();
  }
}

impl<R: Runtime, Z: Zone> Server<R, Z> {
  /// Creates a new mDNS server.
  pub async fn new(zone: Z, opts: ServerOptions) -> io::Result<Self> {
    let (shutdown_tx, shutdown_rx) = async_channel::bounded(1);

    let zone = Arc::new(zone);
    let handles = FuturesUnordered::new();

    let v4 = match multicast_udp4_socket::<R>(MDNS_PORT) {
      Ok(conn) => {
        conn.join_multicast_v4(IPV4_MDNS, opts.ipv4_interface)?;
        Some(Processor::<R, Z>::new(
          conn,
          zone.clone(),
          opts.log_empty_responses,
          shutdown_rx.clone(),
        ))
      }
      Err(e) => {
        tracing::error!(err=%e, "mdns: failed to bind to IPv4");
        None
      }
    };

    let v6 = match multicast_udp6_socket::<R>(MDNS_PORT) {
      Ok(conn) => {
        conn.join_multicast_v6(&IPV6_MDNS, opts.ipv6_interface)?;
        Some(Processor::<R, Z>::new(
          conn,
          zone.clone(),
          opts.log_empty_responses,
          shutdown_rx.clone(),
        ))
      }
      Err(e) => {
        tracing::error!(err=%e, "mdns: failed to bind to IPv6");
        None
      }
    };

    match (v4, v6) {
      (Some(v4), Some(v6)) => {
        handles.push(R::Spawner::spawn(v4.process()));
        handles.push(R::Spawner::spawn(v6.process()));
      }
      (Some(v4), None) => {
        handles.push(R::Spawner::spawn(v4.process()));
      }
      (None, Some(v6)) => {
        handles.push(R::Spawner::spawn(v6.process()));
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

struct Processor<R: Runtime, Z: Zone> {
  zone: Arc<Z>,
  conn: <R::Net as Net>::UdpSocket,
  /// Indicates the server should print an informative message
  /// when there is an mDNS query for which the server has no response.
  log_empty_responses: bool,
  shutdown_rx: Receiver<()>,
}

impl<R: Runtime, Z: Zone> Processor<R, Z> {
  fn new(
    conn: <R::Net as Net>::UdpSocket,
    zone: Arc<Z>,
    log_empty_responses: bool,
    shutdown_rx: Receiver<()>,
  ) -> Self {
    Self {
      conn,
      zone,
      log_empty_responses,
      shutdown_rx,
    }
  }

  async fn process(self) {
    let mut buf = vec![0; MAX_PAYLOAD_SIZE];

    loop {
      futures_util::select! {
        _ = self.shutdown_rx.recv().fuse() => return,
        default => {
          let (len, addr) = match self.conn.recv_from(&mut buf).await {
            Ok((len, addr)) => (len, addr),
            Err(e) => {
              tracing::error!(err=%e, "mdns: failed to receive data from UDP socket");
              continue;
            }
          };

          let msg = match Message::decode(&buf[..len]) {
            Ok(msg) => msg,
            Err(e) => {
              tracing::error!(err=%e, "mdns: failed to unpack packet");
              continue;
            }
          };

          self.handle_query(addr, msg).await;
          buf.clear();
        }
      }
    }
  }

  async fn handle_query(&self, from: SocketAddr, query: Message) {
    if query.header.opcode != OP_CODE_QUERY {
      // "In both multicast query and multicast response messages, the OPCODE MUST
      // be zero on transmission (only standard queries are currently supported
      // over multicast).  Multicast DNS messages received with an OPCODE other
      // than zero MUST be silently ignored."  Note: OpcodeQuery == 0
      tracing::error!(opcode = %query.header.opcode, "mdns: received query with non-zero OpCode");
      return;
    }

    if query.header.response_code != RESPONSE_CODE_NO_ERROR {
      // "In both multicast query and multicast response messages, the Response
      // Code MUST be zero on transmission.  Multicast DNS messages received with
      // non-zero Response Codes MUST be silently ignored."
      tracing::error!(response_code = %query.header.response_code, "mdns: received query with non-zero ResponseCode");
      return;
    }

    // TODO(reddaly): Handle "TC (Truncated) Bit":
    //    In query messages, if the TC bit is set, it means that additional
    //    Known-Answer records may be following shortly.  A responder SHOULD
    //    record this fact, and wait for those additional Known-Answer records,
    //    before deciding whether to respond.  If the TC bit is clear, it means
    //    that the querying host has no additional Known Answers.
    if query.header.truncated {
      tracing::error!("mdns: support for DNS requests with high truncated bit not implemented");
      return;
    }

    let mut multicast_answers = OneOrMore::new();
    let mut unicast_answers = OneOrMore::new();

    // Handle each query
    let queries = query.questions();
    for query in queries {
      match self.handle_question(query).await {
        Ok((mrecs, urecs)) => {
          multicast_answers.extend(mrecs);
          unicast_answers.extend(urecs)
        }
        Err(e) => {
          // query=%query,
          tracing::error!( err=%e, "mdns: fail to handle query");
        }
      }
    }

    if self.log_empty_responses && multicast_answers.is_empty() && unicast_answers.is_empty() {
      let mut questions = MediumVec::with_capacity(queries.len());

      for query in queries {
        questions.push(query.name().as_str());
      }

      tracing::info!(
        "mdns: no responses for query with questions: {}",
        questions.join(", ")
      );
    }
    panic!("mdns: asdasdasd");

    // See section 18 of RFC 6762 for rules about DNS headers.
    let resp = |answers: OneOrMore<Record>, unicast: bool| -> Option<Answer> {
      // 18.1: ID (Query Identifier)
      // 0 for multicast response, query.Id for unicast response
      let mut id = 0;
      if unicast {
        id = query.id();
      }

      if answers.is_empty() {
        return None;
      }

      // let mut msg = Message::new();
      // let mut hdr = Header::new();
      // hdr
      //   .set_id(id)
      //   // 18.3: OPCODE - must be zero in response (OpcodeQuery == 0)
      //   .set_op_code(OpCode::Query)
      //   // 18.4: AA (Authoritative Answer) Bit - must be set to 1
      //   .set_authoritative(true)
      //   // 18.2: QR (Query/Response) Bit - must be set to 1 in response.
      //   .set_message_type(MessageType::Response);
      // // The following fields must all be set to 0:
      // // 18.5: TC (TRUNCATED) Bit
      // // 18.6: RD (Recursion Desired) Bit
      // // 18.7: RA (Recursion Available) Bit
      // // 18.8: Z (Zero) Bit
      // // 18.9: AD (Authentic Data) Bit
      // // 18.10: CD (Checking Disabled) Bit
      // // 18.11: RCODE (Response Code)
      // msg.set_header(hdr).add_answers(answers);
      let msg = Answer::new(id, answers);
      Some(msg)
    };

    if let Some(mresp) = resp(multicast_answers, false) {
      if let Err(e) = self.send_response(mresp, from, false).await {
        tracing::error!(err=%e, "mdns: error sending multicast response");
        return;
      }
    }

    if let Some(uresp) = resp(unicast_answers, true) {
      if let Err(e) = self.send_response(uresp, from, true).await {
        tracing::error!(err=%e, "mdns: error sending unicast response");
      }
    }
  }

  async fn handle_question(
    &self,
    query: &Query,
  ) -> Result<(OneOrMore<Record>, OneOrMore<Record>), Z::Error> {
    let records = self.zone.records(query.name(), query.query_type()).await?;

    if records.is_empty() {
      return Ok((OneOrMore::new(), OneOrMore::new()));
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
    let qc: u16 = query.query_class().into();
    let res = if (qc & (1 << 15)) != 0 || FORCE_UNICAST_RESPONSES {
      (OneOrMore::new(), records)
    } else {
      (records, OneOrMore::new())
    };

    Ok(res)
  }

  async fn send_response(
    &self,
    msg: Answer,
    from: SocketAddr,
    _unicast: bool,
  ) -> Result<usize, Either<ProtoError, io::Error>> {
    // TODO(reddaly): Respect the unicast argument, and allow sending responses
    // over multicast.

    let data = msg.encode().map_err(Either::Left)?;
    self.conn.send_to(&data, from).await.map_err(Either::Right)
  }
}
