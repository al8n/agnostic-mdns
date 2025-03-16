use core::net::SocketAddr;
use std::{io, ops::ControlFlow};

use agnostic_net::{
  Net, UdpSocket,
  runtime::{AsyncSpawner, RuntimeLite},
};
use async_channel::{Receiver, Sender};
use atomic_refcell::AtomicRefCell;
use futures::{FutureExt, StreamExt as _, stream::FuturesUnordered};
use iprobe::{ipv4, ipv6};
use mdns_proto::{
  error::{BufferType, ProtoError},
  proto::{Message, Question, ResourceRecord},
  server::SlabEndpoint,
};
use smallvec_wrapper::SmallVec;
use triomphe::Arc;

use crate::{
  Buffer, MDNS_PORT, ServerOptions,
  utils::{multicast_udp4_socket, multicast_udp6_socket},
};

use super::Zone;

/// The builder for [`Server`].
pub struct Server<N, Z>
where
  N: Net,
  Z: Zone,
{
  zone: Arc<Z>,
  opts: ServerOptions,
  handles: AtomicRefCell<
    FuturesUnordered<<<N::Runtime as RuntimeLite>::Spawner as AsyncSpawner>::JoinHandle<()>>,
  >,
  shutdown_tx: Sender<()>,
  _m: std::marker::PhantomData<N>,
}

impl<N, Z> Drop for Server<N, Z>
where
  N: Net,
  Z: Zone,
{
  fn drop(&mut self) {
    self.shutdown_tx.close();
  }
}

impl<N, Z> Server<N, Z>
where
  N: Net,
  Z: Zone,
{
  /// Creates a new mDNS server.
  pub async fn new(zone: Z, opts: ServerOptions) -> io::Result<Self> {
    let (shutdown_tx, shutdown_rx) = async_channel::bounded(1);

    let zone = Arc::new(zone);
    let handles = FuturesUnordered::new();

    let v4 = if ipv4() {
      match multicast_udp4_socket(opts.ipv4_interface, MDNS_PORT)
        .and_then(<N::UdpSocket as TryFrom<_>>::try_from)
      {
        Ok(conn) => Some(Processor::<N, Z>::new(
          conn,
          zone.clone(),
          opts.log_empty_responses,
          opts.max_payload_size,
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
      match multicast_udp6_socket(opts.ipv6_interface, MDNS_PORT)
        .and_then(<N::UdpSocket as TryFrom<_>>::try_from)
      {
        Ok(conn) => Some(Processor::<N, Z>::new(
          conn,
          zone.clone(),
          opts.log_empty_responses,
          opts.max_payload_size,
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
  max_payload_size: usize,
  endpoint: SlabEndpoint,
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
    max_payload_size: usize,
    shutdown_rx: Receiver<()>,
  ) -> io::Result<Self> {
    conn.local_addr().map(|local_addr| Self {
      conn,
      zone,
      local_addr,
      log_empty_responses,
      max_payload_size,
      endpoint: SlabEndpoint::new(),
      shutdown_rx,
    })
  }

  async fn process(self) {
    let Self {
      conn,
      zone,
      shutdown_rx,
      mut endpoint,
      local_addr,
      log_empty_responses,
      max_payload_size,
    } = self;

    let mut buf = Buffer::zerod(max_payload_size);

    tracing::info!(local=%local_addr, service=?zone, "mdns server: listening mDNS packets");
    loop {
      let shutdown_fut = shutdown_rx.recv().fuse();
      let recv_fut = async {
        match conn.recv_from(&mut buf).await {
          Err(_err) => {
            #[cfg(target_os = "linux")]
            tracing::error!(err=%_err, local=%local_addr, "mdns server: failed to receive data from UDP socket");
            return ControlFlow::<(), bool>::Continue(true);
          }
          Ok((len, addr)) => {
            if len == 0 {
              return ControlFlow::Continue(false);
            }

            let data = &buf[..len];
            tracing::trace!(from=%addr, data=?data, "mdns server: received packet");

            Self::handle_query(&mut endpoint, &conn, addr, data, &zone, log_empty_responses).await;
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

  async fn handle_query(
    endpoint: &mut SlabEndpoint,
    conn: &N::UdpSocket,
    addr: SocketAddr,
    data: &[u8],
    zone: &Z,
    log_empty_responses: bool,
  ) {
    let ch = match endpoint.accept() {
      Err(e) => {
        tracing::error!(from=%addr, err=%e, "mdns server: fail to accept connection");
        return;
      }
      Ok(ch) => ch,
    };

    let mut questions = SmallVec::new();
    questions.extend_from_slice(&[Question::default(); 4]);
    let mut answers = SmallVec::new();
    let mut authorities = SmallVec::new();
    let mut additionals = SmallVec::new();
    let req = {
      loop {
        match Message::read(
          data,
          &mut questions,
          &mut answers,
          &mut authorities,
          &mut additionals,
        ) {
          Ok(msg) => break msg,
          Err(e) => match e {
            ProtoError::NotEnoughWriteSpace {
              tried_to_write,
              buffer_type,
              ..
            } => match buffer_type {
              BufferType::Question => {
                questions.resize(tried_to_write.into(), Question::default());
              }
              BufferType::Answer => {
                answers.resize(tried_to_write.into(), ResourceRecord::default());
              }
              BufferType::Authority => {
                authorities.resize(tried_to_write.into(), ResourceRecord::default());
              }
              BufferType::Additional => {
                additionals.resize(tried_to_write.into(), ResourceRecord::default());
              }
            },
            _ => {
              tracing::error!(from=%addr, err=%e, "mdns server: fail to parse message");
              if let Err(e) = endpoint.drain_connection(ch) {
                tracing::error!(from=%addr, err=%e, "mdns server: fail to drain connection");
              }
              return;
            }
          },
        }
      }
    };

    let q = match endpoint.recv(ch, req) {
      Err(e) => {
        tracing::error!(from=%addr, err=%e, "mdns server: fail to handle event");
        if let Err(e) = endpoint.drain_connection(ch) {
          tracing::error!(from=%addr, err=%e, "mdns server: fail to drain connection");
        }
        return;
      }
      Ok(q) => q,
    };

    for question in q.questions() {
      match endpoint.response(q.query_handle(), *question) {
        Err(e) => {
          tracing::error!(from=%addr, err=%e, "mdns server: fail to handle question");
        }
        Ok(outgoing) => {
          tracing::debug!(
            from=%addr,
            class=%question.class(),
            type=?question.ty(),
            name=%question.name(),
            "mdns server: handling question",
          );
          let mut answers = match zone.answers(question.name(), question.ty()).await {
            Err(e) => {
              tracing::error!(from=%addr, err=%e, "mdns server: fail to get answers from zone");
              continue;
            }
            Ok(records) => records.collect::<SmallVec<_>>(),
          };
          let mut additionals = match zone.additionals(question.name(), question.ty()).await {
            Err(e) => {
              tracing::error!(from=%addr, err=%e, "mdns server: fail to get additionals from zone");
              continue;
            }
            Ok(records) => records.collect::<SmallVec<_>>(),
          };

          if log_empty_responses && (answers.is_empty() && additionals.is_empty()) {
            tracing::info!(
              class=%question.class(),
              type=?question.ty(),
              name=%question.name(),
              "mdns server: no responses for question",
            );
            continue;
          }

          let msg = Message::new(
            outgoing.id(),
            outgoing.flags(),
            &mut [],
            &mut answers,
            &mut [],
            &mut additionals,
          );
          let encoded_len = msg.space_needed();

          let mut buf = Buffer::zerod(encoded_len);

          let len = match msg.write(&mut buf) {
            Ok(len) => len,
            Err(e) => {
              tracing::error!(from=%addr, err=%e, "mdns server: fail to serialize response message");
              continue;
            }
          };
          tracing::trace!(from=%addr, data=?&buf[..len], "mdns server: sending response message");
          if let Err(e) = conn.send_to(&buf[..len], addr).await {
            tracing::error!(from=%addr, err=%e, "mdns server: fail to send response message");
            continue;
          }
        }
      };
    }

    if let Err(e) = endpoint.drain_query(q.query_handle()) {
      tracing::error!(from=%addr, err=%e, "mdns server: fail to drain query");
    }

    if let Err(e) = endpoint.drain_connection(ch) {
      tracing::error!(from=%addr, err=%e, "mdns server: fail to drain connection");
    }
  }
}
