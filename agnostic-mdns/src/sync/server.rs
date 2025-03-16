use std::{
  io::{self, ErrorKind},
  net::{SocketAddr, UdpSocket},
  sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
  },
};

use crate::{
  Buffer, MDNS_PORT, ServerOptions,
  utils::{multicast_udp4_socket, multicast_udp6_socket},
};
use iprobe::{ipv4, ipv6};
use mdns_proto::{
  error::{BufferType, ProtoError},
  proto::{Message, Question, ResourceRecord},
  server::{Endpoint, SlabEndpoint},
};
use smallvec_wrapper::SmallVec;

use super::Zone;

const MAX_PAYLOAD_SIZE: usize = 9000;

/// A closer for the [`Server`].
#[derive(Debug, Clone)]
pub struct Closer(Arc<AtomicBool>);

impl Closer {
  fn new() -> Self {
    Self(Arc::new(AtomicBool::new(false)))
  }

  /// Closes the server.
  ///
  /// Returns `true` if this invocation closed the server, `false` if the server was already closed.
  pub fn close(&self) -> bool {
    loop {
      let curr = false;

      match self
        .0
        .compare_exchange_weak(curr, true, Ordering::AcqRel, Ordering::Relaxed)
      {
        Ok(_) => return true,
        Err(true) => return false,
        Err(false) => continue,
      }
    }
  }

  /// Returns `true` if the server is closed.
  pub fn is_closed(&self) -> bool {
    self.0.load(Ordering::SeqCst)
  }
}

/// A mDNS server, there is no background
/// thread running to serve the records. This server is synchronous and
/// will block the current thread until the server is stopped.
pub struct Server<Z> {
  zone: Z,
  endpoint: SlabEndpoint,
  v4_udp: Option<UdpSocket>,
  v6_udp: Option<UdpSocket>,
  closer: Closer,
  log_empty_responses: bool,
}

impl<Z> Server<Z>
where
  Z: Zone,
{
  /// Creates a new server with the given zone and options.
  pub fn new(zone: Z, opts: ServerOptions) -> io::Result<(Self, Closer)> {
    let v4 = if ipv4() {
      match multicast_udp4_socket(opts.ipv4_interface, MDNS_PORT) {
        Ok(conn) => Some(conn),
        Err(e) => {
          tracing::error!(err=%e, "mdns server: failed to bind to IPv4");
          None
        }
      }
    } else {
      None
    };

    let v6 = if ipv6() {
      match multicast_udp6_socket(opts.ipv6_interface, MDNS_PORT) {
        Ok(conn) => Some(conn),
        Err(e) => {
          tracing::error!(err=%e, "mdns server: failed to bind to IPv6");
          None
        }
      }
    } else {
      None
    };

    let closer = Closer::new();
    Ok((
      Self {
        zone,
        endpoint: Endpoint::new(),
        v4_udp: v4,
        v6_udp: v6,
        closer: closer.clone(),
        log_empty_responses: opts.log_empty_responses,
      },
      closer,
    ))
  }

  /// Returns a reference to the zone.
  pub fn zone(&self) -> &Z {
    &self.zone
  }

  /// Runs the server, blocking the current thread until the server is stopped.
  pub fn run(self) {
    let Self {
      zone,
      mut endpoint,
      v4_udp,
      v6_udp,
      closer,
      log_empty_responses,
    } = self;

    let mut buf = vec![0; MAX_PAYLOAD_SIZE];

    loop {
      if closer.is_closed() {
        endpoint.close();
        return;
      }

      if let Some(udp) = v4_udp.as_ref() {
        let v4_data = match udp.recv_from(&mut buf) {
          Ok((size, addr)) => {
            if size == 0 {
              None
            } else {
              Some((size, addr))
            }
          }
          Err(e) => match e.kind() {
            ErrorKind::WouldBlock => None,
            _ => {
              tracing::error!(err=%e, "mdns server: fail to receive data");
              None
            }
          },
        };

        if let Some((size, addr)) = v4_data {
          let data = &buf[..size];
          Self::handle_query(&mut endpoint, udp, addr, data, &zone, log_empty_responses);
        }
      }

      if let Some(udp) = v6_udp.as_ref() {
        let v6_data = match udp.recv_from(&mut buf) {
          Ok((size, addr)) => Some((size, addr)),
          Err(e) => match e.kind() {
            ErrorKind::WouldBlock => None,
            _ => {
              tracing::error!(err=%e, "mdns server: fail to receive data");
              None
            }
          },
        };

        if let Some((size, addr)) = v6_data {
          let data = &buf[..size];
          Self::handle_query(&mut endpoint, udp, addr, data, &zone, log_empty_responses);
        }
      }
    }
  }

  fn handle_query(
    endpoint: &mut SlabEndpoint,
    conn: &UdpSocket,
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
          let mut answers = match zone.answers(question.name(), question.ty()) {
            Err(e) => {
              tracing::error!(from=%addr, err=%e, "mdns server: fail to get answers from zone");
              continue;
            }
            Ok(records) => records.collect::<SmallVec<_>>(),
          };
          let mut additionals = match zone.additionals(question.name(), question.ty()) {
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

          if let Err(e) = msg.write(&mut buf) {
            tracing::error!(from=%addr, err=%e, "mdns server: fail to serialize response message");
            continue;
          }

          if let Err(e) = conn.send_to(&buf[..encoded_len], addr) {
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
