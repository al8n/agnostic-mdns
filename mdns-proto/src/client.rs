use core::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use dns_protocol::{Cursor, Deserialize, Label, Message, Question, ResourceType};

use super::{
  Srv, Txt,
  error::{ProtoError, proto_error_parse},
};

/// Events reacted to incoming responses
#[derive(Debug, Clone, Copy)]
pub enum Response<'a> {
  /// An A record
  A {
    /// The name of the service
    name: Label<'a>,
    /// The IPv4 address
    addr: Ipv4Addr,
  },
  /// An AAAA record
  AAAA {
    /// The name of the service
    name: Label<'a>,
    /// The IPv6 address
    addr: Ipv6Addr,
    /// The zone of the address, if any
    zone: Option<u32>,
  },
  /// A PTR record
  Ptr(Label<'a>),
  /// A TXT record
  Txt {
    /// The name of the service
    name: Label<'a>,
    /// The TXT record
    txt: Txt<'a, 'a>,
  },
  /// A SRV record
  Srv {
    /// The name of the service
    name: Label<'a>,
    /// The service record
    srv: Srv<'a>,
  },
}

// /// Returned after we query for a service.
// #[derive(Debug, Clone, Copy)]
// pub struct ServiceEntry<'a> {
//   name: Label<'a>,
//   host: Label<'a>,
//   port: u16,
//   ipv4: Option<Ipv4Addr>,
//   ipv6: Option<Ipv6Addr>,
//   zone: Option<u32>,
//   txts: Option<Txt<'a, 'a>>,
//   sent: bool,
// }

// impl Default for ServiceEntry<'_> {
//   #[inline]
//   fn default() -> Self {
//     Self {
//       name: Label::default(),
//       host: Label::default(),
//       port: 0,
//       ipv4: None,
//       ipv6: None,
//       zone: None,
//       sent: false,
//       txts: None,
//     }
//   }
// }

// impl<'a> ServiceEntry<'a> {
//   #[inline]
//   const fn complete(&self) -> bool {
//     (self.ipv4.is_some() || self.ipv6.is_some()) && self.port != 0 && self.txts.is_some()
//   }

//   /// Set the name of the service.
//   #[inline]
//   pub const fn with_name(&mut self, name: Label<'a>) -> &mut Self {
//     self.name = name;
//     self
//   }

//   /// Set the host of the service.
//   #[inline]
//   pub const fn with_host(&mut self, host: Label<'a>) -> &mut Self {
//     self.host = host;
//     self
//   }

//   /// Set the port of the service.
//   #[inline]
//   pub const fn with_port(&mut self, port: u16) -> &mut Self {
//     self.port = port;
//     self
//   }

//   /// Set the IPv4 address of the service.
//   #[inline]
//   pub const fn with_ipv4(&mut self, ipv4: Ipv4Addr) -> &mut Self {
//     self.ipv4 = Some(ipv4);
//     self
//   }

//   /// Set the IPv6 address of the service.
//   #[inline]
//   pub const fn set_ipv6(&mut self, ipv6: Ipv6Addr) -> &mut Self {
//     self.ipv6 = Some(ipv6);
//     self
//   }

//   /// Set the zone of the service.
//   #[inline]
//   pub const fn set_zone(&mut self, zone: u32) -> &mut Self {
//     self.zone = Some(zone);
//     self
//   }

//   /// Set the TXT record of the service.
//   #[inline]
//   pub const fn set_txt(&mut self, txts: Txt<'a, 'a>) -> &mut Self {
//     self.txts = Some(txts);
//     self
//   }

//   /// Returns the name of the service.
//   #[inline]
//   pub const fn name(&self) -> &Label<'a> {
//     &self.name
//   }

//   /// Returns the host of the service.
//   #[inline]
//   pub const fn host(&self) -> &Label<'a> {
//     &self.host
//   }

//   /// Returns the port of the service.
//   #[inline]
//   pub const fn port(&self) -> u16 {
//     self.port
//   }

//   /// Returns the IPv4 address of the service, if any.
//   #[inline]
//   pub const fn ipv4(&self) -> Option<&Ipv4Addr> {
//     self.ipv4.as_ref()
//   }

//   /// Returns the IPv6 address of the service, if any.
//   #[inline]
//   pub const fn ipv6(&self) -> Option<&Ipv6Addr> {
//     self.ipv6.as_ref()
//   }

//   /// Returns the zone of the service, if any.
//   #[inline]
//   pub const fn zone(&self) -> Option<u32> {
//     self.zone
//   }

//   /// Returns the TXT record of the service.
//   ///
//   /// See [`Txt`] for more information.
//   #[inline]
//   pub const fn txt(&self) -> Option<&Txt<'a, 'a>> {
//     self.txts.as_ref()
//   }
// }

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

/// The client side endpoint of the mDNS protocol
pub struct Endpoint;

impl Endpoint {
  /// Prepare a question.
  pub fn prepare_question(name: Label<'_>, unicast_response: bool) -> Question<'_> {
    // RFC 6762, section 18.12.  Repurposing of Top Bit of qclass in Query
    // Section
    //
    // In the Query Section of a Multicast DNS query, the top bit of the qclass
    // field is used to indicate that unicast responses are preferred for this
    // particular question.  (See Section 5.4.)
    let qclass = if unicast_response {
      let base: u16 = 1;
      base | (1 << 15)
    } else {
      1
    };

    Question::new(name, ResourceType::Ptr, qclass)
  }

  /// Handle an incoming message
  pub fn recv<'innards>(
    from: SocketAddr,
    msg: &Message<'_, 'innards>,
  ) -> impl Iterator<Item = Result<Response<'innards>, ProtoError>> {
    // TODO(reddaly): Check that response corresponds to service addr?
    msg
      .answers()
      .iter()
      .chain(msg.additional().iter())
      .filter_map(move |record| {
        let record_name = record.name();
        match record.ty() {
          ResourceType::A => {
            let src = record.data();
            let res: Result<[u8; 4], _> = src.try_into();

            match res {
              Ok(ip) => Some(Ok(Response::A {
                name: record_name,
                addr: Ipv4Addr::from(ip),
              })),
              Err(_) => {
                #[cfg(feature = "tracing")]
                tracing::error!("mdns endpoint: invalid A record data");
                Some(Err(proto_error_parse("A")))
              }
            }
          }
          ResourceType::AAAA => {
            let src = record.data();
            let res: Result<[u8; 16], _> = src.try_into();

            match res {
              Ok(ip) => {
                let ip = Ipv6Addr::from(ip);
                let mut zone = None;
                // link-local IPv6 addresses must be qualified with a zone (interface). Zone is
                // specific to this machine/network-namespace and so won't be carried in the
                // mDNS message itself. We borrow the zone from the source address of the UDP
                // packet, as the link-local address should be valid on that interface.
                if Ipv6AddrExt::is_unicast_link_local(&ip) || ip.is_multicast_link_local() {
                  if let SocketAddr::V6(addr) = from {
                    zone = Some(addr.scope_id());
                  }
                }

                Some(Ok(Response::AAAA {
                  name: record_name,
                  addr: ip,
                  zone,
                }))
              }
              Err(_) => {
                #[cfg(feature = "tracing")]
                tracing::error!("mdns endpoint: invalid AAAA record data");
                Some(Err(proto_error_parse("AAAA")))
              }
            }
          }
          ResourceType::Ptr => {
            let mut label = Label::default();
            let cursor = Cursor::new(record.data());
            Some(label.deserialize(cursor).map(|_| Response::Ptr(label)))
          }
          ResourceType::Srv => {
            let data = record.data();

            Some(Srv::from_bytes(data).map(|srv| Response::Srv {
              name: record_name,
              srv,
            }))
          }
          ResourceType::Txt => {
            let data = record.data();
            Some(Ok(Response::Txt {
              name: record_name,
              txt: Txt::from_bytes(data),
            }))
          }
          _ => None,
        }
      })
  }
}
