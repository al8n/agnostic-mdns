use core::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use dns_protocol::{Cursor, Deserialize, Label, Message, Question, ResourceType};

use super::{
  Srv, Txt,
  error::{ProtoError, proto_error_parse},
};

/// Events reacted to incoming responses
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

/// Events reacted to [`ServiceEntry`]s
#[derive(Debug, Clone, Copy)]
pub enum ServiceEvent<'a> {
  /// Service entry is complete
  Complete(ServiceEntry<'a>),
  /// The question should retry, because the service entry for the name of the question is incomplete
  Retry(Question<'a>),
}

/// Returned after we query for a service.
#[derive(Debug, Clone, Copy)]
pub struct ServiceEntry<'a> {
  name: Label<'a>,
  host: Label<'a>,
  port: u16,
  ipv4: Option<Ipv4Addr>,
  ipv6: Option<Ipv6Addr>,
  zone: Option<u32>,
  txts: Option<Txt<'a, 'a>>,
  sent: bool,
}

impl Default for ServiceEntry<'_> {
  #[inline]
  fn default() -> Self {
    Self {
      name: Label::default(),
      host: Label::default(),
      port: 0,
      ipv4: None,
      ipv6: None,
      zone: None,
      sent: false,
      txts: None,
    }
  }
}

impl<'a> ServiceEntry<'a> {
  #[inline]
  const fn complete(&self) -> bool {
    (self.ipv4.is_some() || self.ipv6.is_some()) && self.port != 0 && self.txts.is_some()
  }

  /// Set the name of the service.
  #[inline]
  pub const fn with_name(&mut self, name: Label<'a>) -> &mut Self {
    self.name = name;
    self
  }

  /// Set the host of the service.
  #[inline]
  pub const fn with_host(&mut self, host: Label<'a>) -> &mut Self {
    self.host = host;
    self
  }

  /// Set the port of the service.
  #[inline]
  pub const fn with_port(&mut self, port: u16) -> &mut Self {
    self.port = port;
    self
  }

  /// Set the IPv4 address of the service.
  #[inline]
  pub const fn with_ipv4(&mut self, ipv4: Ipv4Addr) -> &mut Self {
    self.ipv4 = Some(ipv4);
    self
  }

  /// Set the IPv6 address of the service.
  #[inline]
  pub const fn set_ipv6(&mut self, ipv6: Ipv6Addr) -> &mut Self {
    self.ipv6 = Some(ipv6);
    self
  }

  /// Set the zone of the service.
  #[inline]
  pub const fn set_zone(&mut self, zone: u32) -> &mut Self {
    self.zone = Some(zone);
    self
  }

  /// Set the TXT record of the service.
  #[inline]
  pub const fn set_txt(&mut self, txts: Txt<'a, 'a>) -> &mut Self {
    self.txts = Some(txts);
    self
  }

  /// Returns the name of the service.
  #[inline]
  pub const fn name(&self) -> &Label<'a> {
    &self.name
  }

  /// Returns the host of the service.
  #[inline]
  pub const fn host(&self) -> &Label<'a> {
    &self.host
  }

  /// Returns the port of the service.
  #[inline]
  pub const fn port(&self) -> u16 {
    self.port
  }

  /// Returns the IPv4 address of the service, if any.
  #[inline]
  pub const fn ipv4(&self) -> Option<&Ipv4Addr> {
    self.ipv4.as_ref()
  }

  /// Returns the IPv6 address of the service, if any.
  #[inline]
  pub const fn ipv6(&self) -> Option<&Ipv6Addr> {
    self.ipv6.as_ref()
  }

  /// Returns the zone of the service, if any.
  #[inline]
  pub const fn zone(&self) -> Option<u32> {
    self.zone
  }

  /// Returns the TXT record of the service.
  ///
  /// See [`Txt`] for more information.
  #[inline]
  pub const fn txt(&self) -> Option<&Txt<'a, 'a>> {
    self.txts.as_ref()
  }
}

pub trait QueryCache {
  /// Get a mutable reference to an entry
  fn get_mut<'a>(&mut self, name: &Label<'a>) -> Option<&mut ServiceEntry<'a>>;
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

  // /// Collect the service entries
  // pub fn collect<'a, M, Cache>(
  //   &mut self,
  //   qh: QueryHandle,
  //   modified_entries: M,
  //   cache: &mut Cache,
  // ) -> Result<impl Iterator<Item = ServiceEvent<'a>>, Error<C::Error, Q::Error>>
  // where
  //   M: IntoIterator<Item = Label<'a>>,
  //   Cache: QueryCache,
  // {
  //   match self.connections.get(qh.connection_id()) {
  //     None => Err(Error::ConnectionNotFound(ConnectionHandle(
  //       qh.connection_id(),
  //     ))),
  //     Some(conn) => {
  //       if conn.get(qh.qid).is_none() {
  //         return Err(Error::QueryNotFound(qh));
  //       }

  //       // Process all modified entries
  //       Ok(modified_entries.into_iter().filter_map(|name| {
  //         // let canonical_name = cache.resolve_name(&name);

  //         if let Some(entry) = cache.get_mut(&name) {
  //           if entry.complete() && !entry.sent {
  //             entry.sent = true;
  //             return Some(ServiceEvent::Complete(*entry));
  //           } else if !entry.sent {
  //             // Fire off a node-specific query for incomplete entries

  //             // RFC 6762, section 18.12.  Repurposing of Top Bit of qclass in Query
  //             // Section
  //             //
  //             // In the Query Section of a Multicast DNS query, the top bit of the qclass
  //             // field is used to indicate that unicast responses are preferred for this
  //             // particular question.  (See Section 5.4.)
  //             let question = Question::new(name, ResourceType::Ptr, 1);

  //             return Some(ServiceEvent::Retry(question));
  //           }
  //         }

  //         None
  //       }))
  //     }
  //   }
  // }
}

// /// Handle an incoming response
// pub fn recv_response<'container, 'innards, C, A, M>(
// &mut self,
// from: SocketAddr,
// cache: &mut InprogressCache<'container, C, A>,
// msg: Message<'container, 'innards>,
// ) -> Result<impl Iterator<Item = Response<'container>>, Error<S::Error, Q::Error>>
// where
// C: for<'b> Cache<Label<'b>, ServiceEntry<'b>>,
// A: for<'b> Cache<Label<'b>, Label<'b>>,
// M: for<'b> Cache<Label<'b>, ()>,
// {
// self.check_direction(Side::Client)?;

// let mut modified_entries = M::new();

// // TODO(reddaly): Check that response corresponds to service addr?
// for record in msg.answers().iter().chain(msg.additional().iter()) {
//   let record_name = record.name();
//   match record.ty() {
//     ResourceType::A => {
//       let src = record.data();
//       let res: Result<[u8; 4], _> = src.try_into();

//       match res {
//         Ok(ip) => {
//           cache.entry(&record_name, |entry| {
//             entry.ipv4 = Some(Ipv4Addr::from(ip));
//           });

//           modified_entries.insert(record_name, ());
//         }
//         Err(_) => {
//           #[cfg(feature = "tracing")]
//           tracing::error!(type=%self.side, "mdns endpoint: invalid A record data");
//           return Err(proto_error_parse("A").into());
//         }
//       }
//     }
//     ResourceType::AAAA => {
//       let src = record.data();
//       let res: Result<[u8; 16], _> = src.try_into();

//       match res {
//         Ok(ip) => {
//           cache.entry(&record_name, |entry| {
//             let ip = Ipv6Addr::from(ip);
//             entry.ipv6 = Some(ip);

//             // link-local IPv6 addresses must be qualified with a zone (interface). Zone is
//             // specific to this machine/network-namespace and so won't be carried in the
//             // mDNS message itself. We borrow the zone from the source address of the UDP
//             // packet, as the link-local address should be valid on that interface.
//             if Ipv6AddrExt::is_unicast_link_local(&ip) || ip.is_multicast_link_local() {
//               if let SocketAddr::V6(addr) = from {
//                 entry.zone = Some(addr.scope_id());
//               }
//             }
//           });

//           modified_entries.insert(record_name, ());
//         }
//         Err(_) => {
//           #[cfg(feature = "tracing")]
//           tracing::error!(type=%self.side, "mdns endpoint: invalid AAAA record data");
//           return Err(proto_error_parse("AAAA").into());
//         }
//       }
//     }
//     ResourceType::Ptr => {
//       cache.entry(&record_name, |_| {});
//       modified_entries.insert(record_name, ());
//     }
//     ResourceType::Srv => {
//       let data = record.data();
//       let srv = Srv::from_bytes(data)?;

//       // Check for a target mismatch
//       let target = srv.target();
//       if target != record_name {
//         cache.create_alias(&record_name, &target);
//       }

//       // Update the entry
//       cache.entry(&record_name, |entry| {
//         entry.host = target;
//         entry.port = srv.port();
//       });
//       modified_entries.insert(record_name, ());
//     }
//     ResourceType::Txt => {
//       let data = record.data();
//       cache.entry(&record_name, |entry| {
//         entry.txts = Txt::from_bytes(data, 0, data.len());
//         entry.has_txt = true;
//       });
//       modified_entries.insert(record_name, ());
//     }
//     _ => continue,
//   }
// }

// // Process all modified entries
// Ok(modified_entries.into_iter().filter_map(|(name, _)| {
//   let canonical_name = cache.resolve_name(&name);

//   if let Some(entry) = cache.entries.get_mut(&canonical_name) {
//     if entry.complete() && !entry.sent {
//       entry.sent = true;
//       return Some(Response::Complete(*entry));
//     } else if !entry.sent {
//       // Fire off a node-specific query for incomplete entries

//       // RFC 6762, section 18.12.  Repurposing of Top Bit of qclass in Query
//       // Section
//       //
//       // In the Query Section of a Multicast DNS query, the top bit of the qclass
//       // field is used to indicate that unicast responses are preferred for this
//       // particular question.  (See Section 5.4.)
//       let question = Question::new(name, ResourceType::Ptr, 1);

//       return Some(Response::Retry(question));
//     }
//   }

//   None
// }))
// }

// /// Track the state of service entries and their aliases for a single mDNS query.
// pub struct InprogressCache<'a, C, A> {
//   // The actual entries being built
//   entries: C,
//   // Maps alias names to their canonical name
//   aliases: A,
//   _m: PhantomData<&'a ()>,
// }

// impl<C, A> Default for InprogressCache<'_, C, A>
// where
//   C: Default,
//   A: Default,
// {
//   #[inline]
//   fn default() -> Self {
//     Self {
//       entries: C::default(),
//       aliases: A::default(),
//       _m: PhantomData,
//     }
//   }
// }

// impl<'a, C, A> InprogressCache<'a, C, A>
// where
//   C: for<'b> Cache<Label<'b>, ServiceEntry<'b>>,
//   A: for<'b> Cache<Label<'b>, Label<'b>>,
// {
//   /// Create a new inprogress cache for a query
//   pub fn new() -> Self {
//     Self {
//       entries: C::new(),
//       aliases: A::new(),
//       _m: PhantomData,
//     }
//   }

//   // Get the canonical name for a given name (following aliases if needed)
//   fn resolve_name(&self, name: &Label<'a>) -> Label<'a> {
//     let mut current = name;
//     let mut seen = A::new();

//     while let Some(target) = self.aliases.get(current) {
//       if seen.contains_key(target) {
//         // Circular reference detected, break the cycle
//         break;
//       }
//       seen.insert(*current, Label::default());
//       current = target;
//     }

//     *current
//   }

//   /// Get a mutable reference to an entry, creating it if it doesn't exist.
//   ///
//   /// The entry is then passed to the closure for modification.
//   fn entry<F>(&mut self, name: &Label<'a>, op: F)
//   where
//     F: FnOnce(&mut ServiceEntry<'a>),
//   {
//     let canonical_name = self.resolve_name(name);

//     if !self.entries.contains_key(&canonical_name) {
//       let builder = ServiceEntry::default().with_name(canonical_name);
//       self.entries.insert(canonical_name, builder);
//     }

//     op(self.entries.get_mut(&canonical_name).unwrap())
//   }

//   // Create an alias from one name to another
//   fn create_alias(&mut self, from: &Label<'a>, to: &Label<'a>) {
//     let canonical_to = self.resolve_name(to);

//     // If the 'from' exists as an entry, merge it into 'to'
//     if let Some(from_entry) = self.entries.remove(from) {
//       self.entry(&canonical_to, |to_entry| {
//         // Merge the entries, keeping non-None values from the original entry
//         if to_entry.port == 0 {
//           to_entry.port = from_entry.port;
//         }

//         if to_entry.ipv4.is_none() {
//           to_entry.ipv4 = from_entry.ipv4;
//         }

//         if to_entry.ipv6.is_none() {
//           to_entry.ipv6 = from_entry.ipv6;
//           to_entry.zone = from_entry.zone;
//         }

//         if !to_entry.has_txt {
//           to_entry.has_txt = from_entry.has_txt;
//           to_entry.txts = from_entry.txts;
//         }
//       });
//     }

//     // Create the alias
//     self.aliases.insert(*from, canonical_to);
//   }
// }
