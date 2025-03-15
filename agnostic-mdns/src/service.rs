use core::{error::Error, net::IpAddr};

use std::{
  io,
  net::{Ipv4Addr, Ipv6Addr, ToSocketAddrs},
  str::FromStr,
  sync::atomic::{AtomicU32, Ordering},
};

use super::{IPV4_SIZE, IPV6_SIZE, invalid_input_err, is_fqdn};

use mdns_proto::proto::{Label, ResourceRecord, ResourceType};
use smallvec_wrapper::{SmallVec, TinyVec};
use smol_str::{SmolStr, ToSmolStr, format_smolstr};
use triomphe::Arc;

const DEFAULT_TTL: u32 = 120;
const DNS_CLASS_IN: u16 = 1;

/// The error of the service
#[derive(Debug, thiserror::Error)]
enum ServiceError {
  /// Service port is missing
  #[error("missing service port")]
  PortNotFound,
  /// Cannot determine the host ip addresses for the host name
  #[error("could not determine the host ip addresses for {hostname}: {error}")]
  IpNotFound {
    /// the host name
    hostname: SmolStr,
    /// the error
    #[source]
    error: Box<dyn Error + Send + Sync + 'static>,
  },
  /// Not a fully qualified domain name
  #[error("{0} is not a fully qualified domain name")]
  NotFQDN(SmolStr),
  /// The TXT data is too long
  #[error("TXT record is too long")]
  TxtDataTooLong,
}

use ptr::PTR;
use srv::SRV;
use txt::TXT;

mod ptr;
mod srv;
mod txt;

/// ```text
/// -- RFC 1035 -- Domain Implementation and Specification    November 1987
///
/// 3.4. Internet specific RRs
///
/// 3.4.1. A RDATA format
///
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///     |                    ADDRESS                    |
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///
/// where:
///
/// ADDRESS         A 32 bit Internet address.
///
/// Hosts that have multiple Internet addresses will have multiple A
/// records.
///
/// A records cause no additional section processing.  The RDATA section of
/// an A line in a Zone File is an Internet address expressed as four
/// decimal numbers separated by dots without any embedded spaces (e.g.,
/// "10.2.data.52" or "192.data.5.6").
/// ```
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
struct A([u8; IPV4_SIZE]);

impl FromStr for A {
  type Err = <Ipv4Addr as FromStr>::Err;

  fn from_str(s: &str) -> Result<Self, Self::Err> {
    s.parse::<Ipv4Addr>().map(Into::into)
  }
}

impl A {
  /// Creates a new `A` record data.
  #[inline]
  pub const fn new(addr: Ipv4Addr) -> Self {
    Self(addr.octets())
  }

  /// Returns the IPv4 address of the `A` record data.
  #[inline]
  pub const fn addr(&self) -> Ipv4Addr {
    Ipv4Addr::new(self.0[0], self.0[1], self.0[2], self.0[3])
  }

  /// Returns the bytes format of the `A` record data.
  #[inline]
  pub const fn data(&self) -> &[u8] {
    &self.0
  }
}

impl From<Ipv4Addr> for A {
  #[inline]
  fn from(value: Ipv4Addr) -> Self {
    Self::new(value)
  }
}

impl From<A> for Ipv4Addr {
  #[inline]
  fn from(value: A) -> Self {
    value.addr()
  }
}

/// ```text
/// -- RFC 1886 -- IPv6 DNS Extensions              December 1995
///
/// 2.2 AAAA data format
///
///    A 128 bit IPv6 address is encoded in the data portion of an AAAA
///    resource record in network byte order (high-order byte first).
/// ```
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
#[allow(clippy::upper_case_acronyms)]
struct AAAA([u8; IPV6_SIZE]);

impl FromStr for AAAA {
  type Err = <Ipv6Addr as FromStr>::Err;

  fn from_str(s: &str) -> Result<Self, Self::Err> {
    s.parse::<Ipv6Addr>().map(Into::into)
  }
}

impl AAAA {
  /// Creates a new `AAAA` record data.
  #[inline]
  pub const fn new(addr: Ipv6Addr) -> Self {
    Self(addr.octets())
  }

  /// Returns the IPv6 address of the `AAAA` record data.
  #[inline]
  pub fn addr(&self) -> Ipv6Addr {
    Ipv6Addr::from(self.0)
  }

  /// Returns the bytes format of the `AAAA` record data.
  #[inline]
  pub const fn data(&self) -> &[u8] {
    &self.0
  }
}

impl From<Ipv6Addr> for AAAA {
  #[inline]
  fn from(value: Ipv6Addr) -> Self {
    Self::new(value)
  }
}

impl From<AAAA> for Ipv6Addr {
  #[inline]
  fn from(value: AAAA) -> Self {
    value.addr()
  }
}

/// A builder for creating a new [`Service`].
pub struct ServiceBuilder<'a> {
  instance: Label<'a>,
  service: Label<'a>,
  domain: Option<Label<'a>>,
  hostname: Option<Label<'a>>,
  port: Option<u16>,
  ipv4s: TinyVec<Ipv4Addr>,
  ipv6s: TinyVec<Ipv6Addr>,
  txt: TinyVec<SmolStr>,
  ttl: u32,
  srv_priority: u16,
  srv_weight: u16,
}

impl<'a> ServiceBuilder<'a> {
  /// Returns a new ServiceBuilder with default values.
  pub fn new(instance: Label<'a>, service: Label<'a>) -> Self {
    Self {
      instance,
      service,
      domain: None,
      hostname: None,
      port: None,
      ipv4s: TinyVec::new(),
      ipv6s: TinyVec::new(),
      txt: TinyVec::new(),
      ttl: DEFAULT_TTL,
      srv_priority: 10,
      srv_weight: 1,
    }
  }

  /// Gets the current instance name.
  ///
  /// ## Example
  ///
  /// ```rust
  /// use agnostic_mdns::ServiceBuilder;
  ///
  /// let builder = ServiceBuilder::new("hostname".into(), "_http._tcp".into());
  /// assert_eq!(builder.instance().as_str(), "hostname");
  /// ```
  pub fn instance(&self) -> &Label<'a> {
    &self.instance
  }

  /// Gets the current service name.
  ///
  /// ## Example
  ///
  /// ```rust
  /// use agnostic_mdns::ServiceBuilder;
  ///
  /// let builder = ServiceBuilder::new("hostname".into(), "_http._tcp".into());
  /// assert_eq!(builder.service().as_str(), "_http._tcp");
  /// ```
  pub fn service(&self) -> &Label<'a> {
    &self.service
  }

  /// Gets the current domain.
  ///
  /// ## Example
  ///
  /// ```rust
  /// use agnostic_mdns::ServiceBuilder;
  ///
  /// let builder = ServiceBuilder::new("hostname".into(), "_http._tcp".into());
  ///
  /// assert!(builder.domain().is_none());
  /// ```
  pub fn domain(&self) -> Option<&Label<'a>> {
    self.domain.as_ref()
  }

  /// Sets the domain for the service.
  ///
  /// ## Example
  ///
  /// ```rust
  /// use agnostic_mdns::ServiceBuilder;
  ///
  /// let builder = ServiceBuilder::new("hostname".into(), "_http._tcp".into())
  ///   .with_domain("local.".into());
  ///
  /// assert_eq!(builder.domain().unwrap().as_str(), "local.");
  /// ```
  pub fn with_domain(mut self, domain: Label<'a>) -> Self {
    self.domain = Some(domain);
    self
  }

  /// Gets the current host name.
  ///
  /// ## Example
  ///
  /// ```rust
  /// use agnostic_mdns::ServiceBuilder;
  ///
  /// let builder = ServiceBuilder::new("hostname".into(), "_http._tcp".into())
  ///   .with_hostname("testhost.".into());
  ///
  /// assert_eq!(builder.hostname().unwrap().as_str(), "testhost.");
  /// ```
  pub fn hostname(&self) -> Option<&Label<'a>> {
    self.hostname.as_ref()
  }

  /// Sets the host name for the service.
  ///
  /// ## Example
  ///
  /// ```rust
  /// use agnostic_mdns::ServiceBuilder;
  ///
  /// let builder = ServiceBuilder::new("hostname".into(), "_http._tcp".into())
  ///   .with_hostname("testhost.".into());
  /// ```
  pub fn with_hostname(mut self, hostname: Label<'a>) -> Self {
    self.hostname = Some(hostname);
    self
  }

  /// Gets the TTL.
  ///
  /// Defaults to `120` seconds.
  ///
  /// ## Example
  ///
  /// ```rust
  /// use agnostic_mdns::ServiceBuilder;
  ///
  /// let builder = ServiceBuilder::new("hostname".into(), "_http._tcp".into());
  /// assert_eq!(builder.ttl(), 120);
  ///
  /// let builder = builder.with_ttl(60);
  /// assert_eq!(builder.ttl(), 60);
  /// ```
  pub fn ttl(&self) -> u32 {
    self.ttl
  }

  /// Sets the TTL for the service.
  ///
  /// Defaults to `120` seconds.
  ///
  /// ## Example
  ///
  /// ```rust
  /// use agnostic_mdns::ServiceBuilder;
  ///
  /// let builder = ServiceBuilder::new("hostname".into(), "_http._tcp".into())
  ///   .with_ttl(60);
  /// ```
  pub fn with_ttl(mut self, ttl: u32) -> Self {
    self.ttl = ttl;
    self
  }

  /// Gets the priority for SRV records.
  ///
  /// Defaults to `10`.
  ///
  /// ## Example
  ///
  /// ```rust
  /// use agnostic_mdns::ServiceBuilder;
  ///
  /// let builder = ServiceBuilder::new("hostname".into(), "_http._tcp".into());
  /// assert_eq!(builder.srv_priority(), 10);
  ///
  /// let builder = builder.with_srv_priority(5);
  /// assert_eq!(builder.srv_priority(), 5);
  /// ```
  pub fn srv_priority(&self) -> u16 {
    self.srv_priority
  }

  /// Sets the priority for SRV records.
  ///
  /// Defaults to `10`.
  ///
  /// ## Example
  ///
  /// ```rust
  /// use agnostic_mdns::ServiceBuilder;
  ///
  /// let builder = ServiceBuilder::new("hostname".into(), "_http._tcp".into())
  ///   .with_srv_priority(5);
  /// ```
  pub fn with_srv_priority(mut self, priority: u16) -> Self {
    self.srv_priority = priority;
    self
  }

  /// Gets the weight for SRV records.
  ///
  /// Defaults to `1`.
  ///
  /// ## Example
  ///
  /// ```rust
  /// use agnostic_mdns::ServiceBuilder;
  ///
  /// let builder = ServiceBuilder::new("hostname".into(), "_http._tcp".into());
  /// assert_eq!(builder.srv_weight(), 1);
  ///
  /// let builder = builder.with_srv_weight(5);
  /// assert_eq!(builder.srv_weight(), 5);
  /// ```
  pub fn srv_weight(&self) -> u16 {
    self.srv_weight
  }

  /// Sets the weight for SRV records.
  ///
  /// Defaults to `1`.
  ///
  /// ## Example
  ///
  /// ```rust
  /// use agnostic_mdns::ServiceBuilder;
  ///
  /// let builder = ServiceBuilder::new("hostname".into(), "_http._tcp".into())
  ///   .with_srv_weight(5);
  /// ```
  pub fn with_srv_weight(mut self, weight: u16) -> Self {
    self.srv_weight = weight;
    self
  }

  /// Gets the current port.
  ///
  /// ## Example
  ///
  /// ```rust
  /// use agnostic_mdns::ServiceBuilder;
  ///
  /// let builder = ServiceBuilder::new("hostname".into(), "_http._tcp".into());
  /// assert!(builder.port().is_none());
  /// ```
  pub fn port(&self) -> Option<u16> {
    self.port
  }

  /// Sets the port for the service.
  ///
  /// ## Example
  ///
  /// ```rust
  /// use agnostic_mdns::ServiceBuilder;
  ///
  /// let builder = ServiceBuilder::new("hostname".into(), "_http._tcp".into())
  ///   .with_port(80);
  /// ```
  pub fn with_port(mut self, port: u16) -> Self {
    self.port = Some(port);
    self
  }

  /// Gets the current IPv4 addresses.
  ///
  /// ## Example
  ///
  /// ```rust
  /// use agnostic_mdns::ServiceBuilder;
  /// use std::net::IpAddr;
  ///
  /// let builder = ServiceBuilder::new("hostname".into(), "_http._tcp".into());
  /// assert!(builder.ipv4s().is_empty());
  ///
  /// let builder = builder.with_ip("192.168.0.1".parse().unwrap());
  ///
  /// assert_eq!(builder.ipv4s(), &["192.168.0.1".parse().unwrap()]);
  /// ```
  pub fn ipv4s(&self) -> &[Ipv4Addr] {
    &self.ipv4s
  }

  /// Gets the current IPv6 addresses.
  ///
  /// ## Example
  ///
  /// ```rust
  /// use agnostic_mdns::ServiceBuilder;
  /// use std::net::IpAddr;
  ///
  /// let builder = ServiceBuilder::new("hostname".into(), "_http._tcp".into());
  /// assert!(builder.ipv6s().is_empty());
  ///
  /// let builder = builder.with_ip("::1".parse().unwrap());
  ///
  /// assert_eq!(builder.ipv6s(), &["::1".parse().unwrap()]);
  /// ```
  pub fn ipv6s(&self) -> &[Ipv6Addr] {
    &self.ipv6s
  }

  /// Sets the IPv4 addresses for the service.
  ///
  /// ## Example
  ///
  /// ```rust
  /// use agnostic_mdns::ServiceBuilder;
  ///
  /// let builder = ServiceBuilder::new("hostname".into(), "_http._tcp".into())
  ///   .with_ipv4s(["192.168.0.1".parse().unwrap()].into_iter().collect());
  /// ```
  pub fn with_ipv4s(mut self, ips: TinyVec<Ipv4Addr>) -> Self {
    self.ipv4s = ips;
    self
  }

  /// Sets the IPv6 addresses for the service.
  ///
  /// ## Example
  ///
  /// ```rust
  /// use agnostic_mdns::ServiceBuilder;
  ///
  /// let builder = ServiceBuilder::new("hostname".into(), "_http._tcp".into())
  ///   .with_ipv6s(["::1".parse().unwrap()].into_iter().collect());
  /// ```
  pub fn with_ipv6s(mut self, ips: TinyVec<Ipv6Addr>) -> Self {
    self.ipv6s = ips;
    self
  }

  /// Pushes an IP address to the list of IP addresses.
  ///
  /// ## Example
  ///
  /// ```rust
  /// use agnostic_mdns::ServiceBuilder;
  /// use std::net::IpAddr;
  ///
  /// let builder = ServiceBuilder::new("hostname".into(), "_http._tcp".into())
  ///  .with_ip(IpAddr::V4("192.168.0.1".parse().unwrap()));
  /// ```
  pub fn with_ip(mut self, ip: IpAddr) -> Self {
    match ip {
      IpAddr::V4(ip) => self.ipv4s.push(ip),
      IpAddr::V6(ip) => self.ipv6s.push(ip),
    }
    self
  }

  /// Gets the current TXT records.
  ///
  /// ## Example
  ///
  /// ```rust
  /// use agnostic_mdns::{ServiceBuilder, SmolStr};
  ///
  /// let builder = ServiceBuilder::new("hostname".into(), "_http._tcp".into());
  /// assert!(builder.txt_records().is_empty());
  ///
  /// let builder = builder.with_txt_record("info".into());
  ///
  /// assert_eq!(builder.txt_records(), &[SmolStr::new("info")]);
  /// ```
  pub fn txt_records(&self) -> &[SmolStr] {
    &self.txt
  }

  /// Sets the TXT records for the service.
  ///
  /// ## Example
  ///
  /// ```rust
  /// use agnostic_mdns::{ServiceBuilder, SmolStr};
  ///
  /// let builder = ServiceBuilder::new("hostname".into(), "_http._tcp".into())
  ///   .with_txt_records([SmolStr::new("info")].into_iter().collect());
  /// ```
  pub fn with_txt_records(mut self, txt: TinyVec<SmolStr>) -> Self {
    self.txt = txt;
    self
  }

  /// Pushes a TXT record to the list of TXT records.
  ///
  /// ## Example
  ///
  /// ```rust
  /// use agnostic_mdns::{ServiceBuilder, SmolStr};
  ///
  /// let builder = ServiceBuilder::new("hostname".into(), "_http._tcp".into())
  ///  .with_txt_record("info".into());
  /// ```
  pub fn with_txt_record(mut self, txt: SmolStr) -> Self {
    self.txt.push(txt);
    self
  }

  /// Finalize the builder and try to create a new [`Service`].
  // TODO(reddaly): This interface may need to change to account for "unique
  // record" conflict rules of the mDNS protocol.  Upon startup, the server should
  // check to ensure that the instance name does not conflict with other instance
  // names, and, if required, select a new name.  There may also be conflicting
  // hostName A/AAAA records.
  pub fn finalize(self) -> io::Result<Service> {
    let domain = self.domain.as_ref().map(|d| format_smolstr!("{}.", d));
    let domain = match domain {
      Some(domain) if !is_fqdn(domain.as_str()) => {
        return Err(invalid_input_err(ServiceError::NotFQDN(domain)));
      }
      Some(domain) => domain,
      None => "local".into(),
    };

    let hostname = self.hostname.as_ref().map(|h| format_smolstr!("{}.", h));
    let hostname = match hostname {
      Some(hostname) if !hostname.is_empty() => {
        if !is_fqdn(hostname.as_str()) {
          return Err(invalid_input_err(ServiceError::NotFQDN(hostname)));
        }
        hostname
      }
      _ => super::hostname_fqdn()?,
    };

    let port = match self.port {
      None | Some(0) => return Err(invalid_input_err(ServiceError::PortNotFound)),
      Some(port) => port,
    };

    let (ipv4s, ipv6s) = if self.ipv4s.is_empty() && self.ipv6s.is_empty() {
      let tmp_hostname = format_smolstr!("{}.{}", hostname, domain);

      let mut ipv4s = TinyVec::new();
      let mut ipv6s = TinyVec::new();
      tmp_hostname
        .as_str()
        .to_socket_addrs()
        .map_err(|e| {
          invalid_input_err(ServiceError::IpNotFound {
            hostname: tmp_hostname,
            error: e.into(),
          })
        })?
        .for_each(|addr| match addr.ip() {
          IpAddr::V4(ip) => ipv4s.push(ip),
          IpAddr::V6(ip) => ipv6s.push(ip),
        });

      (ipv4s, ipv6s)
    } else {
      (self.ipv4s, self.ipv6s)
    };

    let service_addr = format_smolstr!("{}.{}.", self.service, domain.as_str().trim_matches('.'));
    let instance_addr = format_smolstr!("{}.{}.{}.", self.instance, self.service, domain);
    let enum_addr = format_smolstr!("_services._dns-sd._udp.{}.", domain);

    let srv = SRV::new(self.srv_priority, self.srv_weight, port, hostname.clone())
      .map_err(invalid_input_err)?;

    Ok(Service {
      instance: self.instance.to_smolstr(),
      service: self.service.to_smolstr(),
      domain,
      hostname,
      ipv4s: ipv4s.iter().map(|ip| A::from(*ip)).collect(),
      ipv6s: ipv6s.iter().map(|ip| AAAA::from(*ip)).collect(),
      ipv4s_origin: ipv4s,
      ipv6s_origin: ipv6s,
      txt: TXT::new(Arc::from_iter(self.txt)).map_err(invalid_input_err)?,
      service_addr: PTR::new(service_addr).map_err(invalid_input_err)?,
      instance_addr: PTR::new(instance_addr).map_err(invalid_input_err)?,
      enum_addr: PTR::new(enum_addr).map_err(invalid_input_err)?,
      ttl: AtomicU32::new(self.ttl),
      srv,
    })
  }
}

/// Export a named service by implementing a [`Zone`].
#[derive(Debug)]
pub struct Service {
  /// Instance name (e.g. "hostService name")
  instance: SmolStr,
  /// Service name (e.g. "_http._tcp.")
  service: SmolStr,
  /// If blank, assumes "local"
  domain: SmolStr,
  /// Host machine DNS name (e.g. "mymachine.net")
  hostname: SmolStr,
  /// IP addresses for the service's host
  ipv4s_origin: TinyVec<Ipv4Addr>,
  ipv6s_origin: TinyVec<Ipv6Addr>,

  // TODO(al8n): remove the following two fields, when Ipv*Addr::as_octets is stabilized
  ipv4s: TinyVec<A>,
  ipv6s: TinyVec<AAAA>,

  /// Service TXT records
  txt: TXT,
  /// Fully qualified service address
  service_addr: PTR,
  /// Fully qualified instance address
  instance_addr: PTR,
  /// _services._dns-sd._udp.<domain>
  enum_addr: PTR,
  ttl: AtomicU32,
  srv: SRV,
}

impl Service {
  /// Returns the instance of the service.
  #[inline]
  pub const fn instance(&self) -> &SmolStr {
    &self.instance
  }

  /// Returns the service of the mdns service.
  #[inline]
  pub const fn service(&self) -> &SmolStr {
    &self.service
  }

  /// Returns the domain of the mdns service.
  #[inline]
  pub const fn domain(&self) -> &SmolStr {
    &self.domain
  }

  /// Returns the hostname of the mdns service.
  #[inline]
  pub const fn hostname(&self) -> &SmolStr {
    &self.hostname
  }

  /// Returns the port of the mdns service.
  #[inline]
  pub fn port(&self) -> u16 {
    self.srv.port()
  }

  /// Returns the TTL of the mdns service.
  #[inline]
  pub fn ttl(&self) -> u32 {
    self.ttl.load(Ordering::Acquire)
  }

  /// Returns the IPv4 addresses of the mdns service.
  #[inline]
  pub fn ipv4s(&self) -> &[Ipv4Addr] {
    &self.ipv4s_origin
  }

  /// Returns the IPv6 addresses of the mdns service.
  #[inline]
  pub fn ipv6s(&self) -> &[Ipv6Addr] {
    &self.ipv6s_origin
  }

  /// Returns the TXT records of the mdns service.
  #[inline]
  pub fn txt_records(&self) -> &[SmolStr] {
    self.txt.strings()
  }

  #[auto_enums::auto_enum(Iterator)]
  pub(super) fn fetch_answers<'a>(
    &'a self,
    qn: Label<'a>,
    rt: ResourceType,
  ) -> impl Iterator<Item = ResourceRecord<'a>> + 'a {
    let enum_addr_label = Label::from(self.enum_addr.name());
    let service_addr_label = Label::from(self.service_addr.name());
    let instance_addr_label = Label::from(self.instance_addr.name());
    let hostname_label = Label::from(self.hostname.as_str());

    match () {
      () if enum_addr_label.eq(&qn) => self.service_enum(qn, rt),
      () if service_addr_label.eq(&qn) => self.service_records(qn, rt),
      () if instance_addr_label.eq(&qn) => self.instance_records(qn, rt),
      () if hostname_label.eq(&qn) && matches!(rt, ResourceType::A | ResourceType::AAAA) => {
        self.instance_records(qn, rt)
      }
      _ => core::iter::empty(),
    }
  }

  #[auto_enums::auto_enum(Iterator)]
  fn service_enum<'a>(
    &'a self,
    name: Label<'a>,
    rt: ResourceType,
  ) -> impl Iterator<Item = ResourceRecord<'a>> {
    match rt {
      ResourceType::Wildcard | ResourceType::Ptr => core::iter::once(ResourceRecord::new(
        name,
        ResourceType::Ptr,
        DNS_CLASS_IN,
        self.ttl(),
        self.service_addr.data(),
      )),
      _ => core::iter::empty(),
    }
  }

  #[auto_enums::auto_enum(Iterator)]
  fn service_records<'a>(
    &'a self,
    name: Label<'a>,
    rt: ResourceType,
  ) -> impl Iterator<Item = ResourceRecord<'a>> {
    match rt {
      ResourceType::Wildcard | ResourceType::Ptr => {
        // Get the instance records
        core::iter::once(ResourceRecord::new(
          name,
          ResourceType::Ptr,
          DNS_CLASS_IN,
          self.ttl(),
          self.instance_addr.data(),
        ))
        .chain(self.instance_records(self.instance_addr.name().into(), ResourceType::Wildcard))
      }
      _ => core::iter::empty(),
    }
  }

  #[auto_enums::auto_enum(Iterator)]
  fn instance_records<'a>(
    &'a self,
    name: Label<'a>,
    rt: ResourceType,
  ) -> impl Iterator<Item = ResourceRecord<'a>> {
    match rt {
      ResourceType::Wildcard => {
        // Get the SRV, which includes A and AAAA
        let recs = self.instance_records(self.instance_addr.name().into(), ResourceType::Srv);

        // Add the TXT record
        recs
          .chain(self.instance_records(self.instance_addr.name().into(), ResourceType::Txt))
          .collect::<SmallVec<_>>()
          .into_iter()
      }
      ResourceType::A => self.ipv4s.iter().map(move |ip| {
        ResourceRecord::new(name, ResourceType::A, DNS_CLASS_IN, self.ttl(), ip.data())
      }),
      ResourceType::AAAA => self.ipv6s.iter().map(move |ip| {
        ResourceRecord::new(
          name,
          ResourceType::AAAA,
          DNS_CLASS_IN,
          self.ttl(),
          ip.data(),
        )
      }),
      ResourceType::Srv => {
        // Create the SRV Record
        let recs = core::iter::once(ResourceRecord::new(
          name,
          ResourceType::Srv,
          DNS_CLASS_IN,
          self.ttl(),
          self.srv.data(),
        ));
        recs
          // Add the A record
          .chain(self.instance_records(self.instance_addr.name().into(), ResourceType::A))
          // Add the AAAA record
          .chain(self.instance_records(self.instance_addr.name().into(), ResourceType::AAAA))
          .collect::<SmallVec<_>>()
          .into_iter()
      }
      ResourceType::Txt => {
        // Build a TXT response for the instance
        core::iter::once(ResourceRecord::new(
          name,
          ResourceType::Txt,
          DNS_CLASS_IN,
          self.ttl(),
          self.txt.data(),
        ))
      }
      _ => core::iter::empty(),
    }
  }
}
