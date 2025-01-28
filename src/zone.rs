use core::{convert::Infallible, error::Error, future::Future, marker::PhantomData, net::IpAddr};

use std::{
  io,
  net::ToSocketAddrs,
  sync::atomic::{AtomicU32, Ordering},
};

use super::{
  invalid_input_err, is_fqdn,
  types::{Name, RecordDataRef, RecordRef, A, AAAA, PTR, SRV, TXT},
};
use agnostic_net::runtime::RuntimeLite;
use dns_protocol::{Label, ResourceType};
use either::Either;
use smallvec_wrapper::TinyVec;
use smol_str::{format_smolstr, SmolStr};
use triomphe::Arc;

const DEFAULT_TTL: u32 = 120;

/// The error of the service
#[derive(Debug, thiserror::Error)]
pub enum ServiceError {
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
}

/// The interface used to integrate with the server and
/// to serve records dynamically
pub trait Zone: Send + Sync + 'static {
  /// The runtime type
  type Runtime: RuntimeLite;

  /// The error type of the zone
  type Error: core::error::Error + Send + Sync + 'static;

  /// Returns DNS records in response to a DNS question.
  fn records<'a>(
    &'a self,
    name: Label<'a>,
    rt: ResourceType,
  ) -> impl Future<Output = Result<TinyVec<RecordRef<'a>>, Self::Error>> + Send + 'a;
}

macro_rules! auto_impl {
  ($($name:ty),+$(,)?) => {
    $(
      impl<Z: Zone> Zone for $name {
        type Runtime = Z::Runtime;
        type Error = Z::Error;

        async fn records<'a>(
          &'a self,
          name: Label<'a>,
          rt: ResourceType,
        ) -> Result<TinyVec<RecordRef<'a>>, Self::Error> {
          Z::records(self, name, rt).await
        }
      }
    )*
  };
}

auto_impl!(std::sync::Arc<Z>, triomphe::Arc<Z>, std::boxed::Box<Z>,);

/// A builder for creating a new [`Service`].
pub struct ServiceBuilder {
  instance: SmolStr,
  service: SmolStr,
  domain: Option<SmolStr>,
  hostname: Option<SmolStr>,
  port: Option<u16>,
  ipv4s: TinyVec<A>,
  ipv6s: TinyVec<AAAA>,
  txt: TinyVec<SmolStr>,
  ttl: u32,
  srv_priority: u16,
  srv_weight: u16,
}

impl ServiceBuilder {
  /// Returns a new ServiceBuilder with default values.
  pub fn new(instance: SmolStr, service: SmolStr) -> Self {
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
  pub fn instance(&self) -> &SmolStr {
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
  pub fn service(&self) -> &SmolStr {
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
  pub fn domain(&self) -> Option<&SmolStr> {
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
  pub fn with_domain(mut self, domain: SmolStr) -> Self {
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
  pub fn hostname(&self) -> Option<&SmolStr> {
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
  pub fn with_hostname(mut self, hostname: SmolStr) -> Self {
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
  pub fn ipv4s(&self) -> &[A] {
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
  pub fn ipv6s(&self) -> &[AAAA] {
    &self.ipv6s
  }

  /// Sets the IPv4 addresses for the service.
  ///
  /// ## Example
  ///
  /// ```rust
  /// use agnostic_mdns::{A, ServiceBuilder};
  ///
  /// let builder = ServiceBuilder::new("hostname".into(), "_http._tcp".into())
  ///   .with_ipv4s(["192.168.0.1".parse().unwrap()].into_iter().collect());
  /// ```
  pub fn with_ipv4s(mut self, ips: TinyVec<A>) -> Self {
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
  pub fn with_ipv6s(mut self, ips: TinyVec<AAAA>) -> Self {
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
      IpAddr::V4(ip) => self.ipv4s.push(ip.into()),
      IpAddr::V6(ip) => self.ipv6s.push(ip.into()),
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
  pub async fn finalize<R>(self) -> io::Result<Service<R>>
  where
    R: RuntimeLite,
  {
    let domain = match self.domain {
      Some(domain) if !is_fqdn(domain.as_str()) => {
        return Err(invalid_input_err(ServiceError::NotFQDN(domain)))
      }
      Some(domain) => domain,
      None => Name::local_fqdn(),
    };

    let hostname = match self.hostname {
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
      let tmp_hostname = Name::append(hostname.as_str(), domain.as_str());

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
          IpAddr::V4(ip) => ipv4s.push(ip.into()),
          IpAddr::V6(ip) => ipv6s.push(ip.into()),
        });

      (ipv4s, ipv6s)
    } else {
      (self.ipv4s, self.ipv6s)
    };

    let service_addr = format_smolstr!(
      "{}.{}.",
      self.service.as_str().trim_matches('.'),
      domain.as_str().trim_matches('.')
    );
    let instance_addr = format_smolstr!(
      "{}.{}.{}.",
      self.instance.as_str().trim_matches('.'),
      self.service.as_str().trim_matches('.'),
      domain.as_str().trim_matches('.')
    );
    let enum_addr = format_smolstr!(
      "_services._dns-sd._udp.{}.",
      domain.as_str().trim_matches('.')
    );

    let srv = SRV::new(self.srv_priority, self.srv_weight, port, hostname.clone())
      .map_err(invalid_input_err)?;

    Ok(Service {
      instance: self.instance,
      service: self.service,
      domain,
      hostname,
      ipv4s: match ipv4s.into_inner() {
        Either::Left(ips) => Arc::from_iter(ips),
        Either::Right(ips) => Arc::from(ips),
      },
      ipv6s: match ipv6s.into_inner() {
        Either::Left(ips) => Arc::from_iter(ips),
        Either::Right(ips) => Arc::from(ips),
      },
      txt: TXT::new(Arc::from_iter(self.txt)).map_err(invalid_input_err)?,
      service_addr: PTR::new(service_addr).map_err(invalid_input_err)?,
      instance_addr: PTR::new(instance_addr).map_err(invalid_input_err)?,
      enum_addr: PTR::new(enum_addr).map_err(invalid_input_err)?,
      ttl: AtomicU32::new(self.ttl),
      srv,
      _r: PhantomData,
    })
  }
}

/// Export a named service by implementing a [`Zone`].
pub struct Service<R> {
  /// Instance name (e.g. "hostService name")
  instance: SmolStr,
  /// Service name (e.g. "_http._tcp.")
  service: SmolStr,
  /// If blank, assumes "local"
  domain: SmolStr,
  /// Host machine DNS name (e.g. "mymachine.net")
  hostname: SmolStr,
  /// IP addresses for the service's host
  ipv4s: Arc<[A]>,
  ipv6s: Arc<[AAAA]>,

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
  _r: PhantomData<R>,
}

impl<R> Zone for Service<R>
where
  R: RuntimeLite,
{
  type Runtime = R;
  type Error = Infallible;

  async fn records<'a>(
    &'a self,
    qn: Label<'a>,
    rt: ResourceType,
  ) -> Result<TinyVec<RecordRef<'a>>, Infallible> {
    let enum_addr_label = Label::from(self.enum_addr.name());
    let service_addr_label = Label::from(self.service_addr.name());
    let instance_addr_label = Label::from(self.instance_addr.name());
    let hostname_label = Label::from(self.hostname.as_str());
    Ok(match () {
      () if enum_addr_label.eq(&qn) => self
        .service_enum(qn, rt)
        .map(|rr| TinyVec::from_iter([rr]))
        .unwrap_or_default(),
      () if service_addr_label.eq(&qn) => self.service_records(qn, rt),
      () if instance_addr_label.eq(&qn) => self.instance_records(qn, rt),
      () if hostname_label.eq(&qn) && matches!(rt, ResourceType::A | ResourceType::AAAA) => {
        self.instance_records(qn, rt)
      }
      _ => TinyVec::new(),
    })
  }
}

impl<R> Service<R> {
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

  /// Sets the port of the mdns service.
  #[inline]
  pub fn set_port(&self, port: u16) {
    self.srv.set_port(port);
  }

  /// Returns the TTL of the mdns service.
  #[inline]
  pub fn ttl(&self) -> u32 {
    self.ttl.load(Ordering::Acquire)
  }

  /// Sets the TTL of the mdns service.
  #[inline]
  pub fn set_ttl(&self, ttl: u32) {
    self.ttl.store(ttl, Ordering::Release);
  }

  /// Returns the IPv4 addresses of the mdns service.
  #[inline]
  pub fn ipv4s(&self) -> &[A] {
    &self.ipv4s
  }

  /// Returns the IPv6 addresses of the mdns service.
  #[inline]
  pub fn ipv6s(&self) -> &[AAAA] {
    &self.ipv6s
  }

  /// Returns the TXT records of the mdns service.
  #[inline]
  pub fn txt_records(&self) -> &[SmolStr] {
    self.txt.strings()
  }

  fn service_enum<'a>(&'a self, name: Label<'a>, rt: ResourceType) -> Option<RecordRef<'a>> {
    match rt {
      ResourceType::Wildcard | ResourceType::Ptr => Some(RecordRef::from_rdata(
        name,
        self.ttl(),
        RecordDataRef::PTR(&self.service_addr),
      )),
      _ => None,
    }
  }

  fn service_records<'a>(&'a self, name: Label<'a>, rt: ResourceType) -> TinyVec<RecordRef<'a>> {
    match rt {
      ResourceType::Wildcard | ResourceType::Ptr => {
        // Build a PTR response for the service
        let rr = RecordRef::from_rdata(name, self.ttl(), RecordDataRef::PTR(&self.instance_addr));

        let mut recs = TinyVec::from_iter([rr]);

        // Get the instance records
        recs
          .extend(self.instance_records(self.instance_addr.name().into(), ResourceType::Wildcard));
        recs
      }
      _ => TinyVec::new(),
    }
  }

  fn instance_records<'a>(&'a self, name: Label<'a>, rt: ResourceType) -> TinyVec<RecordRef<'a>> {
    match rt {
      ResourceType::Wildcard => {
        // Get the SRV, which includes A and AAAA
        let mut recs = self.instance_records(self.instance_addr.name().into(), ResourceType::Srv);

        // Add the TXT record
        recs.extend(self.instance_records(self.instance_addr.name().into(), ResourceType::Txt));
        recs
      }
      ResourceType::A => self
        .ipv4s
        .iter()
        .map(|ip| RecordRef::from_rdata(name, self.ttl(), RecordDataRef::A(ip)))
        .collect(),
      ResourceType::AAAA => self
        .ipv6s
        .iter()
        .map(|ip| RecordRef::from_rdata(name, self.ttl(), RecordDataRef::AAAA(ip)))
        .collect(),
      ResourceType::Srv => {
        // Create the SRV Record
        let rr = RecordRef::from_rdata(name, self.ttl(), RecordDataRef::SRV(&self.srv));

        let mut recs = TinyVec::from_iter([rr]);

        // Add the A record
        recs.extend(self.instance_records(self.instance_addr.name().into(), ResourceType::A));

        // Add the AAAA record
        recs.extend(self.instance_records(self.instance_addr.name().into(), ResourceType::AAAA));
        recs
      }
      ResourceType::Txt => {
        // Build a TXT response for the instance
        let rr = RecordRef::from_rdata(name, self.ttl(), RecordDataRef::TXT(&self.txt));
        TinyVec::from_iter([rr])
      }
      _ => TinyVec::new(),
    }
  }
}
