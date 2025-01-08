use core::{convert::Infallible, error::Error, future::Future, marker::PhantomData, net::IpAddr};

use std::{io, net::ToSocketAddrs, vec::Vec};

use crate::invalid_input_err;

use super::types::{Name, Record, RecordData, RecordType, SRV};
use agnostic::Runtime;
use smallvec_wrapper::{OneOrMore, TinyVec};
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
    hostname: Name,
    /// the error
    #[source]
    error: Box<dyn Error + Send + Sync + 'static>,
  },
  /// Not a fully qualified domain name
  #[error("{0} is not a fully qualified domain name")]
  NotFQDN(Name),
}

/// The interface used to integrate with the server and
/// to serve records dynamically
pub trait Zone: Send + Sync + 'static {
  /// The runtime type
  type Runtime: Runtime;

  /// The error type of the zone
  type Error: core::error::Error + Send + Sync + 'static;

  /// Returns DNS records in response to a DNS question.
  fn records(
    &self,
    name: &Name,
    rt: RecordType,
  ) -> impl Future<Output = Result<OneOrMore<Record>, Self::Error>> + Send;
}

macro_rules! auto_impl {
  ($($name:ty),+$(,)?) => {
    $(
      impl<Z: Zone> Zone for $name {
        type Runtime = Z::Runtime;
        type Error = Z::Error;

        async fn records(
          &self,
          name: &Name,
          rt: RecordType,
        ) -> Result<OneOrMore<Record>, Self::Error> {
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
  domain: Option<Name>,
  hostname: Option<Name>,
  port: Option<u16>,
  ips: TinyVec<IpAddr>,
  txt: Vec<SmolStr>,
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
      ips: TinyVec::new(),
      txt: Vec::new(),
      ttl: DEFAULT_TTL,
      srv_priority: 10,
      srv_weight: 1,
    }
  }

  /// Gets the current instance name.
  pub fn instance(&self) -> &SmolStr {
    &self.instance
  }

  /// Gets the current service name.
  pub fn service(&self) -> &SmolStr {
    &self.service
  }

  /// Gets the current domain.
  pub fn domain(&self) -> Option<&Name> {
    self.domain.as_ref()
  }

  /// Sets the domain for the service.
  pub fn with_domain(mut self, domain: Name) -> Self {
    self.domain = Some(domain);
    self
  }

  /// Gets the current host name.
  pub fn hostname(&self) -> Option<&Name> {
    self.hostname.as_ref()
  }

  /// Sets the host name for the service.
  pub fn with_hostname(mut self, hostname: Name) -> Self {
    self.hostname = Some(hostname);
    self
  }

  /// Gets the TTL.
  ///
  /// Defaults to `120` seconds.
  pub fn ttl(&self) -> u32 {
    self.ttl
  }

  /// Sets the TTL for the service.
  ///
  /// Defaults to `120` seconds.
  pub fn with_ttl(mut self, ttl: u32) -> Self {
    self.ttl = ttl;
    self
  }

  /// Gets the priority for SRV records.
  ///
  /// Defaults to `10`.
  pub fn srv_priority(&self) -> u16 {
    self.srv_priority
  }

  /// Sets the priority for SRV records.
  ///
  /// Defaults to `10`.
  pub fn with_srv_priority(mut self, priority: u16) -> Self {
    self.srv_priority = priority;
    self
  }

  /// Gets the weight for SRV records.
  ///
  /// Defaults to `1`.
  pub fn srv_weight(&self) -> u16 {
    self.srv_weight
  }

  /// Sets the weight for SRV records.
  ///
  /// Defaults to `1`.
  pub fn with_srv_weight(mut self, weight: u16) -> Self {
    self.srv_weight = weight;
    self
  }

  /// Gets the current port.
  pub fn port(&self) -> Option<u16> {
    self.port
  }

  /// Sets the port for the service.
  pub fn with_port(mut self, port: u16) -> Self {
    self.port = Some(port);
    self
  }

  /// Gets the current IP addresses.
  pub fn ips(&self) -> &[IpAddr] {
    &self.ips
  }

  /// Sets the IP addresses for the service.
  pub fn with_ips(mut self, ips: TinyVec<IpAddr>) -> Self {
    self.ips = ips;
    self
  }

  /// Pushes an IP address to the list of IP addresses.
  pub fn with_ip(mut self, ip: IpAddr) -> Self {
    self.ips.push(ip);
    self
  }

  /// Gets the current TXT records.
  pub fn txt_records(&self) -> &[SmolStr] {
    &self.txt
  }

  /// Sets the TXT records for the service.
  pub fn with_txt_records(mut self, txt: Vec<SmolStr>) -> Self {
    self.txt = txt;
    self
  }

  /// Pushes a TXT record to the list of TXT records.
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
    R: Runtime,
  {
    let domain = match self.domain {
      Some(domain) if !domain.is_fqdn() => {
        return Err(invalid_input_err(ServiceError::NotFQDN(domain)))
      }
      Some(domain) => domain,
      None => Name::local_fqdn(),
    };

    let hostname = match self.hostname {
      Some(hostname) if !hostname.as_str().is_empty() => {
        if !hostname.is_fqdn() {
          return Err(invalid_input_err(ServiceError::NotFQDN(hostname)));
        }
        hostname
      }
      _ => Name::from_components(super::hostname_fqdn()?, true),
    };

    let port = match self.port {
      None | Some(0) => return Err(invalid_input_err(ServiceError::PortNotFound)),
      Some(port) => port,
    };

    let ips = if self.ips.is_empty() {
      let tmp_hostname = hostname.clone().append(&domain);

      tmp_hostname
        .as_str()
        .to_socket_addrs()
        .map_err(|e| {
          invalid_input_err(ServiceError::IpNotFound {
            hostname: tmp_hostname,
            error: e.into(),
          })
        })?
        .map(|addr| addr.ip())
        .collect()
    } else {
      self.ips
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

    Ok(Service {
      port,
      ips,
      txt: Arc::from_iter(self.txt),
      service_addr: Name::from_components(service_addr, true),
      instance_addr: Name::from_components(instance_addr, true),
      enum_addr: Name::from_components(enum_addr, true),
      instance: self.instance,
      service: self.service,
      domain,
      hostname,
      ttl: self.ttl,
      srv_priority: self.srv_priority,
      srv_weight: self.srv_weight,
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
  domain: Name,
  /// Host machine DNS name (e.g. "mymachine.net")
  hostname: Name,
  /// Service port
  port: u16,
  /// IP addresses for the service's host
  ips: TinyVec<IpAddr>,
  /// Service TXT records
  txt: Arc<[SmolStr]>,
  /// Fully qualified service address
  service_addr: Name,
  /// Fully qualified instance address
  instance_addr: Name,
  /// _services._dns-sd._udp.<domain>
  enum_addr: Name,
  ttl: u32,
  srv_priority: u16,
  srv_weight: u16,
  _r: PhantomData<R>,
}

impl<R> Zone for Service<R>
where
  R: Runtime,
{
  type Runtime = R;
  type Error = Infallible;

  async fn records(&self, name: &Name, rt: RecordType) -> Result<OneOrMore<Record>, Infallible> {
    let qn = name;
    Ok(match () {
      () if self.enum_addr.eq(qn) => self.service_enum(name, rt),
      () if self.service_addr.eq(qn) => self.service_records(name, rt),
      () if self.instance_addr.eq(qn) => self.instance_records(name, rt),
      () if self.hostname.eq(qn) && matches!(rt, RecordType::A | RecordType::AAAA) => {
        self.instance_records(name, rt)
      }
      _ => OneOrMore::new(),
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
  pub const fn domain(&self) -> &Name {
    &self.domain
  }

  /// Returns the hostname of the mdns service.
  #[inline]
  pub const fn hostname(&self) -> &Name {
    &self.hostname
  }

  /// Returns the port of the mdns service.
  #[inline]
  pub const fn port(&self) -> u16 {
    self.port
  }

  /// Returns the IP addresses of the mdns service.
  #[inline]
  pub fn ips(&self) -> &[IpAddr] {
    &self.ips
  }

  /// Returns the TXT records of the mdns service.
  #[inline]
  pub fn txt_records(&self) -> &[SmolStr] {
    &self.txt
  }

  fn service_enum(&self, name: &Name, rt: RecordType) -> OneOrMore<Record> {
    match rt {
      RecordType::ANY | RecordType::PTR => OneOrMore::from_buf([Record::from_rdata(
        name.clone(),
        self.ttl,
        RecordData::PTR(self.service_addr.clone()),
      )]),
      _ => OneOrMore::new(),
    }
  }

  fn service_records(&self, name: &Name, rt: RecordType) -> OneOrMore<Record> {
    match rt {
      RecordType::ANY | RecordType::PTR => {
        // Build a PTR response for the service
        let rr = Record::from_rdata(
          name.clone(),
          self.ttl,
          RecordData::PTR(self.instance_addr.clone()),
        );

        let mut recs = OneOrMore::from_buf([rr]);

        // Get the instance records
        recs.extend(self.instance_records(&self.instance_addr, RecordType::ANY));
        recs
      }
      _ => OneOrMore::new(),
    }
  }

  fn instance_records(&self, name: &Name, rt: RecordType) -> OneOrMore<Record> {
    match rt {
      RecordType::ANY => {
        // Get the SRV, which includes A and AAAA
        let mut recs = self.instance_records(&self.instance_addr, RecordType::SRV);

        // Add the TXT record
        recs.extend(self.instance_records(&self.instance_addr, RecordType::TXT));
        recs
      }
      RecordType::A => self
        .ips
        .iter()
        .filter_map(|ip| match ip {
          IpAddr::V4(ip) => Some(Record::from_rdata(
            name.clone(),
            self.ttl,
            RecordData::A(*ip),
          )),
          _ => None,
        })
        .collect(),
      RecordType::AAAA => self
        .ips
        .iter()
        .filter_map(|ip| match ip {
          IpAddr::V6(ip) => Some(Record::from_rdata(
            name.clone(),
            self.ttl,
            RecordData::AAAA(*ip),
          )),
          _ => None,
        })
        .collect(),
      RecordType::SRV => {
        // Create the SRV Record
        let rr = Record::from_rdata(
          name.clone(),
          self.ttl,
          RecordData::SRV(SRV::new(
            self.srv_priority,
            self.srv_weight,
            self.port,
            self.hostname.clone(),
          )),
        );

        let mut recs = OneOrMore::from_buf([rr]);

        // Add the A record
        recs.extend(self.instance_records(&self.instance_addr, RecordType::A));

        // Add the AAAA record
        recs.extend(self.instance_records(&self.instance_addr, RecordType::AAAA));
        recs
      }
      RecordType::TXT => {
        // Build a TXT response for the instance
        let rr = Record::from_rdata(name.clone(), self.ttl, RecordData::TXT(self.txt.clone()));
        OneOrMore::from_buf([rr])
      }
      _ => OneOrMore::new(),
    }
  }
}
