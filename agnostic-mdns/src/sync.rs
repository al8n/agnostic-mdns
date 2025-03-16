use core::convert::Infallible;
use mdns_proto::proto::{Label, ResourceRecord, ResourceType};

use crate::service::Service;

mod server;

pub use server::{Closer, Server};

/// The interface used to integrate with the server and
/// to serve records dynamically
pub trait Zone {
  /// The error type of the zone
  type Error: core::error::Error;

  /// Returns the answers for a DNS question.
  fn answers<'a>(
    &'a self,
    name: Label<'a>,
    rt: ResourceType,
  ) -> Result<impl Iterator<Item = ResourceRecord<'a>> + 'a, Self::Error>;

  /// Returns the additional records for a DNS question.
  fn additionals<'a>(
    &'a self,
    name: Label<'a>,
    rt: ResourceType,
  ) -> Result<impl Iterator<Item = ResourceRecord<'a>> + 'a, Self::Error>;
}

macro_rules! auto_impl {
  ($($name:ty),+$(,)?) => {
    $(
      impl<Z: Zone> Zone for $name {
        type Error = Z::Error;

        fn answers<'a>(
          &'a self,
          name: Label<'a>,
          rt: ResourceType,
        ) -> Result<impl Iterator<Item = ResourceRecord<'a>> + 'a, Self::Error> {
          (**self).answers(name, rt)
        }

        fn additionals<'a>(
          &'a self,
          name: Label<'a>,
          rt: ResourceType,
        ) -> Result<impl Iterator<Item = ResourceRecord<'a>> + 'a, Self::Error> {
          (**self).additionals(name, rt)
        }
      }
    )*
  };
}

auto_impl!(std::sync::Arc<Z>, triomphe::Arc<Z>, std::boxed::Box<Z>,);

impl Zone for Service {
  type Error = Infallible;

  fn answers<'a>(
    &'a self,
    qn: Label<'a>,
    rt: ResourceType,
  ) -> Result<impl Iterator<Item = ResourceRecord<'a>> + 'a, Self::Error> {
    Ok(self.fetch_answers(qn, rt))
  }

  fn additionals<'a>(
    &'a self,
    _: Label<'a>,
    _: ResourceType,
  ) -> Result<impl Iterator<Item = ResourceRecord<'a>> + 'a, Self::Error> {
    Ok(std::iter::empty())
  }
}
