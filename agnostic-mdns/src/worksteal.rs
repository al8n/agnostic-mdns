use agnostic_net::runtime::RuntimeLite;
use dns_protocol::{Label, ResourceRecord, ResourceType};

pub use agnostic_net as net;
pub use server::*;

mod server;

#[cfg(test)]
mod tests;

/// The interface used to integrate with the server and
/// to serve records dynamically
pub trait Zone<R>: Send + Sync + 'static {
  // /// The runtime type
  // type Runtime: RuntimeLite;

  /// The error type of the zone
  type Error: core::error::Error + Send + Sync + 'static;

  /// Returns the answers for a DNS question.
  fn answers<'a>(
    &'a self,
    name: Label<'a>,
    rt: ResourceType,
  ) -> impl Future<Output = Result<impl Iterator<Item = ResourceRecord<'a>> + 'a, Self::Error>> + Send + 'a
  where
    R: RuntimeLite;

  /// Returns the additional records for a DNS question.
  fn additionals<'a>(
    &'a self,
    name: Label<'a>,
    rt: ResourceType,
  ) -> impl Future<Output = Result<impl Iterator<Item = ResourceRecord<'a>> + 'a, Self::Error>> + Send + 'a
  where
    R: RuntimeLite;
}

impl<R> Zone<R> for super::service::Service
where
  R: RuntimeLite,
{
  type Error = core::convert::Infallible;

  async fn answers<'a>(
    &'a self,
    name: Label<'a>,
    rt: ResourceType,
  ) -> Result<impl Iterator<Item = ResourceRecord<'a>> + 'a, Self::Error>
  where
    R: RuntimeLite,
  {
    Ok(self.fetch_answers(name, rt))
  }

  async fn additionals<'a>(
    &'a self,
    _: Label<'a>,
    _: ResourceType,
  ) -> Result<impl Iterator<Item = ResourceRecord<'a>> + 'a, Self::Error>
  where
    R: RuntimeLite,
  {
    Ok(core::iter::empty())
  }
}
