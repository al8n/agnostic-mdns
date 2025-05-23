use mdns_proto::proto::{Label, ResourceRecord, ResourceType};

pub use agnostic_net as net;
pub use async_channel as channel;
pub use client::*;
pub use server::*;

mod client;
mod server;

#[cfg(test)]
mod tests;

/// The interface used to integrate with the server and
/// to serve records dynamically
pub trait Zone: core::fmt::Debug + Send + Sync + 'static {
  /// The error type of the zone
  type Error: core::error::Error + Send + Sync + 'static;

  /// Returns the answers for a DNS question.
  fn answers<'a>(
    &'a self,
    name: Label<'a>,
    rt: ResourceType,
  ) -> impl Future<Output = Result<impl Iterator<Item = ResourceRecord<'a>> + 'a, Self::Error>> + Send + 'a;

  /// Returns the additional records for a DNS question.
  fn additionals<'a>(
    &'a self,
    name: Label<'a>,
    rt: ResourceType,
  ) -> impl Future<Output = Result<impl Iterator<Item = ResourceRecord<'a>> + 'a, Self::Error>> + Send + 'a;
}

impl Zone for super::service::Service {
  type Error = core::convert::Infallible;

  async fn answers<'a>(
    &'a self,
    name: Label<'a>,
    rt: ResourceType,
  ) -> Result<impl Iterator<Item = ResourceRecord<'a>> + 'a, Self::Error> {
    Ok(self.fetch_answers(name, rt))
  }

  async fn additionals<'a>(
    &'a self,
    _: Label<'a>,
    _: ResourceType,
  ) -> Result<impl Iterator<Item = ResourceRecord<'a>> + 'a, Self::Error> {
    Ok(core::iter::empty())
  }
}
