use core::{future::Future, str::FromStr};

use agnostic::Runtime;

use crate::{Service, ServiceBuilder, types::Name};

macro_rules! test_suites {
  ($runtime:ident {
    $($name:ident),+$(,)?
  }) => {
    $(
      paste::paste! {
        #[test]
        fn [< $runtime $name >]() {
          $crate::tests::[< $runtime _run >]($name::<agnostic::[< $runtime >]::[< $runtime:camel Runtime >]>());
        }
      }
    )*
  }
}

mod client;
mod server;
mod zone;

pub(crate) async fn make_service<R: Runtime>() -> Service<R> {
  make_service_with_service_name::<R>("_http._tcp").await
}

pub(crate) async fn make_service_with_service_name<R: Runtime>(name: &str) -> Service<R> {
  ServiceBuilder::new(
    Name::from("testhost."),
    Name::from("hostname"),
    name.into(),
  )
  .with_domain("local.".into())
  .with_port(80)
  .with_ip("192.168.0.42".parse().unwrap())
  .with_ip("2620:0:1000:1900:b0c2:d0b2:c411:18bc".parse().unwrap())
  .with_txt_record("Local web server".into())
  .finalize::<R>()
  .await
  .unwrap()
}

fn tokio_run<F>(f: F)
where
  F: Future<Output = ()>,
{
  tokio::runtime::Builder::new_current_thread()
    .enable_all()
    .build()
    .unwrap()
    .block_on(f);
}

fn smol_run<F>(f: F)
where
  F: Future<Output = ()>,
{
  smol::block_on(f);
}

fn async_std_run<F>(f: F)
where
  F: Future<Output = ()>,
{
  async_std::task::block_on(f);
}
