use core::future::Future;

use agnostic::Runtime;

use super::{Service, ServiceBuilder};

macro_rules! test_suites {
  ($runtime:ident {
    $($name:ident),+$(,)?
  }) => {
    $(
      paste::paste! {
        #[test]
        fn [< $runtime _ $name >]() {
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
  ServiceBuilder::new("hostname".into(), name.into())
    .with_domain("local.".into())
    .with_hostname("testhost.".into())
    .with_port(80)
    .with_ip("192.168.0.42".parse().unwrap())
    .with_ip("2620:0:1000:1900:b0c2:d0b2:c411:18bc".parse().unwrap())
    .with_txt_record("Local web server".into())
    .finalize::<R>()
    .await
    .unwrap()
}

/// Initialize the tracing for the unit tests.
pub fn initialize_tests_tracing() {
  use std::sync::Once;
  static TRACE: Once = Once::new();
  TRACE.call_once(|| {
    let filter = std::env::var("AGNOSTIC_MDNS_TESTING_LOG").unwrap_or_else(|_| "trace".to_owned());
    tracing::subscriber::set_global_default(
      tracing_subscriber::fmt::fmt()
        .without_time()
        .with_line_number(true)
        .with_env_filter(filter)
        .with_file(false)
        .with_target(true)
        .with_ansi(true)
        .finish(),
    )
    .unwrap();
  });
}

#[cfg(feature = "tokio")]
fn tokio_run<F>(f: F)
where
  F: Future<Output = ()>,
{
  initialize_tests_tracing();

  tokio::runtime::Builder::new_current_thread()
    .enable_all()
    .build()
    .unwrap()
    .block_on(f);
}

#[cfg(feature = "smol")]
fn smol_run<F>(f: F)
where
  F: Future<Output = ()>,
{
  initialize_tests_tracing();
  smol::block_on(f);
}

#[cfg(feature = "async-std")]
fn async_std_run<F>(f: F)
where
  F: Future<Output = ()>,
{
  initialize_tests_tracing();
  async_std::task::block_on(f);
}
