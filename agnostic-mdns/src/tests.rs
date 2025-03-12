use super::service::{Service, ServiceBuilder};

pub(crate) fn make_service() -> Service {
  make_service_with_service_name("_http._tcp")
}

pub(crate) fn make_service_with_service_name(name: &str) -> Service {
  ServiceBuilder::new("hostname".into(), name.into())
    .with_domain("local.".into())
    .with_hostname("testhost.".into())
    .with_port(80)
    .with_ip("192.168.0.42".parse().unwrap())
    .with_ip("2620:0:1000:1900:b0c2:d0b2:c411:18bc".parse().unwrap())
    .with_txt_record("Local web server".into())
    .finalize()
    .unwrap()
}

/// Initialize the tracing for the unit tests.
pub fn initialize_tests_tracing() {
  use std::sync::Once;
  static TRACE: Once = Once::new();
  TRACE.call_once(|| {
    let filter = std::env::var("AGNOSTIC_MDNS_TESTING_LOG").unwrap_or_else(|_| "info".to_owned());
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
