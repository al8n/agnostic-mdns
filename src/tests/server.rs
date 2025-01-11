use core::time::Duration;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use agnostic::Runtime;
use futures::StreamExt;

use crate::{
  client::{query_with, QueryParam},
  server::{Server, ServerOptions},
  tests::make_service,
  Name, Service,
};

use super::make_service_with_service_name;

async fn server_start_stop<R: Runtime>() {
  let s = make_service::<R>().await;
  let serv = Server::<Service<R>>::new(s, ServerOptions::default())
    .await
    .unwrap();

  let s = serv.zone();
  assert_eq!(s.instance().as_str(), "hostname");
  assert_eq!(s.hostname().as_str(), "testhost.");
  assert_eq!(s.domain().as_str(), "local.");
  assert_eq!(
    s.ips(),
    &[
      IpAddr::V4("192.168.0.42".parse().unwrap()),
      IpAddr::V6("2620:0:1000:1900:b0c2:d0b2:c411:18bc".parse().unwrap())
    ]
  );
  assert_eq!(s.port(), 80);
  assert_eq!(s.txt_records(), &["Local web server"]);

  let _ = serv.options();

  serv.shutdown().await;
}

async fn server_lookup<R: Runtime>() {
  let s = make_service_with_service_name("_foobar._tcp").await;
  let serv = Server::<Service<R>>::new(s, ServerOptions::default())
    .await
    .unwrap();

  #[cfg(target_os = "linux")]
  let params = QueryParam::new(Name::from("_foobar._tcp"))
    .with_timeout(Duration::from_millis(50))
    .with_disable_ipv6(false);

  #[cfg(not(target_os = "linux"))]
  let params = QueryParam::new(Name::from("_foobar._tcp"))
    .with_timeout(Duration::from_millis(50))
    .with_disable_ipv6(true);

  let mut got_response = false;
  match query_with::<R>(params).await {
    Ok(lookup) => {
      futures::pin_mut!(lookup);
      while let Some(res) = lookup.next().await {
        match res {
          Ok(ent) => {
            tracing::info!("Found service: {:?}", ent);
            assert_eq!(ent.name().as_str(), "hostname._foobar._tcp.local.");
            assert_eq!(ent.host().as_str(), "testhost.");
            assert_eq!(ent.port(), 80);
            assert_eq!(
              ent.ipv4_addr().unwrap(),
              &"192.168.0.42".parse::<Ipv4Addr>().unwrap()
            );
            assert_eq!(
              ent.ipv6_addr().unwrap(),
              &"2620:0:1000:1900:b0c2:d0b2:c411:18bc"
                .parse::<Ipv6Addr>()
                .unwrap()
            );
            assert_eq!(ent.infos()[0].as_str(), "Local web server");
            got_response = true;
          }
          Err(e) => {
            panic!("{e}");
          }
        }
      }

      serv.shutdown().await;
    }
    Err(e) => {
      serv.shutdown().await;
      panic!("{e}");
    }
  }

  assert!(got_response, "No response from the server");
}

#[cfg(feature = "tokio")]
test_suites!(tokio {
  server_start_stop,
  server_lookup,
});

#[cfg(feature = "smol")]
test_suites!(smol {
  server_start_stop,
  server_lookup,
});

#[cfg(feature = "async-std")]
test_suites!(async_std {
  server_start_stop,
  server_lookup,
});
