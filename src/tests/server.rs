use core::time::Duration;

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
            assert_eq!(ent.port(), 80);
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

test_suites!(tokio {
  server_start_stop,
  server_lookup,
});

test_suites!(smol {
  server_start_stop,
  server_lookup,
});

test_suites!(async_std {
  server_start_stop,
  server_lookup,
});
