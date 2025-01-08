use core::time::Duration;

use agnostic::Runtime;
use futures_util::FutureExt;

use crate::{
  client::{bounded, query_with, QueryParam},
  server::{Server, ServerOptions},
  tests::make_service,
  Name,
};

use super::make_service_with_service_name;

async fn server_start_stop<R: Runtime>() {
  let s = make_service::<R>().await;
  let serv = Server::<R>::new(s, ServerOptions::default()).await.unwrap();

  serv.shutdown().await;
}

async fn server_lookup<R: Runtime>() {
  let s = make_service_with_service_name("_foobar._tcp").await;
  let serv = Server::<R>::new(s, ServerOptions::default()).await.unwrap();
  let (producer, consumer) = bounded(1);
  let (err_tx, err_rx) = async_channel::bounded::<String>(1);
  scopeguard::defer!(err_tx.close(););

  let err_tx1 = err_tx.clone();
  R::spawn_detach(async move {
    let timeout = Duration::from_millis(80);
    let sleep = R::sleep(timeout);
    futures_util::select! {
      ent = consumer.recv().fuse() => {
        match ent {
          Err(e) => {
            let _ = err_tx1.send(e.to_string()).await;
          },
          Ok(ent) => {
            if ent.name().to_string().ne("hostname._foobar._tcp.local.") {
              let _ = err_tx1.send(format!("entry has the wrong name: {:?}", ent)).await;
            }

            if ent.port() != 80 {
              let _ = err_tx1.send(format!("entry has the wrong port: {:?}", ent)).await;
            }

            if ent.infos()[0].ne("Local web server") {
              let _ = err_tx1.send(format!("entry has the wrong info: {:?}", ent)).await;
            }

            let _ = err_tx1.send("success".to_string()).await;
          },
        }
      },
      _ = sleep.fuse() => {
        let _ = err_tx1.send("timed out waiting for response".to_string()).await;
      }
    }
  });

  let params = QueryParam::new(Name::from("_foobar._tcp"))
    .with_timeout(Duration::from_millis(50))
    .with_disable_ipv6(true);

  match query_with::<R>(params, producer).await {
    Ok(_) => {}
    Err(e) => {
      serv.shutdown().await;
      panic!("{}", e);
    }
  }

  match err_rx.recv().await {
    Ok(res) => {
      if res.ne("success") {
        serv.shutdown().await;
        panic!("{}", res);
      }

      serv.shutdown().await;
    }
    Err(e) => {
      serv.shutdown().await;
      panic!("{}", e);
    }
  }
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
