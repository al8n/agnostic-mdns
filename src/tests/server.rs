use core::time::Duration;

use agnostic::Runtime;
use futures::FutureExt;

use crate::{
  client::{query_with, unbounded, QueryParam},
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
  let (producer, consumer) = unbounded();
  let (err_tx, err_rx) = async_channel::bounded::<String>(1);
  scopeguard::defer!(err_tx.close(););

  let err_tx1 = err_tx.clone();
  R::spawn_detach(async move {
    let timeout = Duration::from_millis(80);
    let sleep = R::sleep(timeout);
    futures::select! {
      ent = consumer.recv().fuse() => {
        match ent {
          Err(e) => {
            println!("{e}");
            err_tx1.send(e.to_string()).await.unwrap();
          },
          Ok(ent) => {
            panic!("{ent:?}");
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
        err_tx1.send("timed out waiting for response".to_string()).await.unwrap();
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
      panic!("{e}");
    }
  }

  match err_rx.recv().await {
    Ok(res) => {
      if res.ne("success") {
        serv.shutdown().await;
      }

      serv.shutdown().await;
    }
    Err(e) => {
      serv.shutdown().await;
      panic!("{e}");
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
