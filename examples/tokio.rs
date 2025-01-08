use std::time::Duration;

use agnostic_mdns::{
  client::{bounded, lookup, query_with, QueryParam},
  hostname,
  server::{Server, ServerOptions},
  tokio::TokioRuntime,
  Name, RuntimeLite, ServiceBuilder, SmolStr,
};

#[tokio::main]
async fn main() {
  let host = hostname().unwrap();
  let info = SmolStr::new("My awesome service");
  let service = ServiceBuilder::new(host.clone(), "_foobar._tcp".into())
    .with_txt_record(info)
    .with_port(80)
    .with_ip("192.168.0.3".parse().unwrap())
    .finalize::<TokioRuntime>()
    .await
    .unwrap();

  // Create the mDNS server, defer shutdown
  let srv = Server::new(service, ServerOptions::default())
    .await
    .unwrap();

  // Make a channel for results and start listening
  let (producer, consumer) = bounded(4);

  let handle = TokioRuntime::spawn(async move {
    while let Ok(ent) = consumer.recv().await {
      println!("Got new entry: {:?}", ent);
    }
  });

  let params = QueryParam::new(Name::from("_foobar._tcp"))
    .with_timeout(Duration::from_millis(50))
    .with_disable_ipv6(true);

  query_with::<TokioRuntime>(params, producer).await.unwrap();

  handle.await.unwrap();
  srv.shutdown().await;
}
