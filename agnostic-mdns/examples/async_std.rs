use std::time::Duration;

use agnostic_mdns::{
  QueryParam, ServerOptions, SmolStr,
  async_std::{Server, query},
  hostname,
  service::ServiceBuilder,
};

fn main() {
  async_std::task::block_on(async move {
    let host = hostname().unwrap();
    let info = SmolStr::new("My awesome service");
    let service = ServiceBuilder::new(host.as_str().into(), "_foobar._tcp".into())
      .with_txt_record(info)
      .with_port(80)
      .with_ip("192.168.0.3".parse().unwrap())
      .finalize()
      .unwrap();

    // Create the mDNS server, defer shutdown
    let srv = Server::new(service, ServerOptions::default())
      .await
      .unwrap();

    let params = QueryParam::new("_foobar._tcp".into())
      .with_timeout(Duration::from_millis(50))
      .with_disable_ipv6(true);

    let (tx, rx) = async_channel::unbounded();
    query(params, tx).await.unwrap();
    while let Ok(ent) = rx.recv().await {
      println!("Found: {ent:?}");
    }

    srv.shutdown().await;
  });
}
