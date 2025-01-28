use std::time::Duration;

use agnostic_mdns::{
  async_std::{query_with, Server},
  hostname, Name, QueryParam, ServerOptions, ServiceBuilder, SmolStr,
};
use futures::StreamExt;

fn main() {
  async_std::task::block_on(async move {
    let host = hostname().unwrap();
    let info = SmolStr::new("My awesome service");
    let service = ServiceBuilder::new(host.clone(), "_foobar._tcp".into())
      .with_txt_record(info)
      .with_port(80)
      .with_ip("192.168.0.3".parse().unwrap())
      .finalize()
      .await
      .unwrap();

    // Create the mDNS server, defer shutdown
    let srv = Server::new(service, ServerOptions::default())
      .await
      .unwrap();

    let params = QueryParam::new(Name::from("_foobar._tcp"))
      .with_timeout(Duration::from_millis(50))
      .with_disable_ipv6(true);

    let lookup = query_with(params).await.unwrap();

    futures::pin_mut!(lookup);
    while let Some(ent) = lookup.next().await {
      println!("Found: {ent:?}");
    }

    srv.shutdown().await;
  });
}
