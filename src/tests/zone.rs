use core::{
  net::{Ipv4Addr, Ipv6Addr},
  panic,
};

use dns_protocol::ResourceType;

use crate::{tests::make_service, types::RecordDataRef, Zone, A, AAAA};

use super::*;

macro_rules! test_suites {
  ($runtime:ident {
    $($name:ident),+$(,)?
  }) => {
    $(
      paste::paste! {
        #[test]
        fn [< $runtime _ $name >]() {
          $crate::tests::[< $runtime _run >]($name::<agnostic_net::runtime::[< $runtime >]::[< $runtime:camel Runtime>]>());
        }
      }
    )*
  }
}

async fn bad_addr<R: RuntimeLite>() {
  let s = make_service::<R>().await;

  let recs = s
    .records("random".into(), ResourceType::Wildcard)
    .await
    .unwrap();
  assert!(recs.is_empty(), "bad: {recs:?}");
}

async fn service_addr<R: RuntimeLite>() {
  let s = make_service::<R>().await;

  let recs = s
    .records("_http._tcp.local.".into(), ResourceType::Wildcard)
    .await
    .unwrap();
  assert_eq!(recs.len(), 5, "bad: {recs:?}");

  let RecordDataRef::PTR(ptr) = recs[0].data() else {
    panic!("bad: {recs:?}")
  };
  assert_eq!(ptr.name(), "hostname._http._tcp.local.");

  matches!(recs[1].data(), RecordDataRef::SRV(_));
  matches!(recs[2].data(), RecordDataRef::A(_));
  matches!(recs[3].data(), RecordDataRef::AAAA(_));
  matches!(recs[4].data(), RecordDataRef::TXT(_));
}

async fn instance_addr_any<R: RuntimeLite>() {
  let s = make_service::<R>().await;

  let recs = s
    .records("hostname._http._tcp.local.".into(), ResourceType::Wildcard)
    .await
    .unwrap();
  assert_eq!(recs.len(), 4, "bad: {recs:?}");

  matches!(recs[0].data(), RecordDataRef::SRV(_));
  matches!(recs[1].data(), RecordDataRef::A(_));
  matches!(recs[2].data(), RecordDataRef::AAAA(_));
  matches!(recs[3].data(), RecordDataRef::TXT(_));
}

async fn instance_addr_srv<R: RuntimeLite>() {
  let s = make_service::<R>().await;

  let recs = s
    .records("hostname._http._tcp.local.".into(), ResourceType::Srv)
    .await
    .unwrap();
  assert_eq!(recs.len(), 3, "bad: {recs:?}");

  let RecordDataRef::SRV(srv) = recs[0].data() else {
    panic!("bad: {recs:?}")
  };

  matches!(recs[1].data(), RecordDataRef::A(_));
  matches!(recs[2].data(), RecordDataRef::AAAA(_));

  assert_eq!(srv.port(), s.port());
}

async fn instance_addr_a<R: RuntimeLite>() {
  let s = make_service::<R>().await;

  let recs = s
    .records("hostname._http._tcp.local.".into(), ResourceType::A)
    .await
    .unwrap();
  assert_eq!(recs.len(), 1, "bad: {recs:?}");

  let RecordDataRef::A(a) = recs[0].data() else {
    panic!("bad: {recs:?}")
  };

  assert_eq!(**a, A::from("192.168.0.42".parse::<Ipv4Addr>().unwrap()));
}

async fn instance_addr_aaaa<R: RuntimeLite>() {
  let s = make_service::<R>().await;

  let recs = s
    .records("hostname._http._tcp.local.".into(), ResourceType::AAAA)
    .await
    .unwrap();
  assert_eq!(recs.len(), 1, "bad: {recs:?}");

  let RecordDataRef::AAAA(aaaa) = recs[0].data() else {
    panic!("bad: {recs:?}")
  };

  assert_eq!(
    **aaaa,
    AAAA::from(
      "2620:0:1000:1900:b0c2:d0b2:c411:18bc"
        .parse::<Ipv6Addr>()
        .unwrap()
    )
  );
}

async fn instance_addr_txt<R: RuntimeLite>() {
  let s = make_service::<R>().await;

  let recs = s
    .records("hostname._http._tcp.local.".into(), ResourceType::Txt)
    .await
    .unwrap();
  assert_eq!(recs.len(), 1, "bad: {recs:?}");

  let RecordDataRef::TXT(txt) = recs[0].data() else {
    panic!("bad: {recs:?}")
  };

  assert_eq!(txt.strings()[0].as_str(), s.txt_records()[0].as_str());
}

async fn service_enum_ptr<R: RuntimeLite>() {
  let s = make_service::<R>().await;

  let recs = s
    .records("_services._dns-sd._udp.local.".into(), ResourceType::Ptr)
    .await
    .unwrap();
  assert_eq!(recs.len(), 1, "bad: {recs:?}");

  let RecordDataRef::PTR(ptr) = recs[0].data() else {
    panic!("bad: {recs:?}")
  };
  assert_eq!(ptr.name(), "_http._tcp.local.");
}

#[cfg(feature = "tokio")]
test_suites!(tokio {
  bad_addr,
  service_addr,
  instance_addr_any,
  instance_addr_srv,
  instance_addr_a,
  instance_addr_aaaa,
  instance_addr_txt,
  service_enum_ptr,
});

#[cfg(feature = "smol")]
test_suites!(smol {
  bad_addr,
  service_addr,
  instance_addr_any,
  instance_addr_srv,
  instance_addr_a,
  instance_addr_aaaa,
  instance_addr_txt,
  service_enum_ptr,
});

#[cfg(feature = "async-std")]
test_suites!(async_std {
  bad_addr,
  service_addr,
  instance_addr_any,
  instance_addr_srv,
  instance_addr_a,
  instance_addr_aaaa,
  instance_addr_txt,
  service_enum_ptr,
});
