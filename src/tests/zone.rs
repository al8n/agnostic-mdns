use core::{
  net::{Ipv4Addr, Ipv6Addr},
  panic,
};

use smallvec_wrapper::OneOrMore;

use crate::{
  tests::make_service,
  types::{Name, Record, RecordData, RecordType},
  Zone,
};

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
    .records(&Name::from("random"), RecordType::ANY)
    .await
    .unwrap();
  assert!(recs.is_empty(), "bad: {recs:?}");
}

async fn service_addr<R: RuntimeLite>() {
  let s = make_service::<R>().await;

  let recs = s
    .records(&"_http._tcp.local.".into(), RecordType::ANY)
    .await
    .unwrap();
  assert_eq!(recs.len(), 5, "bad: {recs:?}");

  let RecordData::PTR(ptr) = recs[0].data() else {
    panic!("bad: {recs:?}")
  };
  assert_eq!(ptr, &Name::from("hostname._http._tcp.local."));

  matches!(recs[1].data(), RecordData::SRV(_));
  matches!(recs[2].data(), RecordData::A(_));
  matches!(recs[3].data(), RecordData::AAAA(_));
  matches!(recs[4].data(), RecordData::TXT(_));
}

async fn instance_addr_any<R: RuntimeLite>() {
  let s = make_service::<R>().await;

  let recs = s
    .records(&"hostname._http._tcp.local.".into(), RecordType::ANY)
    .await
    .unwrap();
  assert_eq!(recs.len(), 4, "bad: {recs:?}");

  matches!(recs[0].data(), RecordData::SRV(_));
  matches!(recs[1].data(), RecordData::A(_));
  matches!(recs[2].data(), RecordData::AAAA(_));
  matches!(recs[3].data(), RecordData::TXT(_));
}

async fn instance_addr_srv<R: RuntimeLite>() {
  let s = make_service::<R>().await;

  let recs = s
    .records(&"hostname._http._tcp.local.".into(), RecordType::SRV)
    .await
    .unwrap();
  assert_eq!(recs.len(), 3, "bad: {recs:?}");

  let RecordData::SRV(srv) = recs[0].data() else {
    panic!("bad: {recs:?}")
  };

  matches!(recs[1].data(), RecordData::A(_));
  matches!(recs[2].data(), RecordData::AAAA(_));

  assert_eq!(srv.port(), s.port());
}

async fn instance_addr_a<R: RuntimeLite>() {
  let s = make_service::<R>().await;

  let recs = s
    .records(&"hostname._http._tcp.local.".into(), RecordType::A)
    .await
    .unwrap();
  assert_eq!(recs.len(), 1, "bad: {recs:?}");

  let RecordData::A(a) = recs[0].data() else {
    panic!("bad: {recs:?}")
  };

  assert_eq!(a, &"192.168.0.42".parse::<Ipv4Addr>().unwrap());
}

async fn instance_addr_aaaa<R: RuntimeLite>() {
  let s = make_service::<R>().await;

  let recs = s
    .records(&"hostname._http._tcp.local.".into(), RecordType::AAAA)
    .await
    .unwrap();
  assert_eq!(recs.len(), 1, "bad: {recs:?}");

  let RecordData::AAAA(aaaa) = recs[0].data() else {
    panic!("bad: {recs:?}")
  };

  assert_eq!(
    aaaa,
    &"2620:0:1000:1900:b0c2:d0b2:c411:18bc"
      .parse::<Ipv6Addr>()
      .unwrap()
  );
}

async fn instance_addr_txt<R: RuntimeLite>() {
  let s = make_service::<R>().await;

  let recs = s
    .records(&"hostname._http._tcp.local.".into(), RecordType::TXT)
    .await
    .unwrap();
  assert_eq!(recs.len(), 1, "bad: {recs:?}");

  let RecordData::TXT(txt) = recs[0].data() else {
    panic!("bad: {recs:?}")
  };

  assert_eq!(&txt[0], &s.txt_records()[0]);
}

async fn hostname_query<R: RuntimeLite>() {
  let questions = [
    (
      ("testhost.".into(), RecordType::A),
      OneOrMore::from(Record::from_rdata(
        Name::from("testhost."),
        120,
        RecordData::A("192.168.0.42".parse().unwrap()),
      )),
    ),
    (
      ("testhost.".into(), RecordType::AAAA),
      OneOrMore::from(Record::from_rdata(
        Name::from("testhost."),
        120,
        RecordData::AAAA("2620:0:1000:1900:b0c2:d0b2:c411:18bc".parse().unwrap()),
      )),
    ),
  ];

  let s = make_service::<R>().await;

  for ((name, ty), r) in questions.iter() {
    let recs = s.records(name, *ty).await.unwrap();
    assert_eq!(recs.len(), 1, "bad: {recs:?}");
    assert_eq!(&recs, r);
  }
}

async fn service_enum_ptr<R: RuntimeLite>() {
  let s = make_service::<R>().await;

  let recs = s
    .records(&"_services._dns-sd._udp.local.".into(), RecordType::PTR)
    .await
    .unwrap();
  assert_eq!(recs.len(), 1, "bad: {recs:?}");

  let RecordData::PTR(ptr) = recs[0].data() else {
    panic!("bad: {recs:?}")
  };
  assert_eq!(ptr, &Name::from("_http._tcp.local."));
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
  hostname_query,
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
  hostname_query,
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
  hostname_query,
  service_enum_ptr,
});
