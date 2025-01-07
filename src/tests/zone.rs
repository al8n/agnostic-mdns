use core::net::{Ipv4Addr, Ipv6Addr};

use hickory_proto::rr::{
  rdata::{A, AAAA},
  RData, Record, RecordType,
};
use smallvec_wrapper::OneOrMore;

use crate::{tests::make_service, Zone};

use super::*;

async fn bad_addr<R: Runtime>() {
  let s = make_service::<R>().await;

  let recs = s
    .records(&Name::from_str("randome").unwrap(), RecordType::ANY)
    .await
    .unwrap();
  assert!(recs.is_empty(), "bad: {recs:?}");
}

async fn service_addr<R: Runtime>() {
  let s = make_service::<R>().await;

  let recs = s
    .records(&"_http._tcp.local.".parse().unwrap(), RecordType::ANY)
    .await
    .unwrap();
  assert_eq!(recs.len(), 5, "bad: {recs:?}");

  let ptr = recs[0].data().cloned().unwrap().into_ptr().unwrap();
  assert_eq!(ptr.0, Name::from_str("hostname._http._tcp.local.").unwrap());

  recs[1].data().cloned().unwrap().into_srv().expect("SRV");

  recs[2].data().cloned().unwrap().into_a().expect("A");

  recs[3].data().cloned().unwrap().into_aaaa().expect("AAAA");

  recs[4].data().cloned().unwrap().into_txt().expect("TXT");
}

async fn instance_addr_any<R: Runtime>() {
  let s = make_service::<R>().await;

  let recs = s
    .records(
      &"hostname._http._tcp.local.".parse().unwrap(),
      RecordType::ANY,
    )
    .await
    .unwrap();
  assert_eq!(recs.len(), 4, "bad: {recs:?}");

  recs[0].data().cloned().unwrap().into_srv().expect("SRV");

  recs[1].data().cloned().unwrap().into_a().expect("A");

  recs[2].data().cloned().unwrap().into_aaaa().expect("AAAA");

  recs[3].data().cloned().unwrap().into_txt().expect("TXT");
}

async fn instance_addr_srv<R: Runtime>() {
  let s = make_service::<R>().await;

  let recs = s
    .records(
      &"hostname._http._tcp.local.".parse().unwrap(),
      RecordType::SRV,
    )
    .await
    .unwrap();
  assert_eq!(recs.len(), 3, "bad: {recs:?}");

  let srv = recs[0].data().cloned().unwrap().into_srv().expect("SRV");

  recs[1].data().cloned().unwrap().into_a().expect("A");

  recs[2].data().cloned().unwrap().into_aaaa().expect("AAAA");

  assert_eq!(srv.port(), s.port());
}

async fn instance_addr_a<R: Runtime>() {
  let s = make_service::<R>().await;

  let recs = s
    .records(
      &"hostname._http._tcp.local.".parse().unwrap(),
      RecordType::A,
    )
    .await
    .unwrap();
  assert_eq!(recs.len(), 1, "bad: {recs:?}");

  let a = recs[0].data().cloned().unwrap().into_a().expect("A");

  assert_eq!(a.0, "192.168.0.42".parse::<Ipv4Addr>().unwrap());
}

async fn instance_addr_aaaa<R: Runtime>() {
  let s = make_service::<R>().await;

  let recs = s
    .records(
      &"hostname._http._tcp.local.".parse().unwrap(),
      RecordType::AAAA,
    )
    .await
    .unwrap();
  assert_eq!(recs.len(), 1, "bad: {recs:?}");

  let aaaa = recs[0].data().cloned().unwrap().into_aaaa().expect("AAAA");

  assert_eq!(
    aaaa.0,
    "2620:0:1000:1900:b0c2:d0b2:c411:18bc"
      .parse::<Ipv6Addr>()
      .unwrap()
  );
}

async fn instance_addr_txt<R: Runtime>() {
  let s = make_service::<R>().await;

  let recs = s
    .records(
      &"hostname._http._tcp.local.".parse().unwrap(),
      RecordType::TXT,
    )
    .await
    .unwrap();
  assert_eq!(recs.len(), 1, "bad: {recs:?}");

  let txt = recs[0].data().cloned().unwrap().into_txt().expect("TXT");

  assert_eq!(&*txt.txt_data()[0], s.txt_records()[0].as_bytes());
}

async fn hostname_query<R: Runtime>() {
  let questions = [
    (
      ("testhost.".parse().unwrap(), RecordType::A),
      OneOrMore::from(Record::from_rdata(
        Name::from_str("testhost.").unwrap(),
        120,
        RData::A(A("192.168.0.42".parse().unwrap())),
      )),
    ),
    (
      ("testhost.".parse().unwrap(), RecordType::AAAA),
      OneOrMore::from(Record::from_rdata(
        Name::from_str("testhost.").unwrap(),
        120,
        RData::AAAA(AAAA(
          "2620:0:1000:1900:b0c2:d0b2:c411:18bc".parse().unwrap(),
        )),
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

async fn service_enum_ptr<R: Runtime>() {
  let s = make_service::<R>().await;

  let recs = s
    .records(
      &"_services._dns-sd._udp.local.".parse().unwrap(),
      RecordType::PTR,
    )
    .await
    .unwrap();
  assert_eq!(recs.len(), 1, "bad: {recs:?}");

  let ptr = recs[0].data().cloned().unwrap().into_ptr().unwrap();
  assert_eq!(ptr.0, Name::from_str("_http._tcp.local.").unwrap());
}

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
