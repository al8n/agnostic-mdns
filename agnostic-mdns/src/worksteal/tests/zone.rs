use core::{
  net::{Ipv4Addr, Ipv6Addr},
  panic,
};

use mdns_proto::{
  Txt,
  proto::{Cursor, Deserialize, Label, ResourceType},
};

use crate::{tests::make_service, worksteal::Zone};

macro_rules! test_suites {
  ($runtime:ident {
    $($name:ident),+$(,)?
  }) => {
    $(
      paste::paste! {
        #[test]
        fn [< $runtime _ $name >]() {
          $crate::worksteal::tests::[< $runtime _run >]($name());
        }
      }
    )*
  }
}

async fn bad_addr() {
  let s = make_service();

  let recs = s
    .answers("random".into(), ResourceType::Wildcard)
    .await
    .unwrap()
    .collect::<Vec<_>>();
  assert!(recs.is_empty(), "bad: {recs:?}");
}

async fn service_addr() {
  let s = make_service();

  let recs = s
    .answers("_http._tcp.local.".into(), ResourceType::Wildcard)
    .await
    .unwrap()
    .collect::<Vec<_>>();
  assert_eq!(recs.len(), 5, "bad: {recs:?}");

  let ResourceType::Ptr = recs[0].ty() else {
    panic!("bad: {recs:?}")
  };

  let mut label = Label::default();
  label.deserialize(Cursor::new(recs[0].data())).unwrap();
  assert_eq!(label, "hostname._http._tcp.local.".into());

  matches!(recs[1].ty(), ResourceType::Srv);
  matches!(recs[2].ty(), ResourceType::A);
  matches!(recs[3].ty(), ResourceType::AAAA);
  matches!(recs[4].ty(), ResourceType::Txt);
}

async fn instance_addr_any() {
  let s = make_service();

  let recs = s
    .answers("hostname._http._tcp.local.".into(), ResourceType::Wildcard)
    .await
    .unwrap()
    .collect::<Vec<_>>();
  assert_eq!(recs.len(), 4, "bad: {recs:?}");

  matches!(recs[0].ty(), ResourceType::Srv);
  matches!(recs[1].ty(), ResourceType::A);
  matches!(recs[2].ty(), ResourceType::AAAA);
  matches!(recs[3].ty(), ResourceType::Txt);
}

async fn instance_addr_srv() {
  let s = make_service();

  let recs = s
    .answers("hostname._http._tcp.local.".into(), ResourceType::Srv)
    .await
    .unwrap()
    .collect::<Vec<_>>();
  assert_eq!(recs.len(), 3, "bad: {recs:?}");

  let ResourceType::Srv = recs[0].ty() else {
    panic!("bad: {recs:?}")
  };

  matches!(recs[1].ty(), ResourceType::A);
  matches!(recs[2].ty(), ResourceType::AAAA);

  assert_eq!(&recs[0].data()[4..6], s.port().to_be_bytes());
}

async fn instance_addr_a() {
  let s = make_service();

  let recs = s
    .answers("hostname._http._tcp.local.".into(), ResourceType::A)
    .await
    .unwrap()
    .collect::<Vec<_>>();
  assert_eq!(recs.len(), 1, "bad: {recs:?}");

  let ResourceType::A = recs[0].ty() else {
    panic!("bad: {recs:?}")
  };

  assert_eq!(
    recs[0].data(),
    "192.168.0.42".parse::<Ipv4Addr>().unwrap().octets()
  );
}

async fn instance_addr_aaaa() {
  let s = make_service();

  let recs = s
    .answers("hostname._http._tcp.local.".into(), ResourceType::AAAA)
    .await
    .unwrap()
    .collect::<Vec<_>>();
  assert_eq!(recs.len(), 1, "bad: {recs:?}");

  let ResourceType::AAAA = recs[0].ty() else {
    panic!("bad: {recs:?}")
  };

  assert_eq!(
    recs[0].data(),
    "2620:0:1000:1900:b0c2:d0b2:c411:18bc"
      .parse::<Ipv6Addr>()
      .unwrap()
      .octets()
  );
}

async fn instance_addr_txt() {
  let s = make_service();

  let recs = s
    .answers("hostname._http._tcp.local.".into(), ResourceType::Txt)
    .await
    .unwrap()
    .collect::<Vec<_>>();
  assert_eq!(recs.len(), 1, "bad: {recs:?}");

  let ResourceType::Txt = recs[0].ty() else {
    panic!("bad: {recs:?}")
  };

  let txt = Txt::from_bytes(recs[0].data());

  assert_eq!(
    txt.strings().next().unwrap().unwrap().to_string(),
    s.txt_records()[0].as_str()
  );
}

async fn service_enum_ptr() {
  let s = make_service();

  let recs = s
    .answers("_services._dns-sd._udp.local.".into(), ResourceType::Ptr)
    .await
    .unwrap()
    .collect::<Vec<_>>();
  assert_eq!(recs.len(), 1, "bad: {recs:?}");

  let ResourceType::Ptr = recs[0].ty() else {
    panic!("bad: {recs:?}")
  };
  let mut label = Label::default();
  label.deserialize(Cursor::new(recs[0].data())).unwrap();
  assert_eq!(label, Label::from("_http._tcp.local."));
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
