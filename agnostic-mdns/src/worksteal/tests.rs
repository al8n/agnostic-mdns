mod client;
mod server;
mod zone;

#[cfg(feature = "tokio")]
fn tokio_run<F>(f: F)
where
  F: Future<Output = ()>,
{
  use crate::tests::initialize_tests_tracing;

  initialize_tests_tracing();

  tokio::runtime::Builder::new_current_thread()
    .enable_all()
    .build()
    .unwrap()
    .block_on(f);
}

#[cfg(feature = "smol")]
fn smol_run<F>(f: F)
where
  F: Future<Output = ()>,
{
  use crate::tests::initialize_tests_tracing;

  initialize_tests_tracing();
  smol::block_on(f);
}

#[cfg(feature = "async-std")]
fn async_std_run<F>(f: F)
where
  F: Future<Output = ()>,
{
  use crate::tests::initialize_tests_tracing;
  initialize_tests_tracing();
  async_std::task::block_on(f);
}
