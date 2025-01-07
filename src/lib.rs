//! A template for creating Rust open-source repo on GitHub
#![cfg_attr(not(any(feature = "std", test)), no_std)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(docsrs, allow(unused_attributes))]
#![deny(missing_docs)]

#[cfg(all(not(feature = "std"), feature = "alloc"))]
extern crate alloc as std;

#[cfg(all(feature = "std", not(feature = "alloc")))]
extern crate std;

/// template
pub fn it_works() -> usize {
  4
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_works() {
    assert_eq!(it_works(), 4);
  }
}
