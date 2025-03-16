use core::num::NonZeroUsize;

pub use dns_protocol::{BufferType, Error as ProtoError};

#[inline]
pub(super) const fn not_enough_read_data(tried_to_read: usize, available: usize) -> ProtoError {
  ProtoError::NotEnoughReadBytes {
    tried_to_read: NonZeroUsize::new(tried_to_read).unwrap(),
    available,
  }
}

#[inline]
pub(super) const fn proto_error_parse(name: &'static str) -> ProtoError {
  ProtoError::Parse { name }
}
