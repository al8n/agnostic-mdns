use smol_str::{format_smolstr, SmolStr};

use super::{escape_byte, ProtoError, MAX_COMPRESSION_POINTERS, MAX_DOMAIN_NAME_WIRE_OCTETS};

pub(crate) struct Name;

impl Name {
  /// Appends a name to the current name
  pub(crate) fn append(this: &str, other: &str) -> SmolStr {
    format_smolstr!("{}{}", this, other)
  }

  /// Appends a name to the current name in FQDN format.
  pub(crate) fn append_fqdn(this: &str, other: &str) -> SmolStr {
    format_smolstr!("{}.{}.", this.trim_matches('.'), other.trim_matches('.'))
  }

  #[inline]
  pub(crate) fn local() -> SmolStr {
    SmolStr::new("local")
  }

  #[inline]
  pub(crate) fn local_fqdn() -> SmolStr {
    SmolStr::new("local.")
  }

  pub(super) fn decode(msg: &[u8], mut off: usize) -> Result<(SmolStr, usize), ProtoError> {
    // Start with a smaller capacity and let it grow as needed
    let mut s = InlineDomain::with_capacity(23); // Most domain names are shorter than 32 bytes
    let mut off1 = 0;
    let lenmsg = msg.len();
    let mut budget = MAX_DOMAIN_NAME_WIRE_OCTETS as isize;
    let mut ptr = 0; // number of pointers followed

    loop {
      if off >= lenmsg {
        return Err(ProtoError::BufferTooSmall);
      }

      let c = msg[off];
      off += 1;

      match c & 0xC0 {
        0x00 => {
          if c == 0x00 {
            // end of name
            break;
          }

          // literal string
          let label_len = c as usize;
          if off + label_len > lenmsg {
            return Err(ProtoError::BufferTooSmall);
          }

          budget -= (label_len as isize) + 1; // +1 for the label separator
          if budget <= 0 {
            return Err(ProtoError::NameTooLong);
          }

          for &b in msg[off..off + label_len].iter() {
            if is_domain_name_label_special(b) {
              s.extend_from_slice(&[b'\\', b]);
            } else if !(b' '..=b'~').contains(&b) {
              s.extend_from_slice(&escape_byte(b));
            } else {
              s.push(b);
            }
          }
          s.push(b'.');
          off += label_len;
        }
        0xC0 => {
          // pointer to somewhere else in msg.
          // remember location after first ptr,
          // since that's how many bytes we consumed.
          // also, don't follow too many pointers --
          // maybe there's a loop.
          if off >= lenmsg {
            return Err(ProtoError::NotEnoughData);
          }

          let c1 = msg[off];
          off += 1;

          if ptr == 0 {
            off1 = off;
          }

          ptr += 1;
          if ptr > MAX_COMPRESSION_POINTERS {
            return Err(ProtoError::TooManyPointers);
          }

          // pointer should guarantee that it advances and points forwards at least
          // but the condition on previous three lines guarantees that it's
          // at least loop-free
          off = ((c as usize ^ 0xC0) << 8) | c1 as usize;
        }
        _ => return Err(ProtoError::InvalidRdata),
      }
    }

    if ptr == 0 {
      off1 = off;
    }

    if s.is_empty() {
      Ok((SmolStr::from("."), off1))
    } else {
      // SAFETY: We only added ASCII bytes and properly escaped non-ASCII
      let s = core::str::from_utf8(s.as_slice()).expect("we only added ASCII bytes");
      Ok((SmolStr::new(s), off1))
    }
  }

  pub(super) fn skip_decode(msg: &[u8], mut off: usize) -> Result<usize, ProtoError> {
    // Start with a smaller capacity and let it grow as needed
    let mut off1 = 0;
    let lenmsg = msg.len();
    let mut budget = MAX_DOMAIN_NAME_WIRE_OCTETS as isize;
    let mut ptr = 0; // number of pointers followed

    loop {
      if off >= lenmsg {
        return Err(ProtoError::BufferTooSmall);
      }

      let c = msg[off];
      off += 1;

      match c & 0xC0 {
        0x00 => {
          if c == 0x00 {
            // end of name
            break;
          }

          // literal string
          let label_len = c as usize;
          if off + label_len > lenmsg {
            return Err(ProtoError::BufferTooSmall);
          }

          budget -= (label_len as isize) + 1; // +1 for the label separator
          if budget <= 0 {
            return Err(ProtoError::NameTooLong);
          }

          off += label_len;
        }
        0xC0 => {
          // pointer to somewhere else in msg.
          // remember location after first ptr,
          // since that's how many bytes we consumed.
          // also, don't follow too many pointers --
          // maybe there's a loop.
          if off >= lenmsg {
            return Err(ProtoError::NotEnoughData);
          }

          let c1 = msg[off];
          off += 1;

          if ptr == 0 {
            off1 = off;
          }

          ptr += 1;
          if ptr > MAX_COMPRESSION_POINTERS {
            return Err(ProtoError::TooManyPointers);
          }

          // pointer should guarantee that it advances and points forwards at least
          // but the condition on previous three lines guarantees that it's
          // at least loop-free
          off = ((c as usize ^ 0xC0) << 8) | c1 as usize;
        }
        _ => return Err(ProtoError::InvalidRdata),
      }
    }

    if ptr == 0 {
      off1 = off;
    }

    Ok(off1)
  }
}

// Returns true if
// a domain name label byte should be prefixed
// with an escaping backslash.
#[inline]
const fn is_domain_name_label_special(b: u8) -> bool {
  matches!(
    b,
    b'.' | b' ' | b'\'' | b'@' | b';' | b'(' | b')' | b'"' | b'\\'
  )
}

smallvec_wrapper::smallvec_wrapper!(
  InlineDomain<T>([T; 23]);
);

#[cfg(test)]
mod tests {
  use super::*;

  const MAX_PRINTABLE_LABEL: &str =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789x";

  #[test]
  fn empty_domain() {
    let input = [0];
    let (name, _) = Name::decode(&input, 0).unwrap();
    assert_eq!(name.as_str(), ".");
  }

  #[test]
  fn long_label() {
    let s = [b"?".as_slice(), MAX_PRINTABLE_LABEL.as_bytes(), b"\x00"].concat();
    let exp = [MAX_PRINTABLE_LABEL, "."].concat();
    let (name, _) = Name::decode(&s, 0).unwrap();
    assert_eq!(name.as_str(), exp);
  }

  #[test]
  fn unpritable_lable() {
    let s = [
      63, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
      25, 26, 27, 28, 29, 30, 31, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
      19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 0,
    ];
    let exp = [
      92u8, 48, 48, 48, 92, 48, 48, 49, 92, 48, 48, 50, 92, 48, 48, 51, 92, 48, 48, 52, 92, 48, 48,
      53, 92, 48, 48, 54, 92, 48, 48, 55, 92, 48, 48, 56, 92, 48, 48, 57, 92, 48, 49, 48, 92, 48,
      49, 49, 92, 48, 49, 50, 92, 48, 49, 51, 92, 48, 49, 52, 92, 48, 49, 53, 92, 48, 49, 54, 92,
      48, 49, 55, 92, 48, 49, 56, 92, 48, 49, 57, 92, 48, 50, 48, 92, 48, 50, 49, 92, 48, 50, 50,
      92, 48, 50, 51, 92, 48, 50, 52, 92, 48, 50, 53, 92, 48, 50, 54, 92, 48, 50, 55, 92, 48, 50,
      56, 92, 48, 50, 57, 92, 48, 51, 48, 92, 48, 51, 49, 92, 48, 48, 48, 92, 48, 48, 49, 92, 48,
      48, 50, 92, 48, 48, 51, 92, 48, 48, 52, 92, 48, 48, 53, 92, 48, 48, 54, 92, 48, 48, 55, 92,
      48, 48, 56, 92, 48, 48, 57, 92, 48, 49, 48, 92, 48, 49, 49, 92, 48, 49, 50, 92, 48, 49, 51,
      92, 48, 49, 52, 92, 48, 49, 53, 92, 48, 49, 54, 92, 48, 49, 55, 92, 48, 49, 56, 92, 48, 49,
      57, 92, 48, 50, 48, 92, 48, 50, 49, 92, 48, 50, 50, 92, 48, 50, 51, 92, 48, 50, 52, 92, 48,
      50, 53, 92, 48, 50, 54, 92, 48, 50, 55, 92, 48, 50, 56, 92, 48, 50, 57, 92, 48, 51, 48, 46,
    ];

    let (name, _) = Name::decode(&s, 0).unwrap();
    assert_eq!(name.as_str(), core::str::from_utf8(&exp).unwrap());
  }

  #[test]
  fn long_domain() {
    let input = b"5abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVW1abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVW1abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVW1abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVW\x00";

    let exp = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0.abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVW.abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVW.abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVW.abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVW.";

    let name = Name::decode(input, 0).unwrap().0;
    assert_eq!(name.as_str(), exp);
  }

  #[test]
  fn compression_pointer() {
    let input = [
      3, b'f', b'o', b'o', 5, 3, b'c', b'o', b'm', 0, 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
      0xC0, 5,
    ];

    let exp = "foo.\\003com\\000.example.com.";
    let (name, _) = Name::decode(&input, 0).unwrap();
    assert_eq!(name.as_str(), exp);
  }

  #[test]
  fn too_long_domain() {
    let input = b"6xabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVW1abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVW1abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVW1abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVW";

    let name = Name::decode(input, 0).unwrap_err();
    assert_eq!(name, ProtoError::NameTooLong);
  }

  #[test]
  fn too_long_pointer() {
    let input = [
      // 11 length values, first to last
      40, 37, 34, 31, 28, 25, 22, 19, 16, 13, 0, // 12 filler values
      120, 120, 120, 120, 120, 120, 120, 120, 120, 120, 120, 120,
      // 10 pointers, last to first
      192, 10, 192, 9, 192, 8, 192, 7, 192, 6, 192, 5, 192, 4, 192, 3, 192, 2, 192, 1,
    ];

    let err = Name::decode(&input, 0).unwrap_err();
    assert_eq!(err, ProtoError::NameTooLong);
  }

  #[test]
  fn long_by_pointer() {
    let input = [
      // 11 length values, first to last
      37, 34, 31, 28, 25, 22, 19, 16, 13, 10, 0, // 9 filler values
      120, 120, 120, 120, 120, 120, 120, 120, 120, // 10 pointers, last to first
      192, 10, 192, 9, 192, 8, 192, 7, 192, 6, 192, 5, 192, 4, 192, 3, 192, 2, 192, 1,
    ];
    let output = concat!(
      "\\\"\\031\\028\\025\\022\\019\\016\\013\\010\\000xxxxxxxxx",
      "\\192\\010\\192\\009\\192\\008\\192\\007\\192\\006\\192\\005\\192\\004\\192\\003\\192\\002.",
      "\\031\\028\\025\\022\\019\\016\\013\\010\\000xxxxxxxxx",
      "\\192\\010\\192\\009\\192\\008\\192\\007\\192\\006\\192\\005\\192\\004\\192\\003.",
      "\\028\\025\\022\\019\\016\\013\\010\\000xxxxxxxxx",
      "\\192\\010\\192\\009\\192\\008\\192\\007\\192\\006\\192\\005\\192\\004.",
      "\\025\\022\\019\\016\\013\\010\\000xxxxxxxxx",
      "\\192\\010\\192\\009\\192\\008\\192\\007\\192\\006\\192\\005.",
      "\\022\\019\\016\\013\\010\\000xxxxxxxxx\\192\\010\\192\\009\\192\\008\\192\\007\\192\\006.",
      "\\019\\016\\013\\010\\000xxxxxxxxx\\192\\010\\192\\009\\192\\008\\192\\007.",
      "\\016\\013\\010\\000xxxxxxxxx\\192\\010\\192\\009\\192\\008.",
      "\\013\\010\\000xxxxxxxxx\\192\\010\\192\\009.",
      "\\010\\000xxxxxxxxx\\192\\010.",
      "\\000xxxxxxxxx."
    );

    let (name, _) = Name::decode(&input, 0).unwrap();
    assert_eq!(name.as_str(), output);
  }

  #[test]
  fn truncated_name() {
    let input = [7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3];
    let err = Name::decode(&input, 0).unwrap_err();
    assert_eq!(err, ProtoError::BufferTooSmall);
  }

  #[test]
  fn non_absolute_name() {
    let input = [
      7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm',
    ];
    let err = Name::decode(&input, 0).unwrap_err();
    assert_eq!(err, ProtoError::BufferTooSmall);
  }

  #[test]
  fn compression_pointer_cycle_too_many() {
    let input = [0xC0, 0x00];
    let err = Name::decode(&input, 0).unwrap_err();
    assert_eq!(err, ProtoError::TooManyPointers);
  }

  #[test]
  fn compression_pointer_cycle_too_long() {
    let input = [
      3, b'f', b'o', b'o', 3, b'b', b'a', b'r', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0xC0,
      0x04,
    ];
    let err = Name::decode(&input, 0).unwrap_err();
    assert_eq!(err, ProtoError::NameTooLong);
  }

  #[test]
  fn forward_pointer() {
    let input = [2, 0xC0, 0xFF, 0xC0, 0x01];
    let err = Name::decode(&input, 0).unwrap_err();
    assert_eq!(err, ProtoError::BufferTooSmall);
  }

  #[test]
  fn reserved_compression_pointer_0b10() {
    let input = [7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x80];
    let err = Name::decode(&input, 0).unwrap_err();
    assert_eq!(err, ProtoError::InvalidRdata);
  }

  #[test]
  fn reserved_compression_pointer_0b01() {
    let input = [7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x40];
    let err = Name::decode(&input, 0).unwrap_err();
    assert_eq!(err, ProtoError::InvalidRdata);
  }
}
