use core::fmt::{self, Write};

use super::{ProtoError, not_enough_read_data};

/// ```text
/// 3.3.14. TXT RDATA format
///
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///     /                   TXT-DATA                    /
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///
/// where:
///
/// TXT-DATA        One or more <character-string>s.
///
/// TXT RRs are used to hold descriptive text.  The semantics of the text
/// depends on the domain where it is found.
/// ```
#[derive(Debug, Default, Clone, Copy)]
pub struct Txt<'container, 'innards> {
  repr: Repr<'container, 'innards>,
}

#[derive(Debug, Clone, Copy)]
enum Repr<'container, 'innards> {
  BytesStrings {
    /// The original buffer, in totality, that this TXT was parsed from.
    original: &'innards [u8],

    /// The starting position of this TXT in the original buffer.
    start: usize,

    /// The ending position of this TXT in the original buffer.
    end: usize,
  },
  Strings(&'container [&'innards str]),
}

impl Default for Repr<'_, '_> {
  fn default() -> Self {
    Self::Strings(&[])
  }
}

impl<'container, 'innards> Txt<'container, 'innards> {
  /// Creates a new Txt record from a slice of string references
  #[inline]
  pub const fn from_strings(strings: &'container [&'innards str]) -> Self {
    Self {
      repr: Repr::Strings(strings),
    }
  }

  /// Creates a new Txt record from a byte slice with start and end positions
  #[inline]
  pub(super) const fn from_bytes(original: &'innards [u8], start: usize, end: usize) -> Self {
    Self {
      repr: Repr::BytesStrings {
        original,
        start,
        end,
      },
    }
  }

  /// Returns an iterator over the strings in this TXT record
  #[inline]
  pub const fn strings(&self) -> Strings<'container, 'innards> {
    let repr = match &self.repr {
      Repr::BytesStrings {
        original,
        start,
        end,
      } => StringsRepr::Bytes {
        original,
        position: *start,
        end: *end,
      },
      Repr::Strings(strings) => StringsRepr::Strings {
        strings,
        position: 0,
      },
    };

    Strings { repr }
  }
}

/// A TXT string segment that refers to either raw bytes or a pre-parsed string
#[derive(Clone, Copy, Debug)]
pub struct Str<'a> {
  repr: StrRepr<'a>,
}

impl fmt::Display for Str<'_> {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match &self.repr {
      StrRepr::Bytes {
        original,
        start,
        length,
      } => {
        let bytes = &original[*start..*start + *length];
        // Properly handle special characters
        for &byte in bytes {
          match byte {
            b'"' | b'\\' => {
              f.write_str("\\")?;
              f.write_char(byte as char)?;
            }
            b if (b' '..=b'~').contains(&b) => {
              f.write_char(b as char)?;
            }
            b => {
              f.write_str(
                simdutf8::basic::from_utf8(escape_bytes(b).as_slice())
                  .expect("escape bytes must be valid utf8"),
              )?;
            }
          }
        }
        Ok(())
      }
      StrRepr::String(s) => write!(f, "{}", s),
    }
  }
}

/// Internal representation of a TXT string segment
#[derive(Clone, Copy, Debug)]
enum StrRepr<'a> {
  /// The segment is represented by its range of bytes in the buffer
  Bytes {
    /// The original buffer this segment was parsed from
    original: &'a [u8],
    /// Starting position (after the length byte)
    start: usize,
    /// Length of the string
    length: usize,
  },
  /// The segment is a pre-parsed string
  String(&'a str),
}

impl<'a> Str<'a> {
  /// Create a new segment from a buffer with specific range
  fn from_bytes(original: &'a [u8], start: usize, length: usize) -> Self {
    Self {
      repr: StrRepr::Bytes {
        original,
        start,
        length,
      },
    }
  }

  /// Get the raw bytes of this segment
  pub fn as_bytes(&self) -> &'a [u8] {
    match self.repr {
      StrRepr::Bytes {
        original,
        start,
        length,
      } => &original[start..start + length],
      StrRepr::String(s) => s.as_bytes(),
    }
  }

  /// Create a new segment from a pre-parsed string
  #[inline]
  pub const fn new(s: &'a str) -> Self {
    Self {
      repr: StrRepr::String(s),
    }
  }
}

/// Iterator over strings in a TXT record
enum StringsRepr<'container, 'innards> {
  Bytes {
    original: &'innards [u8],
    position: usize,
    end: usize,
  },
  Strings {
    strings: &'container [&'innards str],
    position: usize,
  },
}

/// Iterator over strings in a TXT record
pub struct Strings<'container, 'innards> {
  repr: StringsRepr<'container, 'innards>,
}

impl<'innards> Iterator for Strings<'_, 'innards> {
  type Item = Result<Str<'innards>, ProtoError>;

  fn next(&mut self) -> Option<Self::Item> {
    match &mut self.repr {
      StringsRepr::Bytes {
        original,
        position,
        end,
      } => {
        if *position >= *end {
          return None;
        }

        let result = decode_txt_segment(original, *position, *end);
        match result {
          Ok((segment, new_position)) => {
            *position = new_position;
            Some(Ok(segment))
          }
          Err(e) => {
            // Advance to end on error to stop iteration
            *position = *end;
            Some(Err(e))
          }
        }
      }
      StringsRepr::Strings { strings, position } => {
        if *position >= strings.len() {
          return None;
        }

        let string = strings[*position];
        *position += 1;
        Some(Ok(Str::new(string)))
      }
    }
  }
}

/// Decodes a single TXT segment from a byte slice without UTF-8 validation
fn decode_txt_segment(
  msg: &[u8],
  mut offset: usize,
  end: usize,
) -> Result<(Str<'_>, usize), ProtoError> {
  if offset + 1 > msg.len() || offset >= end {
    return Err(not_enough_read_data(1, 0));
  }

  let length = msg[offset] as usize;
  offset += 1;
  let content_start = offset;
  let content_end = content_start + length;

  if content_end > msg.len() {
    return Err(not_enough_read_data(length, content_end - msg.len()));
  }

  if content_end > end {
    return Err(not_enough_read_data(length, content_end - end));
  }

  let mut consumed = 0;
  for (i, &b) in msg[offset..offset + length].iter().enumerate() {
    match () {
      () if (b == b'"' || b == b'\\') || !(b' '..=b'~').contains(&b) => {
        consumed = i + 1;
      }
      _ => {}
    }
  }

  if consumed == 0 {
    // no escaping needed
    return simdutf8::compat::from_utf8(&msg[offset..offset + length])
      .map(|s| (Str::new(s), offset + length))
      .map_err(Into::into);
  }

  let segment = Str::from_bytes(msg, content_start, length);
  Ok((segment, content_end))
}

/// Decode a TXT record from a byte slice, returning the record and the new offset
pub fn decode_txt<'a>(msg: &[u8], offset: usize) -> Result<(Txt<'a, '_>, usize), ProtoError> {
  if offset >= msg.len() {
    return Err(not_enough_read_data(1, 0));
  }

  // Find the end by parsing through all the strings
  let mut position = offset;
  while position < msg.len() {
    if position + 1 > msg.len() {
      break;
    }

    let length = msg[position] as usize;
    let next_position = position + 1 + length;

    if next_position > msg.len() {
      break;
    }

    position = next_position;
  }

  let txt = Txt::from_bytes(msg, offset, position);
  Ok((txt, position))
}

// Escape byte without allocation using a fixed buffer
#[inline]
const fn escape_bytes(b: u8) -> [u8; 4] {
  let mut buf = [0; 4];
  buf[0] = b'\\';
  buf[1] = b'0' + (b / 100);
  buf[2] = b'0' + ((b / 10) % 10);
  buf[3] = b'0' + (b % 10);
  buf
}
