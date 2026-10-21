//! Zero-copy 3-byte Tag-Length-Value (TLV) codec for OPTIGA command parameters.

use crate::error::OptigaError;

/// Streaming builder for 3-byte Tag-Length-Value records.
pub struct TlvWriter<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> TlvWriter<'a> {
    /// Creates a new `TlvWriter` writing into `buf`.
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Appends a TLV item: 1-byte `tag`, 2-byte big-endian `length`, followed by `value`.
    pub fn write_tlv(&mut self, tag: u8, value: &[u8]) -> Result<(), OptigaError> {
        let len = u16::try_from(value.len()).map_err(|_| OptigaError::InvalidInput)?;
        if self.pos + 3 + value.len() > self.buf.len() {
            return Err(OptigaError::MemoryInsufficient);
        }

        self.buf[self.pos] = tag;
        let len_be = len.to_be_bytes();
        self.buf[self.pos + 1] = len_be[0];
        self.buf[self.pos + 2] = len_be[1];
        self.buf[self.pos + 3..self.pos + 3 + value.len()].copy_from_slice(value);
        self.pos += 3 + value.len();
        Ok(())
    }

    /// Appends a TLV item whose value is the concatenation of `part1` and `part2`.
    pub fn write_tlv_concat(
        &mut self,
        tag: u8,
        part1: &[u8],
        part2: &[u8],
    ) -> Result<(), OptigaError> {
        let total_len = part1.len() + part2.len();
        let len = u16::try_from(total_len).map_err(|_| OptigaError::InvalidInput)?;
        if self.pos + 3 + total_len > self.buf.len() {
            return Err(OptigaError::MemoryInsufficient);
        }

        self.buf[self.pos] = tag;
        let len_be = len.to_be_bytes();
        self.buf[self.pos + 1] = len_be[0];
        self.buf[self.pos + 2] = len_be[1];
        let start1 = self.pos + 3;
        let start2 = start1 + part1.len();
        self.buf[start1..start2].copy_from_slice(part1);
        self.buf[start2..start2 + part2.len()].copy_from_slice(part2);
        self.pos += 3 + total_len;
        Ok(())
    }

    /// Returns the written slice.
    pub fn finish(self) -> &'a [u8] {
        &self.buf[..self.pos]
    }

    /// Returns the current length of written bytes.
    #[inline]
    pub fn len(&self) -> usize {
        self.pos
    }

    /// Checks if no TLV items have been written.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.pos == 0
    }
}

/// Zero-copy parser for 3-byte Tag-Length-Value records.
pub struct TlvReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> TlvReader<'a> {
    /// Creates a new `TlvReader` borrowing `buf`.
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Searches for the first occurrence of `tag` and returns its value slice.
    pub fn find_tag(&mut self, tag: u8) -> Option<&'a [u8]> {
        self.pos = 0;
        for (t, val) in self.by_ref() {
            if t == tag {
                return Some(val);
            }
        }
        None
    }
}

impl<'a> Iterator for TlvReader<'a> {
    type Item = (u8, &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos + 3 > self.buf.len() {
            return None;
        }

        let tag = self.buf[self.pos];
        let len = u16::from_be_bytes([self.buf[self.pos + 1], self.buf[self.pos + 2]]) as usize;
        let val_start = self.pos + 3;
        let val_end = val_start + len;

        if val_end > self.buf.len() {
            return None;
        }

        self.pos = val_end;
        Some((tag, &self.buf[val_start..val_end]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tlv_roundtrip() {
        let mut buf = [0u8; 64];
        let mut writer = TlvWriter::new(&mut buf);

        writer.write_tlv(0x01, &[0xAA, 0xBB]).unwrap();
        writer.write_tlv(0x02, &[0x11, 0x22, 0x33, 0x44]).unwrap();
        let written = writer.finish();

        assert_eq!(written.len(), (3 + 2) + (3 + 4));

        let mut reader = TlvReader::new(written);
        let first = reader.next().unwrap();
        assert_eq!(first.0, 0x01);
        assert_eq!(first.1, &[0xAA, 0xBB]);

        let second = reader.next().unwrap();
        assert_eq!(second.0, 0x02);
        assert_eq!(second.1, &[0x11, 0x22, 0x33, 0x44]);

        assert_eq!(reader.next(), None);

        // find_tag test
        let mut reader2 = TlvReader::new(written);
        assert_eq!(reader2.find_tag(0x02), Some(&[0x11, 0x22, 0x33, 0x44][..]));
        assert_eq!(reader2.find_tag(0x05), None);
    }
}
