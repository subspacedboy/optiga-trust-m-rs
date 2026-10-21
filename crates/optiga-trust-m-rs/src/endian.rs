//! Big-endian slice readers and writers for wire protocol codecs.

/// Reads a 16-bit unsigned integer in big-endian byte order from `buf`.
/// Returns `None` if `buf.len() < 2`.
#[inline]
pub const fn read_u16_be(buf: &[u8]) -> Option<u16> {
    if buf.len() < 2 {
        None
    } else {
        Some(u16::from_be_bytes([buf[0], buf[1]]))
    }
}

/// Reads a 24-bit unsigned integer in big-endian byte order from `buf` as a `u32`.
/// Returns `None` if `buf.len() < 3`.
#[inline]
pub const fn read_u24_be(buf: &[u8]) -> Option<u32> {
    if buf.len() < 3 {
        None
    } else {
        Some(u32::from_be_bytes([0x00, buf[0], buf[1], buf[2]]))
    }
}

/// Reads a 32-bit unsigned integer in big-endian byte order from `buf`.
/// Returns `None` if `buf.len() < 4`.
#[inline]
pub const fn read_u32_be(buf: &[u8]) -> Option<u32> {
    if buf.len() < 4 {
        None
    } else {
        Some(u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]))
    }
}

/// Writes a 16-bit unsigned integer in big-endian byte order into `buf`.
/// Returns `None` if `buf.len() < 2`.
#[inline]
pub fn write_u16_be(buf: &mut [u8], val: u16) -> Option<()> {
    if buf.len() < 2 {
        None
    } else {
        buf[..2].copy_from_slice(&val.to_be_bytes());
        Some(())
    }
}

/// Writes the lower 24 bits of a `u32` in big-endian byte order into `buf`.
/// Returns `None` if `buf.len() < 3`.
#[inline]
pub fn write_u24_be(buf: &mut [u8], val: u32) -> Option<()> {
    if buf.len() < 3 {
        None
    } else {
        let bytes = val.to_be_bytes();
        buf[0] = bytes[1];
        buf[1] = bytes[2];
        buf[2] = bytes[3];
        Some(())
    }
}

/// Writes a 32-bit unsigned integer in big-endian byte order into `buf`.
/// Returns `None` if `buf.len() < 4`.
#[inline]
pub fn write_u32_be(buf: &mut [u8], val: u32) -> Option<()> {
    if buf.len() < 4 {
        None
    } else {
        buf[..4].copy_from_slice(&val.to_be_bytes());
        Some(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_u16_be_roundtrip() {
        let mut buf = [0u8; 2];
        assert_eq!(read_u16_be(&buf), Some(0));
        assert!(write_u16_be(&mut buf, 0x1234).is_some());
        assert_eq!(buf, [0x12, 0x34]);
        assert_eq!(read_u16_be(&buf), Some(0x1234));

        let short_buf = [0u8; 1];
        assert_eq!(read_u16_be(&short_buf), None);
        let mut short_buf_mut = [0u8; 1];
        assert_eq!(write_u16_be(&mut short_buf_mut, 0x1234), None);
    }

    #[test]
    fn test_u24_be_roundtrip() {
        let mut buf = [0u8; 3];
        assert_eq!(read_u24_be(&buf), Some(0));
        assert!(write_u24_be(&mut buf, 0x123456).is_some());
        assert_eq!(buf, [0x12, 0x34, 0x56]);
        assert_eq!(read_u24_be(&buf), Some(0x123456));

        let short_buf = [0u8; 2];
        assert_eq!(read_u24_be(&short_buf), None);
        let mut short_buf_mut = [0u8; 2];
        assert_eq!(write_u24_be(&mut short_buf_mut, 0x123456), None);
    }

    #[test]
    fn test_u32_be_roundtrip() {
        let mut buf = [0u8; 4];
        assert_eq!(read_u32_be(&buf), Some(0));
        assert!(write_u32_be(&mut buf, 0xDEADBEEF).is_some());
        assert_eq!(buf, [0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(read_u32_be(&buf), Some(0xDEADBEEF));

        let short_buf = [0u8; 3];
        assert_eq!(read_u32_be(&short_buf), None);
        let mut short_buf_mut = [0u8; 3];
        assert_eq!(write_u32_be(&mut short_buf_mut, 0xDEADBEEF), None);
    }
}
