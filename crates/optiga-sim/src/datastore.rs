//! In-memory datastore pre-loaded with OPTIGA test platform secrets.

use optiga_trust_m_rs::pal::{Datastore, DatastoreId};
use std::collections::HashMap;

/// Standard default platform binding shared secret (64 bytes: `0x01..=0x40`).
/// Matches `optiga_platform_binding_shared_secret` in `pal_os_datastore.c`.
pub const DEFAULT_PLATFORM_BINDING_SECRET: [u8; 64] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E,
    0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D,
    0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C,
    0x3D, 0x3E, 0x3F, 0x40,
];

/// In-memory implementation of `Datastore` for host simulation and tests.
#[derive(Debug, Clone)]
pub struct InMemoryDatastore {
    storage: HashMap<u16, Vec<u8>>,
}

impl Default for InMemoryDatastore {
    fn default() -> Self {
        let mut ds = Self {
            storage: HashMap::new(),
        };
        // Pre-populate platform binding shared secret
        ds.storage.insert(
            DatastoreId::PlatformBindingSharedSecret as u16,
            DEFAULT_PLATFORM_BINDING_SECRET.to_vec(),
        );
        ds
    }
}

impl InMemoryDatastore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn without_secrets() -> Self {
        Self {
            storage: HashMap::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatastoreError {
    NotFound,
    BufferTooSmall,
}

impl Datastore for InMemoryDatastore {
    type Error = DatastoreError;

    fn read(&self, id: DatastoreId, buf: &mut [u8]) -> Result<usize, Self::Error> {
        let key = id as u16;
        let data = self.storage.get(&key).ok_or(DatastoreError::NotFound)?;
        if buf.len() < data.len() {
            return Err(DatastoreError::BufferTooSmall);
        }
        buf[..data.len()].copy_from_slice(data);
        Ok(data.len())
    }

    fn write(&mut self, id: DatastoreId, data: &[u8]) -> Result<(), Self::Error> {
        let key = id as u16;
        self.storage.insert(key, data.to_vec());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_in_memory_datastore_default_secret() {
        let ds = InMemoryDatastore::new();
        let mut buf = [0u8; 64];
        let len = ds.read(DatastoreId::PlatformBindingSharedSecret, &mut buf).unwrap();
        assert_eq!(len, 64);
        assert_eq!(buf, DEFAULT_PLATFORM_BINDING_SECRET);

        let mut short_buf = [0u8; 32];
        assert_eq!(
            ds.read(DatastoreId::PlatformBindingSharedSecret, &mut short_buf),
            Err(DatastoreError::BufferTooSmall)
        );
    }

    #[test]
    fn test_in_memory_datastore_write_read() {
        let mut ds = InMemoryDatastore::new();
        let ctx = [0xAA, 0xBB, 0xCC, 0xDD];
        assert!(ds.write(DatastoreId::ManageContext, &ctx).is_ok());

        let mut buf = [0u8; 10];
        let len = ds.read(DatastoreId::ManageContext, &mut buf).unwrap();
        assert_eq!(len, 4);
        assert_eq!(&buf[..4], &ctx);
    }
}
