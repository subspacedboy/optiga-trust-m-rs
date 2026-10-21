//! High-level Utility service API (`OptigaUtil`).
//!
//! Provides ergonomic methods for reading/writing data objects, metadata,
//! monotonic counters, and managing application lifecycle (open/close/hibernate).

use crate::cmd::opcodes;
use crate::cmd::types::Oid;
use crate::cmd::OptigaCmd;
use crate::error::OptigaError;
use crate::ifx_i2c::headers::ProtectionConfig;
use crate::pal::{Datastore, DatastoreId, HostCrypto, MonotonicClock, OptigaI2cBus};
use embedded_hal::delay::DelayNs;
use embedded_hal::digital::OutputPin;

/// High-level utility service for OPTIGA data objects, counters, and application lifecycle.
pub struct OptigaUtil<'a, I2C, D, VDD, RST, CLK, CRYPTO, DS> {
    pub cmd: &'a mut OptigaCmd<I2C, D, VDD, RST, CLK, CRYPTO, DS>,
    pub protection: ProtectionConfig,
}

impl<'a, I2C, D, VDD, RST, CLK, CRYPTO, DS> OptigaUtil<'a, I2C, D, VDD, RST, CLK, CRYPTO, DS>
where
    I2C: OptigaI2cBus,
    D: DelayNs,
    VDD: OutputPin,
    RST: OutputPin,
    CLK: MonotonicClock,
    CRYPTO: HostCrypto,
    DS: Datastore,
{
    /// Creates a new `OptigaUtil` handle borrowing `cmd`.
    pub fn new(cmd: &'a mut OptigaCmd<I2C, D, VDD, RST, CLK, CRYPTO, DS>) -> Self {
        Self {
            cmd,
            protection: ProtectionConfig::default(),
        }
    }

    /// Sets the default protection configuration for utility operations.
    pub fn set_protection(&mut self, protection: ProtectionConfig) {
        self.protection = protection;
    }

    /// Opens the OPTIGA application context.
    pub fn open_application(&mut self, restore_from_hibernate: bool) -> Result<(), OptigaError> {
        let param = if restore_from_hibernate { 0x01 } else { 0x00 };
        let mut out = [0u8; 16];
        self.cmd
            .execute(opcodes::OPEN_APPLICATION, param, &[], &mut out, self.protection)?;
        Ok(())
    }

    /// Closes the OPTIGA application context. If `hibernate` is true, persists the 8-byte context handle.
    pub fn close_application(&mut self, hibernate: bool) -> Result<(), OptigaError> {
        let param = if hibernate { 0x01 } else { 0x00 };
        let mut out = [0u8; 16];
        let len = self
            .cmd
            .execute(opcodes::CLOSE_APPLICATION, param, &[], &mut out, self.protection)?;

        if hibernate && len >= 8 {
            self.cmd
                .stack
                .prl
                .datastore
                .write(DatastoreId::HibernateContext, &out[..8])
                .map_err(|_| OptigaError::DatastoreError)?;
        }
        Ok(())
    }

    /// Reads data from a data object starting at `offset`.
    pub fn read_data(&mut self, oid: Oid, offset: u16, out_buf: &mut [u8]) -> Result<usize, OptigaError> {
        let read_len = u16::try_from(out_buf.len()).map_err(|_| OptigaError::InvalidInput)?;
        let oid_be = oid.as_u16().to_be_bytes();
        let off_be = offset.to_be_bytes();
        let len_be = read_len.to_be_bytes();

        let in_data = [
            oid_be[0], oid_be[1],
            off_be[0], off_be[1],
            len_be[0], len_be[1],
        ];

        self.cmd.execute(opcodes::GET_DATA_OBJECT, 0x00, &in_data, out_buf, self.protection)
    }

    /// Writes data to a data object starting at `offset`.
    pub fn write_data(&mut self, oid: Oid, offset: u16, data: &[u8], erase_and_write: bool) -> Result<(), OptigaError> {
        let oid_be = oid.as_u16().to_be_bytes();
        let off_be = offset.to_be_bytes();

        let mut in_data = [0u8; 1553];
        if 4 + data.len() > in_data.len() {
            return Err(OptigaError::MemoryInsufficient);
        }

        in_data[0] = oid_be[0];
        in_data[1] = oid_be[1];
        in_data[2] = off_be[0];
        in_data[3] = off_be[1];
        in_data[4..4 + data.len()].copy_from_slice(data);

        let param = if erase_and_write { 0x40 } else { 0x00 };
        let mut out = [0u8; 4];
        self.cmd.execute(opcodes::SET_DATA_OBJECT, param, &in_data[..4 + data.len()], &mut out, self.protection)?;
        Ok(())
    }

    /// Reads metadata from a data object or key OID.
    pub fn read_metadata(&mut self, oid: Oid, out_buf: &mut [u8]) -> Result<usize, OptigaError> {
        let read_len = u16::try_from(out_buf.len()).map_err(|_| OptigaError::InvalidInput)?;
        let oid_be = oid.as_u16().to_be_bytes();
        let len_be = read_len.to_be_bytes();

        let in_data = [
            oid_be[0], oid_be[1],
            0x00, 0x00,
            len_be[0], len_be[1],
        ];

        self.cmd.execute(opcodes::GET_DATA_OBJECT, 0x01, &in_data, out_buf, self.protection)
    }

    /// Reads a 32-bit monotonic counter value.
    pub fn read_monotonic_counter(&mut self, counter_oid: Oid) -> Result<u32, OptigaError> {
        let mut buf = [0u8; 4];
        let len = self.read_data(counter_oid, 0, &mut buf)?;
        if len < 4 {
            return Err(OptigaError::CommandError);
        }
        Ok(u32::from_be_bytes(buf))
    }

    /// Increments a monotonic counter by `count` (typically 1).
    pub fn increment_monotonic_counter(&mut self, counter_oid: Oid, count: u8) -> Result<(), OptigaError> {
        let oid_be = counter_oid.as_u16().to_be_bytes();
        let in_data = [oid_be[0], oid_be[1], count];
        let mut out = [0u8; 4];
        self.cmd.execute(opcodes::SET_DATA_OBJECT, 0x02, &in_data, &mut out, self.protection)?;
        Ok(())
    }
}
