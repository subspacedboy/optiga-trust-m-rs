//! High-level Utility service API (`OptigaUtil`).
//!
//! Provides ergonomic methods for reading/writing data objects, metadata,
//! monotonic counters, and managing application lifecycle (open/close/hibernate).

use crate::cmd::opcodes;
use crate::cmd::tlv::TlvWriter;
use crate::cmd::types::Oid;
use crate::cmd::OptigaCmd;
use crate::config::OPTIGA_APPLICATION_ID;
use crate::error::OptigaError;
use crate::ifx_i2c::headers::ProtectionConfig;
use crate::pal::rust_crypto::RustCryptoBackend;
use crate::pal::{Datastore, DatastoreId, HostCrypto, NoDatastore, NoPin, OptigaI2cBus, OptigaTimer};
use embedded_hal::digital::OutputPin;

/// High-level utility service for OPTIGA data objects, counters, and application lifecycle.
pub struct OptigaUtil<
    'a,
    I2C,
    T,
    VDD = NoPin,
    RST = NoPin,
    CRYPTO = RustCryptoBackend,
    DS = NoDatastore,
> {
    pub cmd: &'a mut OptigaCmd<I2C, T, VDD, RST, CRYPTO, DS>,
    pub protection: ProtectionConfig,
}

impl<'a, I2C, T, VDD, RST, CRYPTO, DS> OptigaUtil<'a, I2C, T, VDD, RST, CRYPTO, DS>
where
    I2C: OptigaI2cBus,
    T: OptigaTimer,
    VDD: OutputPin,
    RST: OutputPin,
    CRYPTO: HostCrypto,
    DS: Datastore,
{
    /// Creates a new `OptigaUtil` handle borrowing `cmd`.
    pub fn new(cmd: &'a mut OptigaCmd<I2C, T, VDD, RST, CRYPTO, DS>) -> Self {
        Self {
            cmd,
            protection: ProtectionConfig::default(),
        }
    }

    /// Sets the default protection configuration for utility operations.
    pub fn set_protection(&mut self, protection: ProtectionConfig) {
        self.protection = protection;
    }

    /// Opens the OPTIGA application context (`0x70`).
    ///
    /// Sends the mandatory 16-byte OPTIGA Application Identifier (`D27600000447656E417574684170706C`).
    /// If `restore_from_hibernate` is `true`, appends the 8-byte hibernate context handle from
    /// `DatastoreId::HibernateContext` and clears the stored handle.
    pub fn open_application(&mut self, restore_from_hibernate: bool) -> Result<(), OptigaError> {
        let mut out = [0u8; 16];
        if restore_from_hibernate {
            let mut handle = [0u8; 8];
            let len = self
                .cmd
                .stack
                .prl
                .datastore
                .read(DatastoreId::HibernateContext, &mut handle)
                .map_err(|_| OptigaError::DatastoreError)?;
            if len < 8 || handle == [0u8; 8] {
                return Err(OptigaError::CommandError);
            }
            // Clear stored hibernate context handle in datastore
            self.cmd
                .stack
                .prl
                .datastore
                .write(DatastoreId::HibernateContext, &[0u8; 8])
                .map_err(|_| OptigaError::DatastoreError)?;

            let mut in_data = [0u8; 24];
            in_data[..16].copy_from_slice(&OPTIGA_APPLICATION_ID);
            in_data[16..24].copy_from_slice(&handle);
            self.cmd.execute(
                opcodes::OPEN_APPLICATION,
                0x01,
                &in_data,
                &mut out,
                self.protection,
            )?;
        } else {
            self.cmd.execute(
                opcodes::OPEN_APPLICATION,
                0x00,
                &OPTIGA_APPLICATION_ID,
                &mut out,
                self.protection,
            )?;
        }
        Ok(())
    }

    /// Closes the OPTIGA application context (`0x71`).
    ///
    /// If `hibernate` is `true`, persists the 8-byte context handle returned by the chip
    /// into `DatastoreId::HibernateContext`.
    pub fn close_application(&mut self, hibernate: bool) -> Result<(), OptigaError> {
        let param = if hibernate { 0x01 } else { 0x00 };
        let mut out = [0u8; 16];
        let len = self
            .cmd
            .execute(opcodes::CLOSE_APPLICATION, param, &[], &mut out, self.protection)?;

        if hibernate {
            if len != 8 {
                return Err(OptigaError::CommandError);
            }
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
    pub fn read_data(
        &mut self,
        oid: Oid,
        offset: u16,
        out_buf: &mut [u8],
    ) -> Result<usize, OptigaError> {
        let read_len = u16::try_from(out_buf.len()).map_err(|_| OptigaError::InvalidInput)?;
        let oid_be = oid.as_u16().to_be_bytes();
        let off_be = offset.to_be_bytes();
        let len_be = read_len.to_be_bytes();

        let in_data = [
            oid_be[0], oid_be[1], off_be[0], off_be[1], len_be[0], len_be[1],
        ];

        self.cmd
            .execute(opcodes::GET_DATA_OBJECT, 0x00, &in_data, out_buf, self.protection)
    }

    /// Writes data to a data object starting at `offset` without stack buffer allocation.
    pub fn write_data(
        &mut self,
        oid: Oid,
        offset: u16,
        data: &[u8],
        erase_and_write: bool,
    ) -> Result<(), OptigaError> {
        let oid_be = oid.as_u16().to_be_bytes();
        let off_be = offset.to_be_bytes();
        let param = if erase_and_write { 0x40 } else { 0x00 };
        let mut out = [0u8; 4];

        self.cmd.execute_with(
            opcodes::SET_DATA_OBJECT,
            param,
            |buf| {
                if 4 + data.len() > buf.len() {
                    return Err(OptigaError::MemoryInsufficient);
                }
                buf[0] = oid_be[0];
                buf[1] = oid_be[1];
                buf[2] = off_be[0];
                buf[3] = off_be[1];
                buf[4..4 + data.len()].copy_from_slice(data);
                Ok(4 + data.len())
            },
            &mut out,
            self.protection,
        )?;
        Ok(())
    }

    /// Reads metadata from a data object or key OID.
    pub fn read_metadata(&mut self, oid: Oid, out_buf: &mut [u8]) -> Result<usize, OptigaError> {
        let read_len = u16::try_from(out_buf.len()).map_err(|_| OptigaError::InvalidInput)?;
        let oid_be = oid.as_u16().to_be_bytes();
        let len_be = read_len.to_be_bytes();

        let in_data = [oid_be[0], oid_be[1], 0x00, 0x00, len_be[0], len_be[1]];

        self.cmd
            .execute(opcodes::GET_DATA_OBJECT, 0x01, &in_data, out_buf, self.protection)
    }

    /// Writes metadata to a data object or key OID (`SetDataObject` with `Param = 0x01`).
    pub fn write_metadata(&mut self, oid: Oid, metadata: &[u8]) -> Result<(), OptigaError> {
        if metadata.is_empty() {
            return Err(OptigaError::InvalidInput);
        }
        let oid_be = oid.as_u16().to_be_bytes();
        let mut out = [0u8; 4];

        self.cmd.execute_with(
            opcodes::SET_DATA_OBJECT,
            0x01,
            |buf| {
                if 4 + metadata.len() > buf.len() {
                    return Err(OptigaError::MemoryInsufficient);
                }
                buf[0] = oid_be[0];
                buf[1] = oid_be[1];
                buf[2] = 0x00;
                buf[3] = 0x00;
                buf[4..4 + metadata.len()].copy_from_slice(metadata);
                Ok(4 + metadata.len())
            },
            &mut out,
            self.protection,
        )?;
        Ok(())
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

    /// Increments a monotonic counter by `count` (`SetDataObject` with `Param = 0x02`).
    pub fn increment_monotonic_counter(
        &mut self,
        counter_oid: Oid,
        count: u8,
    ) -> Result<(), OptigaError> {
        let oid_be = counter_oid.as_u16().to_be_bytes();
        // Wire format: [OID (2B BE), Offset = 0x0000 (2B BE), Count (1B)]
        let in_data = [oid_be[0], oid_be[1], 0x00, 0x00, count];
        let mut out = [0u8; 4];
        self.cmd
            .execute(opcodes::SET_DATA_OBJECT, 0x02, &in_data, &mut out, self.protection)?;
        Ok(())
    }

    /// Starts a Protected Update sequence (`SetObjectProtected` `0x03`, Tag `0x82`).
    pub fn protected_update_start(
        &mut self,
        manifest_version: u8,
        manifest: &[u8],
    ) -> Result<(), OptigaError> {
        let mut out = [0u8; 4];
        self.cmd.execute_with(
            opcodes::SET_OBJECT_PROTECTED,
            manifest_version,
            |buf| {
                let mut writer = TlvWriter::new(buf);
                writer.write_tlv(0x82, manifest)?;
                Ok(writer.len())
            },
            &mut out,
            self.protection,
        )?;
        Ok(())
    }

    /// Continues a Protected Update sequence with an intermediate fragment (`SetObjectProtected` `0x03`, Tag `0x83`).
    pub fn protected_update_continue(&mut self, fragment: &[u8]) -> Result<(), OptigaError> {
        let mut out = [0u8; 4];
        self.cmd.execute_with(
            opcodes::SET_OBJECT_PROTECTED,
            0x00,
            |buf| {
                let mut writer = TlvWriter::new(buf);
                writer.write_tlv(0x83, fragment)?;
                Ok(writer.len())
            },
            &mut out,
            self.protection,
        )?;
        Ok(())
    }

    /// Finalizes a Protected Update sequence with the final fragment (`SetObjectProtected` `0x03`, Tag `0x81`).
    pub fn protected_update_final(&mut self, fragment: &[u8]) -> Result<(), OptigaError> {
        let mut out = [0u8; 4];
        self.cmd.execute_with(
            opcodes::SET_OBJECT_PROTECTED,
            0x00,
            |buf| {
                let mut writer = TlvWriter::new(buf);
                writer.write_tlv(0x81, fragment)?;
                Ok(writer.len())
            },
            &mut out,
            self.protection,
        )?;
        Ok(())
    }

    /// Executes a complete Protected Update (Start -> Continue* -> Final) in one call.
    pub fn protected_update(
        &mut self,
        manifest_version: u8,
        manifest: &[u8],
        fragments: &[&[u8]],
    ) -> Result<(), OptigaError> {
        if fragments.is_empty() {
            return Err(OptigaError::InvalidInput);
        }
        self.protected_update_start(manifest_version, manifest)?;
        for frag in &fragments[..fragments.len() - 1] {
            self.protected_update_continue(frag)?;
        }
        self.protected_update_final(fragments[fragments.len() - 1])
    }
}
