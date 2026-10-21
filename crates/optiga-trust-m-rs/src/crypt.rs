//! High-level Cryptographic service API (`OptigaCrypt`).
//!
//! Provides hardware-accelerated cryptographic primitives:
//! - True Random Number Generation (TRNG)
//! - ECC Keypair Generation (NIST P-256/384, Brainpool)
//! - ECDSA signature generation and verification
//! - ECDH shared secret derivation

use crate::cmd::opcodes;
use crate::cmd::tlv::{TlvReader, TlvWriter};
use crate::cmd::types::{EccCurve, KeyUsage, Oid, SessionSlot};
use crate::cmd::OptigaCmd;
use crate::error::OptigaError;
use crate::ifx_i2c::headers::ProtectionConfig;
use crate::pal::{Datastore, HostCrypto, MonotonicClock, OptigaI2cBus};
use embedded_hal::delay::DelayNs;
use embedded_hal::digital::OutputPin;

/// High-level cryptographic service for OPTIGA operations.
pub struct OptigaCrypt<'a, I2C, D, VDD, RST, CLK, CRYPTO, DS> {
    pub cmd: &'a mut OptigaCmd<I2C, D, VDD, RST, CLK, CRYPTO, DS>,
    pub protection: ProtectionConfig,
}

impl<'a, I2C, D, VDD, RST, CLK, CRYPTO, DS> OptigaCrypt<'a, I2C, D, VDD, RST, CLK, CRYPTO, DS>
where
    I2C: OptigaI2cBus,
    D: DelayNs,
    VDD: OutputPin,
    RST: OutputPin,
    CLK: MonotonicClock,
    CRYPTO: HostCrypto,
    DS: Datastore,
{
    /// Creates a new `OptigaCrypt` service borrowing `cmd`.
    pub fn new(cmd: &'a mut OptigaCmd<I2C, D, VDD, RST, CLK, CRYPTO, DS>) -> Self {
        Self {
            cmd,
            protection: ProtectionConfig::default(),
        }
    }

    /// Sets the protection configuration for cryptographic operations.
    pub fn set_protection(&mut self, protection: ProtectionConfig) {
        self.protection = protection;
    }

    /// Fills `out_buf` with hardware true random numbers from OPTIGA's TRNG.
    pub fn get_random(&mut self, out_buf: &mut [u8]) -> Result<(), OptigaError> {
        let req_len = u16::try_from(out_buf.len()).map_err(|_| OptigaError::InvalidInput)?;
        let in_data = req_len.to_be_bytes();

        let mut rx = [0u8; 300];
        let len = self.cmd.execute(opcodes::GET_RANDOM, 0x00, &in_data, &mut rx, self.protection)?;
        if len < out_buf.len() {
            return Err(OptigaError::CommandError);
        }
        out_buf.copy_from_slice(&rx[..out_buf.len()]);
        Ok(())
    }

    /// Generates an ECC keypair on-chip in an ephemeral session slot.
    pub fn generate_keypair_in_session(
        &mut self,
        curve: EccCurve,
        usage: KeyUsage,
        pubkey_out: &mut [u8],
    ) -> Result<SessionSlot, OptigaError> {
        let slot = self.cmd.acquire_session_slot()?;
        let slot_oid_be = slot.oid().as_u16().to_be_bytes();

        let mut tlv_buf = [0u8; 64];
        let mut writer = TlvWriter::new(&mut tlv_buf);
        writer.write_tlv(0x01, &slot_oid_be)?;
        writer.write_tlv(0x02, &[usage.0])?;
        writer.write_tlv(0x07, &[0x01])?; // Export public key
        let in_data = writer.finish();

        let mut rx = [0u8; 300];
        let rx_len = self.cmd.execute(opcodes::GEN_KEYPAIR, curve as u8, in_data, &mut rx, self.protection)?;

        let mut reader = TlvReader::new(&rx[..rx_len]);
        if let Some(pubkey) = reader.find_tag(0x02) {
            if pubkey.len() > pubkey_out.len() {
                return Err(OptigaError::MemoryInsufficient);
            }
            pubkey_out[..pubkey.len()].copy_from_slice(pubkey);
            Ok(slot)
        } else {
            Err(OptigaError::CommandError)
        }
    }

    /// Signs `digest` using ECDSA (FIPS 186-3) with the private key located at `key_oid`.
    pub fn ecdsa_sign(
        &mut self,
        digest: &[u8],
        key_oid: Oid,
        signature_out: &mut [u8],
    ) -> Result<usize, OptigaError> {
        let oid_be = key_oid.as_u16().to_be_bytes();

        let mut tlv_buf = [0u8; 128];
        let mut writer = TlvWriter::new(&mut tlv_buf);
        writer.write_tlv(0x01, digest)?;
        writer.write_tlv(0x03, &oid_be)?;
        let in_data = writer.finish();

        let mut rx = [0u8; 300];
        let rx_len = self.cmd.execute(opcodes::CALC_SIGN, 0x11, in_data, &mut rx, self.protection)?;

        let mut reader = TlvReader::new(&rx[..rx_len]);
        if let Some(sig) = reader.find_tag(0x02) {
            if sig.len() > signature_out.len() {
                return Err(OptigaError::MemoryInsufficient);
            }
            signature_out[..sig.len()].copy_from_slice(sig);
            Ok(sig.len())
        } else if rx_len > 0 && rx_len <= signature_out.len() {
            signature_out[..rx_len].copy_from_slice(&rx[..rx_len]);
            Ok(rx_len)
        } else {
            Err(OptigaError::CommandError)
        }
    }

    /// Verifies an ECDSA signature over `digest` using the provided `pubkey`.
    pub fn ecdsa_verify(
        &mut self,
        digest: &[u8],
        signature: &[u8],
        pubkey: &[u8],
        curve: EccCurve,
    ) -> Result<bool, OptigaError> {
        let mut tlv_buf = [0u8; 300];
        let mut writer = TlvWriter::new(&mut tlv_buf);
        writer.write_tlv(0x01, digest)?;
        writer.write_tlv(0x02, signature)?;
        writer.write_tlv(0x05, &[curve as u8])?;
        writer.write_tlv(0x06, pubkey)?;
        let in_data = writer.finish();

        let mut rx = [0u8; 16];
        match self.cmd.execute(opcodes::VERIFY_SIGN, 0x11, in_data, &mut rx, self.protection) {
            Ok(_) => Ok(true),
            Err(OptigaError::Device(crate::error::DeviceError::SignatureVerificationFailure)) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Performs ECDH key agreement deriving a shared secret from `priv_key_oid` and `peer_pubkey`.
    pub fn ecdh(
        &mut self,
        priv_key_oid: Oid,
        peer_pubkey: &[u8],
        curve: EccCurve,
        shared_secret_out: &mut [u8],
    ) -> Result<usize, OptigaError> {
        let oid_be = priv_key_oid.as_u16().to_be_bytes();

        let mut tlv_buf = [0u8; 256];
        let mut writer = TlvWriter::new(&mut tlv_buf);
        writer.write_tlv(0x01, &oid_be)?;
        writer.write_tlv(0x05, &[curve as u8])?;
        writer.write_tlv(0x06, peer_pubkey)?;
        writer.write_tlv(0x07, &[0x01])?; // Export shared secret
        let in_data = writer.finish();

        let mut rx = [0u8; 300];
        let rx_len = self.cmd.execute(opcodes::CALC_SSEC, 0x01, in_data, &mut rx, self.protection)?;

        let mut reader = TlvReader::new(&rx[..rx_len]);
        if let Some(ssec) = reader.find_tag(0x07) {
            if ssec.len() > shared_secret_out.len() {
                return Err(OptigaError::MemoryInsufficient);
            }
            shared_secret_out[..ssec.len()].copy_from_slice(ssec);
            Ok(ssec.len())
        } else if rx_len > 0 && rx_len <= shared_secret_out.len() {
            shared_secret_out[..rx_len].copy_from_slice(&rx[..rx_len]);
            Ok(rx_len)
        } else {
            Err(OptigaError::CommandError)
        }
    }
}
