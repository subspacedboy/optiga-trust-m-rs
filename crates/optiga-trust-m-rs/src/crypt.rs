//! High-level Cryptographic service API (`OptigaCrypt`).
//!
//! Provides hardware-accelerated cryptographic primitives:
//! - True and Deterministic Random Number Generation (TRNG / DRNG)
//! - SHA-256 Hashing (host data and on-chip OID data)
//! - ECC Keypair Generation (persistent OID, ephemeral session slot, or exported to host)
//! - ECDSA signature generation and verification (host public key or OID certificate/key)
//! - ECDH shared secret derivation (exported to host or stored in session slot)
//! - Key Derivation (`DeriveKey`: TLS 1.2 PRF and HKDF with SHA-256/384/512)

use crate::cmd::opcodes;
use crate::cmd::tlv::{TlvReader, TlvWriter};
use crate::cmd::types::{EccCurve, KdfAlg, KeyUsage, Oid, RngType, SessionSlot};
use crate::cmd::OptigaCmd;
use crate::error::OptigaError;
use crate::ifx_i2c::headers::ProtectionConfig;
use crate::pal::rust_crypto::RustCryptoBackend;
use crate::pal::{Datastore, HostCrypto, NoDatastore, NoPin, OptigaI2cBus, OptigaTimer};
use embedded_hal::digital::OutputPin;

/// Strips redundant leading `0x00` padding bytes from ASN.1 DER `INTEGER` `(r, s)` components
/// when the following byte is `<= 0x7F` (matching `optiga_cmd_ecc_r_s_padding_check` in C).
pub fn ecc_r_s_padding_check(sig: &mut [u8], sig_len: usize) -> Result<usize, OptigaError> {
    if sig_len < 4 || sig_len > sig.len() || sig[0] != 0x02 {
        return Err(OptigaError::CommandError);
    }

    let len_r = sig[1] as usize;
    let start_s = len_r + 2;
    if len_r == 0 || start_s + 2 > sig_len || sig[start_s] != 0x02 {
        return Err(OptigaError::CommandError);
    }

    let len_s = sig[start_s + 1] as usize;
    if len_s == 0 || start_s + 2 + len_s != sig_len {
        return Err(OptigaError::CommandError);
    }

    let delta_r = usize::from(len_r > 1 && sig[2] == 0x00 && sig[3] <= 0x7F);
    let delta_s = usize::from(len_s > 1 && sig[start_s + 2] == 0x00 && sig[start_s + 3] <= 0x7F);

    if delta_r == 0 && delta_s == 0 {
        return Ok(sig_len);
    }

    let mut current_len = sig_len;
    if delta_r == 1 {
        sig[1] -= 1;
        current_len -= 1;
        sig.copy_within((2 + delta_r)..(2 + len_r + 2), 2);
    }

    if delta_s == 1 {
        sig[start_s + 1 - delta_r] -= 1;
        current_len -= 1;
    }

    sig.copy_within(
        (start_s + 2 + delta_s)..(start_s + 2 + len_s),
        start_s + 2 - delta_r,
    );

    Ok(current_len)
}

/// High-level cryptographic service for OPTIGA operations.
pub struct OptigaCrypt<
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

impl<'a, I2C, T, VDD, RST, CRYPTO, DS> OptigaCrypt<'a, I2C, T, VDD, RST, CRYPTO, DS>
where
    I2C: OptigaI2cBus,
    T: OptigaTimer,
    VDD: OutputPin,
    RST: OutputPin,
    CRYPTO: HostCrypto,
    DS: Datastore,
{
    /// Creates a new `OptigaCrypt` service borrowing `cmd`.
    pub fn new(cmd: &'a mut OptigaCmd<I2C, T, VDD, RST, CRYPTO, DS>) -> Self {
        Self {
            cmd,
            protection: ProtectionConfig::default(),
        }
    }

    /// Sets the protection configuration for cryptographic operations.
    pub fn set_protection(&mut self, protection: ProtectionConfig) {
        self.protection = protection;
    }

    /// Fills `out_buf` (8..=256 bytes) with hardware random bytes from OPTIGA's TRNG.
    pub fn get_random(&mut self, out_buf: &mut [u8]) -> Result<(), OptigaError> {
        self.get_random_with_type(RngType::Trng, out_buf)
    }

    /// Fills `out_buf` (8..=256 bytes) with hardware random bytes using `rng_type` (TRNG or DRNG).
    pub fn get_random_with_type(
        &mut self,
        rng_type: RngType,
        out_buf: &mut [u8],
    ) -> Result<(), OptigaError> {
        if !(8..=256).contains(&out_buf.len()) {
            return Err(OptigaError::InvalidInput);
        }
        let req_len = out_buf.len() as u16;
        let in_data = req_len.to_be_bytes();

        let len = self.cmd.execute(
            opcodes::GET_RANDOM,
            rng_type as u8,
            &in_data,
            out_buf,
            self.protection,
        )?;
        if len != out_buf.len() {
            return Err(OptigaError::CommandError);
        }
        Ok(())
    }

    /// Computes a one-shot SHA-256 digest of `data` using OPTIGA (`CalcHash` `0x30`, `Param = 0xE2`).
    pub fn hash_sha256(&mut self, data: &[u8], digest_out: &mut [u8; 32]) -> Result<(), OptigaError> {
        self.cmd.execute_with_response(
            opcodes::CALC_HASH,
            0xE2, // SHA-256
            |buf| {
                let mut writer = TlvWriter::new(buf);
                // Tag 0x00 = StartFinal
                writer.write_tlv(0x00, data)?;
                Ok(writer.len())
            },
            |out_data| {
                let mut reader = TlvReader::new(out_data);
                let digest = reader.find_tag(0x00).ok_or(OptigaError::CommandError)?;
                if digest.len() != 32 {
                    return Err(OptigaError::CommandError);
                }
                digest_out.copy_from_slice(digest);
                Ok(())
            },
            self.protection,
        )
    }

    /// Computes a SHA-256 digest over the contents of an on-chip data object OID (`CalcHash` Tag `0x06`).
    pub fn hash_oid_sha256(
        &mut self,
        oid: Oid,
        offset: u16,
        length: u16,
        digest_out: &mut [u8; 32],
    ) -> Result<(), OptigaError> {
        let oid_be = oid.as_u16().to_be_bytes();
        let off_be = offset.to_be_bytes();
        let len_be = length.to_be_bytes();
        let oid_spec = [
            oid_be[0], oid_be[1], off_be[0], off_be[1], len_be[0], len_be[1],
        ];

        self.cmd.execute_with_response(
            opcodes::CALC_HASH,
            0xE2, // SHA-256
            |buf| {
                let mut writer = TlvWriter::new(buf);
                // Tag 0x06 = Hash OID data (Start & Final on OID)
                writer.write_tlv(0x06, &oid_spec)?;
                Ok(writer.len())
            },
            |out_data| {
                let mut reader = TlvReader::new(out_data);
                let digest = reader.find_tag(0x00).ok_or(OptigaError::CommandError)?;
                if digest.len() != 32 {
                    return Err(OptigaError::CommandError);
                }
                digest_out.copy_from_slice(digest);
                Ok(())
            },
            self.protection,
        )
    }

    /// Generates an ECC keypair on-chip and stores the private key in `private_key_oid`,
    /// writing the exported public key into `pubkey_out` and returning its byte length.
    pub fn ecc_generate_keypair(
        &mut self,
        curve: EccCurve,
        private_key_oid: Oid,
        usage: KeyUsage,
        pubkey_out: &mut [u8],
    ) -> Result<usize, OptigaError> {
        let oid_be = private_key_oid.as_u16().to_be_bytes();

        self.cmd.execute_with_response(
            opcodes::GEN_KEYPAIR,
            curve as u8,
            |buf| {
                let mut writer = TlvWriter::new(buf);
                writer.write_tlv(0x01, &oid_be)?;
                writer.write_tlv(0x02, &[usage.0])?;
                Ok(writer.len())
            },
            |out_data| {
                let mut reader = TlvReader::new(out_data);
                let pubkey = reader.find_tag(0x02).ok_or(OptigaError::CommandError)?;
                if pubkey.len() > pubkey_out.len() {
                    return Err(OptigaError::MemoryInsufficient);
                }
                pubkey_out[..pubkey.len()].copy_from_slice(pubkey);
                Ok(pubkey.len())
            },
            self.protection,
        )
    }

    /// Generates an ECC keypair on-chip and exports both the private key and public key to the host.
    ///
    /// Returns `(private_key_len, public_key_len)`.
    pub fn ecc_generate_keypair_export(
        &mut self,
        curve: EccCurve,
        private_key_out: &mut [u8],
        pubkey_out: &mut [u8],
    ) -> Result<(usize, usize), OptigaError> {
        self.cmd.execute_with_response(
            opcodes::GEN_KEYPAIR,
            curve as u8,
            |buf| {
                let mut writer = TlvWriter::new(buf);
                // Tag 0x07 with empty value requests private key export
                writer.write_tlv(0x07, &[])?;
                Ok(writer.len())
            },
            |out_data| {
                let mut reader = TlvReader::new(out_data);
                let privkey = reader.find_tag(0x01).ok_or(OptigaError::CommandError)?;
                let pubkey = reader.find_tag(0x02).ok_or(OptigaError::CommandError)?;
                if privkey.len() > private_key_out.len() || pubkey.len() > pubkey_out.len() {
                    return Err(OptigaError::MemoryInsufficient);
                }
                private_key_out[..privkey.len()].copy_from_slice(privkey);
                pubkey_out[..pubkey.len()].copy_from_slice(pubkey);
                Ok((privkey.len(), pubkey.len()))
            },
            self.protection,
        )
    }

    /// Generates an ECC keypair on-chip in an ephemeral session slot (`0xE100..=0xE103`).
    ///
    /// If the command fails on the bus or device, the acquired `SessionSlot` is automatically
    /// released before returning `Err`.
    pub fn generate_keypair_in_session(
        &mut self,
        curve: EccCurve,
        usage: KeyUsage,
        pubkey_out: &mut [u8],
    ) -> Result<SessionSlot, OptigaError> {
        let slot = self.cmd.acquire_session_slot()?;
        let slot_oid = slot.oid();
        match self.ecc_generate_keypair(curve, slot_oid, usage, pubkey_out) {
            Ok(_) => Ok(slot),
            Err(e) => {
                self.cmd.release_session_slot(slot);
                Err(e)
            }
        }
    }

    /// Signs `digest` using ECDSA (FIPS 186-3) with the private key located at `key_oid`.
    ///
    /// Returns the ASN.1 DER `(r, s)` `INTEGER` pair in `signature_out` after performing
    /// the OPTIGA leading-zero padding check.
    pub fn ecdsa_sign(
        &mut self,
        digest: &[u8],
        key_oid: Oid,
        signature_out: &mut [u8],
    ) -> Result<usize, OptigaError> {
        let oid_be = key_oid.as_u16().to_be_bytes();

        self.cmd.execute_with_response(
            opcodes::CALC_SIGN,
            0x11,
            |buf| {
                let mut writer = TlvWriter::new(buf);
                writer.write_tlv(0x01, digest)?;
                writer.write_tlv(0x03, &oid_be)?;
                Ok(writer.len())
            },
            |out_data| {
                if out_data.len() > signature_out.len() {
                    return Err(OptigaError::MemoryInsufficient);
                }
                signature_out[..out_data.len()].copy_from_slice(out_data);
                ecc_r_s_padding_check(signature_out, out_data.len())
            },
            self.protection,
        )
    }

    /// Signs `digest` using ECDSA with the ephemeral private key in `session_slot`.
    pub fn ecdsa_sign_with_session(
        &mut self,
        digest: &[u8],
        session_slot: &SessionSlot,
        signature_out: &mut [u8],
    ) -> Result<usize, OptigaError> {
        self.ecdsa_sign(digest, session_slot.oid(), signature_out)
    }

    /// Verifies an ECDSA signature over `digest` using the provided host `pubkey`.
    pub fn ecdsa_verify(
        &mut self,
        digest: &[u8],
        signature: &[u8],
        pubkey: &[u8],
        curve: EccCurve,
    ) -> Result<bool, OptigaError> {
        let mut rx = [0u8; 4];
        let res = self.cmd.execute_with(
            opcodes::VERIFY_SIGN,
            0x11,
            |buf| {
                let mut writer = TlvWriter::new(buf);
                writer.write_tlv(0x01, digest)?;
                writer.write_tlv(0x02, signature)?;
                writer.write_tlv(0x05, &[curve as u8])?;
                writer.write_tlv(0x06, pubkey)?;
                Ok(writer.len())
            },
            &mut rx,
            self.protection,
        );
        match res {
            Ok(_) => Ok(true),
            Err(OptigaError::Device(crate::error::DeviceError::SignatureVerificationFailure)) => {
                Ok(false)
            }
            Err(e) => Err(e),
        }
    }

    /// Verifies an ECDSA signature over `digest` using an on-chip public key or certificate OID (`Tag 0x04`).
    pub fn ecdsa_verify_with_oid(
        &mut self,
        digest: &[u8],
        signature: &[u8],
        public_key_or_cert_oid: Oid,
    ) -> Result<bool, OptigaError> {
        let oid_be = public_key_or_cert_oid.as_u16().to_be_bytes();
        let mut rx = [0u8; 4];
        let res = self.cmd.execute_with(
            opcodes::VERIFY_SIGN,
            0x11,
            |buf| {
                let mut writer = TlvWriter::new(buf);
                writer.write_tlv(0x01, digest)?;
                writer.write_tlv(0x02, signature)?;
                writer.write_tlv(0x04, &oid_be)?;
                Ok(writer.len())
            },
            &mut rx,
            self.protection,
        );
        match res {
            Ok(_) => Ok(true),
            Err(OptigaError::Device(crate::error::DeviceError::SignatureVerificationFailure)) => {
                Ok(false)
            }
            Err(e) => Err(e),
        }
    }

    /// Performs ECDH key agreement deriving a shared secret from `priv_key_oid` and `peer_pubkey`,
    /// exporting the shared secret to `shared_secret_out`.
    pub fn ecdh(
        &mut self,
        priv_key_oid: Oid,
        peer_pubkey: &[u8],
        curve: EccCurve,
        shared_secret_out: &mut [u8],
    ) -> Result<usize, OptigaError> {
        let oid_be = priv_key_oid.as_u16().to_be_bytes();
        let expected_len = curve.shared_secret_len();
        if shared_secret_out.len() < expected_len {
            return Err(OptigaError::MemoryInsufficient);
        }

        self.cmd.execute_with_response(
            opcodes::CALC_SSEC,
            0x01,
            |buf| {
                let mut writer = TlvWriter::new(buf);
                writer.write_tlv(0x01, &oid_be)?;
                writer.write_tlv(0x05, &[curve as u8])?;
                writer.write_tlv(0x06, peer_pubkey)?;
                // Tag 0x07 with empty value requests exporting the shared secret to host
                writer.write_tlv(0x07, &[])?;
                Ok(writer.len())
            },
            |out_data| {
                if out_data.len() != expected_len {
                    return Err(OptigaError::CommandError);
                }
                shared_secret_out[..expected_len].copy_from_slice(out_data);
                Ok(expected_len)
            },
            self.protection,
        )
    }

    /// Performs ECDH key agreement and stores the resulting shared secret inside an on-chip
    /// `SessionSlot` (`Tag 0x08`) for subsequent `derive_key_*` operations.
    pub fn ecdh_to_session(
        &mut self,
        priv_key_oid: Oid,
        peer_pubkey: &[u8],
        curve: EccCurve,
    ) -> Result<SessionSlot, OptigaError> {
        let slot = self.cmd.acquire_session_slot()?;
        let priv_oid_be = priv_key_oid.as_u16().to_be_bytes();
        let session_oid_be = slot.oid().as_u16().to_be_bytes();

        let mut rx = [0u8; 4];
        let res = self.cmd.execute_with(
            opcodes::CALC_SSEC,
            0x01,
            |buf| {
                let mut writer = TlvWriter::new(buf);
                writer.write_tlv(0x01, &priv_oid_be)?;
                writer.write_tlv(0x05, &[curve as u8])?;
                writer.write_tlv(0x06, peer_pubkey)?;
                writer.write_tlv(0x08, &session_oid_be)?;
                Ok(writer.len())
            },
            &mut rx,
            self.protection,
        );
        match res {
            Ok(_) => Ok(slot),
            Err(e) => {
                self.cmd.release_session_slot(slot);
                Err(e)
            }
        }
    }

    /// Derives a key (`DeriveKey` `0x34`) from `secret_oid` (e.g., a `SessionSlot::oid()` or preshared secret OID)
    /// and exports the derived key into `derived_key_out`.
    pub fn derive_key_to_host(
        &mut self,
        alg: KdfAlg,
        secret_oid: Oid,
        label: &[u8],
        seed_or_salt: &[u8],
        info: Option<&[u8]>,
        derived_key_out: &mut [u8],
    ) -> Result<(), OptigaError> {
        if derived_key_out.is_empty() || derived_key_out.len() > 1553 {
            return Err(OptigaError::InvalidInput);
        }
        let secret_oid_be = secret_oid.as_u16().to_be_bytes();
        let req_len = derived_key_out.len();
        // Hardware requires at least 16 bytes in Tag 0x03 on wire
        let wire_key_len = (req_len.max(16) as u16).to_be_bytes();

        self.cmd.execute_with_response(
            opcodes::DERIVE_KEY,
            alg as u8,
            |buf| {
                let mut writer = TlvWriter::new(buf);
                writer.write_tlv(0x01, &secret_oid_be)?;
                writer.write_tlv(0x03, &wire_key_len)?;
                if let Some(info_bytes) = info {
                    if !info_bytes.is_empty() {
                        writer.write_tlv(0x04, info_bytes)?;
                    }
                }
                writer.write_tlv_concat(0x02, label, seed_or_salt)?;
                writer.write_tlv(0x07, &[])?; // Export to host
                Ok(writer.len())
            },
            |out_data| {
                if out_data.len() < req_len {
                    return Err(OptigaError::CommandError);
                }
                derived_key_out.copy_from_slice(&out_data[..req_len]);
                Ok(())
            },
            self.protection,
        )
    }

    /// Derives a key (`DeriveKey` `0x34`) from `secret_oid` and stores the derived key in `target_session`.
    #[allow(clippy::too_many_arguments)]
    pub fn derive_key_to_session(
        &mut self,
        alg: KdfAlg,
        secret_oid: Oid,
        label: &[u8],
        seed_or_salt: &[u8],
        info: Option<&[u8]>,
        derived_key_len: u16,
        target_session: &SessionSlot,
    ) -> Result<(), OptigaError> {
        if derived_key_len == 0 {
            return Err(OptigaError::InvalidInput);
        }
        let secret_oid_be = secret_oid.as_u16().to_be_bytes();
        let wire_key_len = derived_key_len.max(16).to_be_bytes();
        let target_oid_be = target_session.oid().as_u16().to_be_bytes();
        let mut rx = [0u8; 4];

        self.cmd.execute_with(
            opcodes::DERIVE_KEY,
            alg as u8,
            |buf| {
                let mut writer = TlvWriter::new(buf);
                writer.write_tlv(0x01, &secret_oid_be)?;
                writer.write_tlv(0x03, &wire_key_len)?;
                if let Some(info_bytes) = info {
                    if !info_bytes.is_empty() {
                        writer.write_tlv(0x04, info_bytes)?;
                    }
                }
                writer.write_tlv_concat(0x02, label, seed_or_salt)?;
                writer.write_tlv(0x08, &target_oid_be)?; // Store in session OID
                Ok(writer.len())
            },
            &mut rx,
            self.protection,
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ecc_r_s_padding_check_strips_redundant_zero() {
        // r has 33 bytes with 0x00 followed by 0x55 (<= 0x7F): redundant zero should be stripped!
        // s has 33 bytes with 0x00 followed by 0x80 (> 0x7F): valid two's complement sign byte, kept!
        let mut sig = [0u8; 70];
        sig[0] = 0x02;
        sig[1] = 33;
        sig[2] = 0x00;
        sig[3..35].fill(0x55);
        sig[35] = 0x02;
        sig[36] = 33;
        sig[37] = 0x00;
        sig[38] = 0x80;
        sig[39..70].fill(0xAA);

        let new_len = ecc_r_s_padding_check(&mut sig, 70).unwrap();
        assert_eq!(new_len, 69);
        assert_eq!(sig[0], 0x02);
        assert_eq!(sig[1], 32);
        assert_eq!(sig[2], 0x55);
        assert_eq!(sig[34], 0x02);
        assert_eq!(sig[35], 33);
        assert_eq!(sig[36], 0x00);
        assert_eq!(sig[37], 0x80);
    }
}
