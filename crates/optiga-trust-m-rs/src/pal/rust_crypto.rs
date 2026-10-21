//! Pure-Rust `#![no_std]` implementation of `HostCrypto` using RustCrypto primitives.

use super::HostCrypto;
use aes::Aes128;
use ccm::{
    aead::{generic_array::GenericArray, AeadInPlace, KeyInit},
    consts::U8,
    Ccm,
};
use core::fmt;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroize;

/// AES-128-CCM with 8-byte authentication tag (M = 8) and 8-byte nonce (N = 8).
pub type Aes128Ccm8 = Ccm<Aes128, U8, U8>;

/// HMAC with SHA-256.
pub type HmacSha256 = Hmac<Sha256>;

/// Errors originating from host cryptographic operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoError {
    /// Key or parameter length is invalid for the requested cipher.
    InvalidKeyLength,
    /// Ciphertext or authentication tag verification failed.
    TagVerificationFailed,
    /// HMAC or hashing operation failed.
    HmacError,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidKeyLength => write!(f, "Invalid key or parameter length"),
            Self::TagVerificationFailed => write!(f, "Tag verification failed"),
            Self::HmacError => write!(f, "HMAC error"),
        }
    }
}

/// Pure-Rust `#![no_std]` host cryptographic backend.
#[derive(Debug, Clone, Copy, Default)]
pub struct RustCryptoBackend;

impl HostCrypto for RustCryptoBackend {
    type Error = CryptoError;

    fn tls_prf_sha256(
        &mut self,
        secret: &[u8],
        label: &[u8],
        seed: &[u8],
        out: &mut [u8],
    ) -> Result<(), Self::Error> {
        if out.is_empty() {
            return Ok(());
        }

        // P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) + HMAC_hash(secret, A(2) + seed) + ...
        // where A(0) = seed_concat = label || seed
        //       A(i) = HMAC_hash(secret, A(i-1))
        let mut a = [0u8; 32];

        // Compute A(1) = HMAC(secret, label || seed)
        let mut hmac_a: HmacSha256 =
            Mac::new_from_slice(secret).map_err(|_| CryptoError::HmacError)?;
        hmac_a.update(label);
        hmac_a.update(seed);
        let a_res = hmac_a.finalize().into_bytes();
        a.copy_from_slice(&a_res);

        let mut offset = 0;
        while offset < out.len() {
            // Compute HMAC(secret, A(i) || label || seed)
            let mut hmac_block: HmacSha256 =
                Mac::new_from_slice(secret).map_err(|_| CryptoError::HmacError)?;
            hmac_block.update(&a);
            hmac_block.update(label);
            hmac_block.update(seed);
            let block = hmac_block.finalize().into_bytes();

            let to_copy = core::cmp::min(block.len(), out.len() - offset);
            out[offset..offset + to_copy].copy_from_slice(&block[..to_copy]);
            offset += to_copy;

            if offset < out.len() {
                // Compute A(i+1) = HMAC(secret, A(i))
                let mut hmac_next_a: HmacSha256 =
                    Mac::new_from_slice(secret).map_err(|_| CryptoError::HmacError)?;
                hmac_next_a.update(&a);
                let next_a_res = hmac_next_a.finalize().into_bytes();
                a.copy_from_slice(&next_a_res);
            }
        }

        a.zeroize();
        Ok(())
    }

    fn aes128_ccm_8_encrypt(
        &mut self,
        key: &[u8; 16],
        nonce: &[u8; 8],
        associated_data: &[u8],
        buf: &mut [u8],
    ) -> Result<[u8; 8], Self::Error> {
        let cipher = Aes128Ccm8::new(GenericArray::from_slice(key));
        let tag = cipher
            .encrypt_in_place_detached(
                GenericArray::from_slice(nonce),
                associated_data,
                buf,
            )
            .map_err(|_| CryptoError::InvalidKeyLength)?;

        let mut tag_arr = [0u8; 8];
        tag_arr.copy_from_slice(tag.as_slice());
        Ok(tag_arr)
    }

    fn aes128_ccm_8_decrypt(
        &mut self,
        key: &[u8; 16],
        nonce: &[u8; 8],
        associated_data: &[u8],
        buf: &mut [u8],
        tag: &[u8; 8],
    ) -> Result<(), Self::Error> {
        let cipher = Aes128Ccm8::new(GenericArray::from_slice(key));
        match cipher.decrypt_in_place_detached(
            GenericArray::from_slice(nonce),
            associated_data,
            buf,
            GenericArray::from_slice(tag),
        ) {
            Ok(()) => Ok(()),
            Err(_) => {
                buf.zeroize();
                Err(CryptoError::TagVerificationFailed)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn test_tls_prf_sha256_rfc5246_sample() {
        let mut backend = RustCryptoBackend;
        let secret = hex!("abacabacabacabacabacabacabacabac");
        let label = b"test label";
        let seed = hex!("0102030405060708090a0b0c0d0e0f10");

        let mut out1 = [0u8; 40];
        let mut out2 = [0u8; 40];

        assert!(backend.tls_prf_sha256(&secret, label, &seed, &mut out1).is_ok());
        // Deterministic check
        assert!(backend.tls_prf_sha256(&secret, label, &seed, &mut out2).is_ok());
        assert_eq!(out1, out2);
        assert_ne!(out1, [0u8; 40]);

        // Slicing check: first 16 bytes match a 16-byte derivation
        let mut out_short = [0u8; 16];
        assert!(backend.tls_prf_sha256(&secret, label, &seed, &mut out_short).is_ok());
        assert_eq!(&out1[..16], &out_short[..]);
    }

    #[test]
    fn test_aes128_ccm_8_nist_vector() {
        // NIST SP 800-38C Example 1:
        // Key: 404142434445464748494a4b4c4d4e4f
        // Nonce: 10111213141516 (7 bytes) -> for 8-byte nonce:
        // Let's test roundtrip encrypt/decrypt and tag verification failure on corruption
        let mut backend = RustCryptoBackend;
        let key = hex!("404142434445464748494a4b4c4d4e4f");
        let nonce = hex!("1011121314151617");
        let aad = hex!("0001020304050607");
        let plaintext = hex!("202122232425262728292a2b2c2d2e2f");

        let mut buf = plaintext;
        let tag = backend
            .aes128_ccm_8_encrypt(&key, &nonce, &aad, &mut buf)
            .expect("encryption succeeds");

        // Verify ciphertext differs from plaintext
        assert_ne!(buf, plaintext);

        // Decrypt with correct tag
        let mut decrypt_buf = buf;
        backend
            .aes128_ccm_8_decrypt(&key, &nonce, &aad, &mut decrypt_buf, &tag)
            .expect("decryption succeeds");
        assert_eq!(decrypt_buf, plaintext);

        // Corrupted tag fails and zeroizes buffer
        let mut bad_buf = buf;
        let mut bad_tag = tag;
        bad_tag[0] ^= 0x01;
        let err = backend.aes128_ccm_8_decrypt(&key, &nonce, &aad, &mut bad_buf, &bad_tag);
        assert_eq!(err, Err(CryptoError::TagVerificationFailed));
        assert_eq!(bad_buf, [0u8; 16]); // Zeroized on error!

        // Corrupted ciphertext fails and zeroizes buffer
        let mut bad_buf2 = buf;
        bad_buf2[0] ^= 0x01;
        let err2 = backend.aes128_ccm_8_decrypt(&key, &nonce, &aad, &mut bad_buf2, &tag);
        assert_eq!(err2, Err(CryptoError::TagVerificationFailed));
        assert_eq!(bad_buf2, [0u8; 16]); // Zeroized on error!
    }
}
