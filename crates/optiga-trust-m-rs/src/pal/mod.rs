//! Platform Abstraction Layer (PAL) traits for hardware and cryptographic independence.

pub mod rust_crypto;

use core::fmt::Debug;
use embedded_hal::delay::DelayNs;
use embedded_hal::digital::OutputPin;
use embedded_hal::i2c::I2c;

/// Extension of `embedded_hal::i2c::I2c` supporting dynamic bus speed negotiation.
pub trait OptigaI2cBus: I2c {
    /// Sets the I2C master clock frequency in kHz (e.g., 100 for standard negotiation, up to 1000 for FM+).
    /// Returns `Err` if the bitrate cannot be configured.
    fn set_bitrate_khz(&mut self, bitrate_khz: u16) -> Result<(), Self::Error>;
}

/// Monotonic millisecond clock used for timeouts and protocol timers.
pub trait MonotonicClock {
    /// Returns current monotonic tick count in milliseconds.
    fn now_ms(&self) -> u32;
}

/// Unified timer trait combining sub-millisecond delays (`DelayNs`) and
/// a monotonic millisecond tick counter (`MonotonicClock`).
///
/// Automatically implemented for any type implementing both `DelayNs` and `MonotonicClock`.
pub trait OptigaTimer: DelayNs + MonotonicClock {}

impl<T: DelayNs + MonotonicClock> OptigaTimer for T {}

/// Asynchronous extension of `embedded_hal_async::i2c::I2c` supporting dynamic bus speed negotiation.
#[cfg(feature = "async")]
#[allow(async_fn_in_trait)]
pub trait AsyncOptigaI2cBus: embedded_hal_async::i2c::I2c {
    /// Sets the I2C master clock frequency in kHz (e.g., 100 for standard negotiation, up to 1000 for FM+).
    /// Returns `Err` if the bitrate cannot be configured.
    async fn set_bitrate_khz(&mut self, bitrate_khz: u16) -> Result<(), Self::Error>;
}

/// Unified asynchronous timer trait combining non-blocking delays (`embedded_hal_async::delay::DelayNs`)
/// and a monotonic millisecond tick counter (`MonotonicClock`).
///
/// Automatically implemented for any type implementing both `embedded_hal_async::delay::DelayNs` and `MonotonicClock`.
#[cfg(feature = "async")]
pub trait AsyncOptigaTimer: embedded_hal_async::delay::DelayNs + MonotonicClock {}

#[cfg(feature = "async")]
impl<T: embedded_hal_async::delay::DelayNs + MonotonicClock> AsyncOptigaTimer for T {}

/// Well-known datastore slot identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum DatastoreId {
    /// Platform binding shared secret (`0x11`), max length 64 bytes.
    PlatformBindingSharedSecret = 0x0011,
    /// Shielded connection managed session context (`0x22`).
    ManageContext = 0x0022,
    /// Hibernate application context handle (`0x33`), 8 bytes.
    HibernateContext = 0x0033,
}

/// Persistent or RAM-backed datastore for OPTIGA host secrets and session states.
pub trait Datastore {
    type Error: Debug;

    /// Reads the entry for `id` into `buf`, returning the number of bytes read.
    fn read(&self, id: DatastoreId, buf: &mut [u8]) -> Result<usize, Self::Error>;

    /// Writes `data` to the slot identified by `id`.
    fn write(&mut self, id: DatastoreId, data: &[u8]) -> Result<(), Self::Error>;
}

/// Host cryptographic primitives required by the Presentation Layer.
pub trait HostCrypto {
    type Error: Debug;

    /// Derives `out.len()` bytes using TLS 1.2 PRF with HMAC-SHA256 (RFC 5246 Section 5).
    fn tls_prf_sha256(
        &mut self,
        secret: &[u8],
        label: &[u8],
        seed: &[u8],
        out: &mut [u8],
    ) -> Result<(), Self::Error>;

    /// Encrypts `buf` in-place using AES-128-CCM with an 8-byte MAC tag and 8-byte nonce.
    /// Returns the 8-byte authentication tag.
    fn aes128_ccm_8_encrypt(
        &mut self,
        key: &[u8; 16],
        nonce: &[u8; 8],
        associated_data: &[u8],
        buf: &mut [u8],
    ) -> Result<[u8; 8], Self::Error>;

    /// Decrypts `buf` in-place and verifies the 8-byte `tag` using AES-128-CCM-8.
    /// Must zeroize `buf` and return `Err` if tag verification fails!
    fn aes128_ccm_8_decrypt(
        &mut self,
        key: &[u8; 16],
        nonce: &[u8; 8],
        associated_data: &[u8],
        buf: &mut [u8],
        tag: &[u8; 8],
    ) -> Result<(), Self::Error>;
}

/// Dummy GPIO pin that safely ignores output operations.
///
/// Useful for hardware configurations where `VDD` or `RESET` pins are hardwired.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoPin;

impl embedded_hal::digital::ErrorType for NoPin {
    type Error = core::convert::Infallible;
}

impl OutputPin for NoPin {
    #[inline]
    fn set_low(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }

    #[inline]
    fn set_high(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

/// No-op datastore implementation for unshielded configurations where platform binding
/// secrets and hibernate context persistence are not required.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoDatastore;

impl Datastore for NoDatastore {
    type Error = ();

    #[inline]
    fn read(&self, _id: DatastoreId, _buf: &mut [u8]) -> Result<usize, Self::Error> {
        Err(())
    }

    #[inline]
    fn write(&mut self, _id: DatastoreId, _data: &[u8]) -> Result<(), Self::Error> {
        Err(())
    }
}
