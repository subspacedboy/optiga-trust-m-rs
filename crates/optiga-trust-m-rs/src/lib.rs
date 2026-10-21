#![no_std]
#![forbid(unsafe_code)]

//! `optiga-trust-m-rs` is a pure-Rust, `#![no_std]`, zero-heap driver for the Infineon OPTIGA™ Trust M
//! security controller and its `ifx_i2c` (Infineon I2C Protocol v2.03) communication stack.

pub mod cmd;
pub mod config;
pub mod crypt;
pub mod endian;
pub mod error;
pub mod ifx_i2c;
pub mod pal;
pub mod util;

pub use cmd::types::{EccCurve, KeyUsage, Oid, SessionSlot};
pub use cmd::OptigaCmd;
pub use crypt::OptigaCrypt;
pub use error::{DeviceError, IfxI2cError, OptigaError};
pub use ifx_i2c::{
    DataLinkLayer, IfxI2cStack, PhysicalLayer, PresentationLayer, ProtectionConfig,
    ProtectionLevel, ResetType, TransportLayer,
};
pub use pal::rust_crypto::{CryptoError, RustCryptoBackend};
pub use pal::{Datastore, DatastoreId, HostCrypto, MonotonicClock, NoPin, OptigaI2cBus};
pub use util::OptigaUtil;

use embedded_hal::delay::DelayNs;
use embedded_hal::digital::OutputPin;

/// Top-level OPTIGA Trust M device instance providing safe, owned access to Utility and Cryptographic services.
pub struct OptigaTrustM<I2C, D, VDD, RST, CLK, CRYPTO, DS> {
    pub cmd: OptigaCmd<I2C, D, VDD, RST, CLK, CRYPTO, DS>,
}

impl<I2C, D, VDD, RST, CLK, CRYPTO, DS> OptigaTrustM<I2C, D, VDD, RST, CLK, CRYPTO, DS>
where
    I2C: OptigaI2cBus,
    D: DelayNs,
    VDD: OutputPin,
    RST: OutputPin,
    CLK: MonotonicClock,
    CRYPTO: HostCrypto,
    DS: Datastore,
{
    /// Creates a new `OptigaTrustM` instance wrapping the given hardware bus and crypto providers.
    pub fn new(
        i2c: I2C,
        delay: D,
        vdd_pin: VDD,
        rst_pin: RST,
        clock: CLK,
        crypto: CRYPTO,
        datastore: DS,
    ) -> Self {
        let stack = IfxI2cStack::new(i2c, delay, vdd_pin, rst_pin, clock, crypto, datastore);
        let cmd = OptigaCmd::new(stack);
        Self { cmd }
    }

    /// Initializes and negotiates communication with the OPTIGA chip.
    pub fn open(
        &mut self,
        reset_type: ResetType,
        frame_size: u16,
        freq_khz: u16,
    ) -> Result<(), OptigaError> {
        self.cmd
            .stack
            .open(reset_type, frame_size, freq_khz)
            .map_err(OptigaError::Comms)
    }

    /// Borrows the utility service (`OptigaUtil`).
    pub fn util(&mut self) -> OptigaUtil<'_, I2C, D, VDD, RST, CLK, CRYPTO, DS> {
        OptigaUtil::new(&mut self.cmd)
    }

    /// Borrows the cryptographic service (`OptigaCrypt`).
    pub fn crypt(&mut self) -> OptigaCrypt<'_, I2C, D, VDD, RST, CLK, CRYPTO, DS> {
        OptigaCrypt::new(&mut self.cmd)
    }
}
