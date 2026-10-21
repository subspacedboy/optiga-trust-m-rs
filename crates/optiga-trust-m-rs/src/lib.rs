#![no_std]
#![forbid(unsafe_code)]

//! `optiga-trust-m-rs` is a pure-Rust, `#![no_std]`, zero-heap driver for the Infineon OPTIGA™ Trust M
//! security controller and its `ifx_i2c` (Infineon I2C Protocol v2.03) communication stack.
//!
//! Both synchronous (`embedded-hal` v1.0) and asynchronous (`embedded-hal-async` v1.0, in [`asynch`])
//! drivers are provided out of the box.

#[cfg(feature = "async")]
pub mod asynch;
pub mod cmd;
pub mod config;
pub mod crypt;
pub mod endian;
pub mod error;
pub mod ifx_i2c;
pub mod pal;
pub mod util;

pub use cmd::types::{EccCurve, KdfAlg, KeyUsage, Oid, RngType, SessionSlot};
pub use cmd::OptigaCmd;
pub use crypt::OptigaCrypt;
pub use error::{DeviceError, IfxI2cError, OptigaError};
pub use ifx_i2c::{
    DataLinkLayer, IfxI2cStack, PhysicalLayer, PresentationLayer, ProtectionConfig,
    ProtectionLevel, ResetType, TransportLayer,
};
pub use pal::rust_crypto::{CryptoError, RustCryptoBackend};
pub use pal::{
    Datastore, DatastoreId, HostCrypto, MonotonicClock, NoDatastore, NoPin, OptigaI2cBus,
    OptigaTimer,
};
#[cfg(feature = "async")]
pub use pal::{AsyncOptigaI2cBus, AsyncOptigaTimer};
pub use util::OptigaUtil;

#[cfg(feature = "async")]
pub use asynch::{
    OptigaBuilder as AsyncOptigaBuilder, OptigaFor as AsyncOptigaFor,
    OptigaPlatform as AsyncOptigaPlatform, OptigaTrustM as AsyncOptigaTrustM,
};

use config::IFX_I2C_BASE_ADDR;
use embedded_hal::digital::OutputPin;

/// Trait bundling all hardware and cryptographic types for a synchronous OPTIGA board configuration.
///
/// Implementing `OptigaPlatform` on a zero-sized board struct allows application code to refer
/// to the driver as `OptigaFor<MyBoard>` instead of spelling out 6 generic parameters.
pub trait OptigaPlatform {
    type I2c: OptigaI2cBus;
    type Timer: OptigaTimer;
    type VddPin: OutputPin;
    type RstPin: OutputPin;
    type Crypto: HostCrypto;
    type Datastore: Datastore;
}

/// Type alias projecting an [`OptigaPlatform`] implementation into a concrete [`OptigaTrustM`] instance.
pub type OptigaFor<P> = OptigaTrustM<
    <P as OptigaPlatform>::I2c,
    <P as OptigaPlatform>::Timer,
    <P as OptigaPlatform>::VddPin,
    <P as OptigaPlatform>::RstPin,
    <P as OptigaPlatform>::Crypto,
    <P as OptigaPlatform>::Datastore,
>;

/// Fluent builder for constructing an [`OptigaTrustM`] instance with sensible defaults.
pub struct OptigaBuilder<
    I2C,
    T,
    VDD = NoPin,
    RST = NoPin,
    CRYPTO = RustCryptoBackend,
    DS = NoDatastore,
> {
    i2c: I2C,
    timer: T,
    vdd_pin: VDD,
    rst_pin: RST,
    crypto: CRYPTO,
    datastore: DS,
    slave_address: u8,
}

impl<I2C, T> OptigaBuilder<I2C, T, NoPin, NoPin, RustCryptoBackend, NoDatastore>
where
    I2C: OptigaI2cBus,
    T: OptigaTimer,
{
    /// Creates a new builder with the required I2C bus and timer, defaulting
    /// GPIO pins to [`NoPin`], crypto to [`RustCryptoBackend`], and datastore to [`NoDatastore`].
    pub fn new(i2c: I2C, timer: T) -> Self {
        Self {
            i2c,
            timer,
            vdd_pin: NoPin,
            rst_pin: NoPin,
            crypto: RustCryptoBackend,
            datastore: NoDatastore,
            slave_address: IFX_I2C_BASE_ADDR,
        }
    }
}

impl<I2C, T, VDD, RST, CRYPTO, DS> OptigaBuilder<I2C, T, VDD, RST, CRYPTO, DS>
where
    I2C: OptigaI2cBus,
    T: OptigaTimer,
    VDD: OutputPin,
    RST: OutputPin,
    CRYPTO: HostCrypto,
    DS: Datastore,
{
    /// Configures the `VDD` power switch pin used for `ResetType::Cold`.
    pub fn with_vdd_pin<NewVdd: OutputPin>(
        self,
        vdd_pin: NewVdd,
    ) -> OptigaBuilder<I2C, T, NewVdd, RST, CRYPTO, DS> {
        OptigaBuilder {
            i2c: self.i2c,
            timer: self.timer,
            vdd_pin,
            rst_pin: self.rst_pin,
            crypto: self.crypto,
            datastore: self.datastore,
            slave_address: self.slave_address,
        }
    }

    /// Configures the `RESET` pin used for `ResetType::Warm` and `ResetType::Cold`.
    pub fn with_reset_pin<NewRst: OutputPin>(
        self,
        rst_pin: NewRst,
    ) -> OptigaBuilder<I2C, T, VDD, NewRst, CRYPTO, DS> {
        OptigaBuilder {
            i2c: self.i2c,
            timer: self.timer,
            vdd_pin: self.vdd_pin,
            rst_pin,
            crypto: self.crypto,
            datastore: self.datastore,
            slave_address: self.slave_address,
        }
    }

    /// Configures both `VDD` and `RESET` pins.
    pub fn with_pins<NewVdd: OutputPin, NewRst: OutputPin>(
        self,
        vdd_pin: NewVdd,
        rst_pin: NewRst,
    ) -> OptigaBuilder<I2C, T, NewVdd, NewRst, CRYPTO, DS> {
        OptigaBuilder {
            i2c: self.i2c,
            timer: self.timer,
            vdd_pin,
            rst_pin,
            crypto: self.crypto,
            datastore: self.datastore,
            slave_address: self.slave_address,
        }
    }

    /// Configures a custom [`HostCrypto`] backend for Presentation Layer shielded connections.
    pub fn with_crypto<NewCrypto: HostCrypto>(
        self,
        crypto: NewCrypto,
    ) -> OptigaBuilder<I2C, T, VDD, RST, NewCrypto, DS> {
        OptigaBuilder {
            i2c: self.i2c,
            timer: self.timer,
            vdd_pin: self.vdd_pin,
            rst_pin: self.rst_pin,
            crypto,
            datastore: self.datastore,
            slave_address: self.slave_address,
        }
    }

    /// Configures a [`Datastore`] for platform binding shared secrets and hibernate context persistence.
    pub fn with_datastore<NewDs: Datastore>(
        self,
        datastore: NewDs,
    ) -> OptigaBuilder<I2C, T, VDD, RST, CRYPTO, NewDs> {
        OptigaBuilder {
            i2c: self.i2c,
            timer: self.timer,
            vdd_pin: self.vdd_pin,
            rst_pin: self.rst_pin,
            crypto: self.crypto,
            datastore,
            slave_address: self.slave_address,
        }
    }

    /// Configures a custom initial 7-bit I2C slave address (default `0x30`).
    pub fn with_slave_address(mut self, addr: u8) -> Self {
        self.slave_address = addr & 0x7F;
        self
    }

    /// Builds the configured [`OptigaTrustM`] driver instance.
    pub fn build(self) -> OptigaTrustM<I2C, T, VDD, RST, CRYPTO, DS> {
        let mut dev = OptigaTrustM::new(
            self.i2c,
            self.timer,
            self.vdd_pin,
            self.rst_pin,
            self.crypto,
            self.datastore,
        );
        dev.cmd.stack.pl.set_slave_address(self.slave_address);
        dev
    }
}

/// Top-level OPTIGA Trust M device instance providing safe, owned access to Utility and Cryptographic services.
pub struct OptigaTrustM<
    I2C,
    T,
    VDD = NoPin,
    RST = NoPin,
    CRYPTO = RustCryptoBackend,
    DS = NoDatastore,
> {
    pub cmd: OptigaCmd<I2C, T, VDD, RST, CRYPTO, DS>,
}

impl<I2C, T> OptigaTrustM<I2C, T, NoPin, NoPin, RustCryptoBackend, NoDatastore>
where
    I2C: OptigaI2cBus,
    T: OptigaTimer,
{
    /// Starts a fluent [`OptigaBuilder`] for configuring an `OptigaTrustM` instance.
    pub fn builder(
        i2c: I2C,
        timer: T,
    ) -> OptigaBuilder<I2C, T, NoPin, NoPin, RustCryptoBackend, NoDatastore> {
        OptigaBuilder::new(i2c, timer)
    }
}

impl<I2C, T, DS> OptigaTrustM<I2C, T, NoPin, NoPin, RustCryptoBackend, DS>
where
    I2C: OptigaI2cBus,
    T: OptigaTimer,
    DS: Datastore,
{
    /// Convenience constructor for boards where `VDD` and `RESET` pins are hardwired (using `ResetType::Soft`)
    /// and the default `RustCryptoBackend` is used.
    pub fn new_with_soft_reset(i2c: I2C, timer: T, datastore: DS) -> Self {
        Self::new(i2c, timer, NoPin, NoPin, RustCryptoBackend, datastore)
    }
}

impl<I2C, T, VDD, RST, CRYPTO, DS> OptigaTrustM<I2C, T, VDD, RST, CRYPTO, DS>
where
    I2C: OptigaI2cBus,
    T: OptigaTimer,
    VDD: OutputPin,
    RST: OutputPin,
    CRYPTO: HostCrypto,
    DS: Datastore,
{
    /// Creates a new `OptigaTrustM` instance wrapping the given hardware bus, timer, and crypto providers.
    pub fn new(
        i2c: I2C,
        timer: T,
        vdd_pin: VDD,
        rst_pin: RST,
        crypto: CRYPTO,
        datastore: DS,
    ) -> Self {
        let stack = IfxI2cStack::new(i2c, timer, vdd_pin, rst_pin, crypto, datastore);
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

    /// Releases a previously acquired volatile session slot (`0xE100..=0xE103`).
    #[inline]
    pub fn release_session_slot(&mut self, slot: SessionSlot) {
        self.cmd.release_session_slot(slot);
    }

    /// Borrows the utility service (`OptigaUtil`).
    pub fn util(&mut self) -> OptigaUtil<'_, I2C, T, VDD, RST, CRYPTO, DS> {
        OptigaUtil::new(&mut self.cmd)
    }

    /// Borrows the cryptographic service (`OptigaCrypt`).
    pub fn crypt(&mut self) -> OptigaCrypt<'_, I2C, T, VDD, RST, CRYPTO, DS> {
        OptigaCrypt::new(&mut self.cmd)
    }
}
