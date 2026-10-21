#![no_std]
#![forbid(unsafe_code)]

//! `optiga-trust-m-rs` is a pure-Rust, `#![no_std]`, zero-heap driver for the Infineon OPTIGA™ Trust M
//! security controller and its `ifx_i2c` (Infineon I2C Protocol v2.03) communication stack.

pub mod config;
pub mod endian;
pub mod error;
pub mod ifx_i2c;
pub mod pal;

pub use error::{DeviceError, IfxI2cError, OptigaError};
pub use ifx_i2c::{
    DataLinkLayer, IfxI2cStack, PhysicalLayer, PresentationLayer, ProtectionConfig,
    ProtectionLevel, ResetType, TransportLayer,
};
pub use pal::rust_crypto::{CryptoError, RustCryptoBackend};
pub use pal::{Datastore, DatastoreId, HostCrypto, MonotonicClock, NoPin, OptigaI2cBus};
