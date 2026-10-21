//! Infineon I2C Protocol v2.03 stack implementation (`ifx_i2c`).

pub mod datalink;
pub mod headers;
pub mod physical;

pub use datalink::{DataLinkLayer, DlEvent};
pub use headers::{
    crc16_ccitt, crc16_ccitt_byte, ChainState, Fctr, FrameType, I2cStateStatus, Pctr, PlRegister,
    ProtectionConfig, ProtectionLevel, ProtocolType, ResetType, Sctr, SeqCtrl,
};
pub use physical::PhysicalLayer;
