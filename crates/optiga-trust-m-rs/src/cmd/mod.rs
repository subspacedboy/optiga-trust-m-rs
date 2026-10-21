//! Command Layer (`cmd`): APDU framing, auto-`0xF1C2` device error retrieval, and session management.

pub mod tlv;
pub mod types;

pub use tlv::{TlvReader, TlvWriter};
pub use types::{EccCurve, KeyUsage, Oid, SessionSlot};

use crate::error::{DeviceError, OptigaError};
use crate::ifx_i2c::headers::{ProtectionConfig, ProtectionLevel};
use crate::ifx_i2c::IfxI2cStack;
use crate::pal::{Datastore, HostCrypto, MonotonicClock, OptigaI2cBus};
use embedded_hal::delay::DelayNs;
use embedded_hal::digital::OutputPin;

/// Bit flag OR'd with opcodes to clear OPTIGA's last error register before execution.
pub const OPTIGA_CMD_CLEAR_LAST_ERROR: u8 = 0x80;

/// Base opcodes for OPTIGA Trust M commands.
pub mod opcodes {
    pub const OPEN_APPLICATION: u8 = 0x70;
    pub const CLOSE_APPLICATION: u8 = 0x71;
    pub const GET_DATA_OBJECT: u8 = 0x01;
    pub const SET_DATA_OBJECT: u8 = 0x02;
    pub const SET_OBJECT_PROTECTED: u8 = 0x03;
    pub const GET_RANDOM: u8 = 0x0C;
    pub const ENCRYPT_SYM: u8 = 0x14;
    pub const DECRYPT_SYM: u8 = 0x15;
    pub const CALC_HASH: u8 = 0x30;
    pub const CALC_SIGN: u8 = 0x31;
    pub const VERIFY_SIGN: u8 = 0x32;
    pub const CALC_SSEC: u8 = 0x33;
    pub const DERIVE_KEY: u8 = 0x34;
    pub const GEN_KEYPAIR: u8 = 0x38;
    pub const GEN_SYM_KEY: u8 = 0x39;
}

/// Command Layer executing APDUs with automatic `0xF1C2` device error retrieval.
pub struct OptigaCmd<I2C, D, VDD, RST, CLK, CRYPTO, DS> {
    pub stack: IfxI2cStack<I2C, D, VDD, RST, CLK, CRYPTO, DS>,
    tx_apdu_buf: [u8; 1557],
    session_slots_mask: u8,
}

impl<I2C, D, VDD, RST, CLK, CRYPTO, DS> OptigaCmd<I2C, D, VDD, RST, CLK, CRYPTO, DS>
where
    I2C: OptigaI2cBus,
    D: DelayNs,
    VDD: OutputPin,
    RST: OutputPin,
    CLK: MonotonicClock,
    CRYPTO: HostCrypto,
    DS: Datastore,
{
    /// Creates a new `OptigaCmd` instance wrapping `stack`.
    pub fn new(stack: IfxI2cStack<I2C, D, VDD, RST, CLK, CRYPTO, DS>) -> Self {
        Self {
            stack,
            tx_apdu_buf: [0u8; 1557],
            session_slots_mask: 0,
        }
    }

    /// Acquires an available volatile session slot (`0xE100..=0xE103`).
    pub fn acquire_session_slot(&mut self) -> Result<SessionSlot, OptigaError> {
        for i in 0..4 {
            if (self.session_slots_mask & (1 << i)) == 0 {
                self.session_slots_mask |= 1 << i;
                return Ok(SessionSlot::new(i).unwrap());
            }
        }
        Err(OptigaError::InstanceInUse)
    }

    /// Releases a previously acquired session slot.
    pub fn release_session_slot(&mut self, slot: SessionSlot) {
        self.session_slots_mask &= !(1 << slot.index());
    }

    /// Executes an APDU command over the stack.
    ///
    /// If the chip returns `Sta == 0xFF` (failure), this method automatically executes
    /// an internal `GetDataObject` request for OID `0xF1C2` without clearing error state,
    /// returning the exact typed `DeviceError`.
    pub fn execute(
        &mut self,
        cmd: u8,
        param: u8,
        in_data: &[u8],
        rx_out: &mut [u8],
        protection: ProtectionConfig,
    ) -> Result<usize, OptigaError> {
        if in_data.len() > 1553 {
            return Err(OptigaError::MemoryInsufficient);
        }

        // Form 4-byte APDU header: [Cmd | 0x80, Param, InLength (2B BE)]
        self.tx_apdu_buf[0] = cmd | OPTIGA_CMD_CLEAR_LAST_ERROR;
        self.tx_apdu_buf[1] = param;
        let in_len_be = (in_data.len() as u16).to_be_bytes();
        self.tx_apdu_buf[2] = in_len_be[0];
        self.tx_apdu_buf[3] = in_len_be[1];
        self.tx_apdu_buf[4..4 + in_data.len()].copy_from_slice(in_data);
        let total_apdu_len = 4 + in_data.len();

        let mut apdu_rx_buf = [0u8; 1557];
        let rx_len = self
            .stack
            .transceive(&self.tx_apdu_buf[..total_apdu_len], &mut apdu_rx_buf, protection)
            .map_err(OptigaError::Comms)?;

        if rx_len < 4 {
            return Err(OptigaError::CommandError);
        }

        let sta = apdu_rx_buf[0];
        if sta == 0x00 {
            // Success: [Sta=0x00, 0x00, OutLength (2B BE), OutData...]
            let out_len = u16::from_be_bytes([apdu_rx_buf[2], apdu_rx_buf[3]]) as usize;
            if rx_len < 4 + out_len || out_len > rx_out.len() {
                return Err(OptigaError::MemoryInsufficient);
            }
            rx_out[..out_len].copy_from_slice(&apdu_rx_buf[4..4 + out_len]);
            Ok(out_len)
        } else {
            // Device failure: automatically read 0xF1C2 error register
            let device_err = self.read_last_error_code()?;
            Err(OptigaError::Device(device_err))
        }
    }

    /// Automatically reads 1 byte from `0xF1C2` without `0x80` clear flag.
    fn read_last_error_code(&mut self) -> Result<DeviceError, OptigaError> {
        // Form GetDataObject APDU for 0xF1C2:
        // [Cmd=0x01, Param=0x00, Len=0x0006, OID=0xF1C2, Offset=0x0000, Len=0x0001]
        let get_err_apdu = [
            opcodes::GET_DATA_OBJECT, // 0x01 (NO CLEAR ERROR FLAG)
            0x00,
            0x00,
            0x06,
            0xF1,
            0xC2, // OID 0xF1C2
            0x00,
            0x00, // Offset 0x0000
            0x00,
            0x01, // Length 0x0001
        ];

        let mut apdu_rx_buf = [0u8; 64];
        let rx_len = self
            .stack
            .transceive(
                &get_err_apdu,
                &mut apdu_rx_buf,
                ProtectionConfig {
                    level: ProtectionLevel::None,
                    force_reestablish: false,
                },
            )
            .map_err(OptigaError::Comms)?;

        if rx_len >= 5 && apdu_rx_buf[0] == 0x00 {
            let err_byte = apdu_rx_buf[4];
            Ok(DeviceError::from(err_byte))
        } else {
            Ok(DeviceError::GeneralError)
        }
    }
}
