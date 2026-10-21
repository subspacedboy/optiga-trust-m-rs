//! Physical Layer register file simulation and guard time verification.

use crate::clock::SimulatedClock;
use optiga_trust_m_rs::ifx_i2c::headers::{I2cStateStatus, PlRegister};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegisterError {
    GuardTimeViolation { elapsed_us: u64, min_required_us: u64 },
    InvalidRegister(u8),
    WriteLengthMismatch,
    DeviceBusy,
}

/// Simulated OPTIGA Physical Layer register file.
#[derive(Debug)]
pub struct RegisterFile {
    pub slave_address: u8,
    pub configured_base_address: u8,
    pub max_frame_len: u16,
    pub i2c_mode: u8,
    pub soft_reset_supported: bool,
    pub last_bus_activity_us: Option<u64>,
    pub guard_time_violations: usize,
    pub strict_guard_time: bool,
    pub selected_reg: Option<PlRegister>,
    pub is_busy: bool,
}

impl Default for RegisterFile {
    fn default() -> Self {
        Self {
            slave_address: 0x30,
            configured_base_address: 0x30,
            max_frame_len: 277,
            i2c_mode: 0x03, // SM/FM (400 kHz max)
            soft_reset_supported: true,
            last_bus_activity_us: None,
            guard_time_violations: 0,
            strict_guard_time: false,
            selected_reg: None,
            is_busy: false,
        }
    }
}

impl RegisterFile {
    pub fn new() -> Self {
        Self::default()
    }

    /// Verifies the $50\ \mu\text{s}$ guard time invariant and updates `last_bus_activity_us`.
    pub fn check_guard_time(&mut self, clock: &SimulatedClock) -> Result<(), RegisterError> {
        let now = clock.now_us();
        if let Some(last) = self.last_bus_activity_us {
            let elapsed = now.saturating_sub(last);
            if elapsed < 50 {
                self.guard_time_violations += 1;
                if self.strict_guard_time {
                    return Err(RegisterError::GuardTimeViolation {
                        elapsed_us: elapsed,
                        min_required_us: 50,
                    });
                }
            }
        }
        self.last_bus_activity_us = Some(now);
        Ok(())
    }

    /// Returns the maximum supported SCL frequency in kHz based on current `i2c_mode`.
    pub fn max_scl_freq_khz(&self) -> u16 {
        if self.i2c_mode == 0x04 {
            1_000 // FM+ (1000 kHz)
        } else {
            400 // SM/FM (400 kHz)
        }
    }

    /// Reads 4 bytes from `PL_REG_I2C_STATE` (`0x82`).
    pub fn read_i2c_state(&self, has_response: bool, response_len: u16) -> [u8; 4] {
        let mut flags = 0u8;
        if self.is_busy {
            flags |= I2cStateStatus::FLAG_BUSY;
        }
        if has_response {
            flags |= I2cStateStatus::FLAG_RESPONSE_READY;
        }
        if self.soft_reset_supported {
            flags |= I2cStateStatus::FLAG_SOFT_RESET_SUPPORTED;
        }
        let len_be = if has_response { response_len.to_be_bytes() } else { [0, 0] };
        [flags, 0x00, len_be[0], len_be[1]]
    }

    /// Writes content into a register.
    pub fn write_register(&mut self, reg: PlRegister, data: &[u8]) -> Result<(), RegisterError> {
        match reg {
            PlRegister::DataRegLen => {
                if data.len() != 2 {
                    return Err(RegisterError::WriteLengthMismatch);
                }
                let len = u16::from_be_bytes([data[0], data[1]]);
                // OPTIGA clamps to valid boundaries (16..=277)
                self.max_frame_len = len.clamp(16, 277);
                Ok(())
            }
            PlRegister::BaseAddr => {
                if data.len() != 2 {
                    return Err(RegisterError::WriteLengthMismatch);
                }
                // data = [mode, addr & 0x7F]
                let addr_7bit = data[1] & 0x7F;
                self.slave_address = addr_7bit;
                if (data[0] & 0x80) != 0 {
                    self.configured_base_address = addr_7bit;
                }
                Ok(())
            }
            PlRegister::SoftReset => {
                if data.len() != 2 || data != [0x00, 0x00] {
                    return Err(RegisterError::WriteLengthMismatch);
                }
                self.reset();
                Ok(())
            }
            PlRegister::I2cMode => {
                if data.len() != 2 || data[0] != 0x80 {
                    return Err(RegisterError::WriteLengthMismatch);
                }
                self.i2c_mode = data[1];
                Ok(())
            }
            _ => Ok(()),
        }
    }

    /// Resets register values to defaults.
    pub fn reset(&mut self) {
        self.slave_address = self.configured_base_address;
        self.max_frame_len = 277;
        self.i2c_mode = 0x03;
        self.is_busy = false;
        self.selected_reg = None;
    }
}
