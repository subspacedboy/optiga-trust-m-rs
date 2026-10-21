//! Full Virtual OPTIGA Trust M chip state machine.

pub mod apdu_slave;
pub mod dl_slave;
pub mod registers;

use crate::clock::SimulatedClock;
use crate::datastore::DEFAULT_PLATFORM_BINDING_SECRET;
use apdu_slave::VirtualApduEngine;
use dl_slave::{ReceivedFrame, SlaveDataLink};
use optiga_trust_m_rs::ifx_i2c::headers::{PlRegister, SeqCtrl};
use registers::{RegisterError, RegisterFile};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VirtualChipError {
    AddressMismatch { expected: u8, actual: u8 },
    GuardTimeViolation { elapsed_us: u64, min_required_us: u64 },
    EmptyTransaction,
    InvalidRegister(u8),
    NoRegisterSelectedForRead,
    RegisterError(RegisterError),
    ReadBufferOverflow,
    Nack,
}

/// Simulated stateful OPTIGA Trust M hardware chip.
#[derive(Debug)]
pub struct VirtualOptiga {
    pub clock: SimulatedClock,
    pub registers: RegisterFile,
    pub dl: SlaveDataLink,
    pub apdu: VirtualApduEngine,
    pub shared_secret: Vec<u8>,
}

impl VirtualOptiga {
    pub fn new(clock: SimulatedClock) -> Self {
        Self {
            clock,
            registers: RegisterFile::new(),
            dl: SlaveDataLink::new(),
            apdu: VirtualApduEngine::new(),
            shared_secret: DEFAULT_PLATFORM_BINDING_SECRET.to_vec(),
        }
    }

    /// Handles an I2C write transaction from the master.
    pub fn handle_write(&mut self, addr: u8, data: &[u8]) -> Result<(), VirtualChipError> {
        if addr != self.registers.slave_address {
            return Err(VirtualChipError::AddressMismatch {
                expected: self.registers.slave_address,
                actual: addr,
            });
        }
        if data.is_empty() {
            return Err(VirtualChipError::EmptyTransaction);
        }

        // Verify guard time invariant
        if let Err(RegisterError::GuardTimeViolation { elapsed_us, min_required_us }) =
            self.registers.check_guard_time(&self.clock)
        {
            return Err(VirtualChipError::GuardTimeViolation {
                elapsed_us,
                min_required_us,
            });
        }

        let reg_byte = data[0];
        let reg = match reg_byte {
            0x80 => PlRegister::Data,
            0x81 => PlRegister::DataRegLen,
            0x82 => PlRegister::I2cState,
            0x83 => PlRegister::BaseAddr,
            0x84 => PlRegister::MaxSclFrequ,
            0x88 => PlRegister::SoftReset,
            0x89 => PlRegister::I2cMode,
            other => return Err(VirtualChipError::InvalidRegister(other)),
        };

        if data.len() == 1 {
            // Register select for subsequent read (Phase A)
            self.registers.selected_reg = Some(reg);
            return Ok(());
        }

        // Write register content (Phase B of write)
        let payload = &data[1..];
        match reg {
            PlRegister::Data => {
                // Feed into Data Link Layer
                match self.dl.receive_frame(payload) {
                    Ok(ReceivedFrame::Data { payload, is_duplicate, .. }) => {
                        if !is_duplicate {
                            // Forward packet to APDU/PRL engine
                            if let Some(resp_packet) =
                                self.apdu.process_tl_packet(&payload, &self.shared_secret)
                            {
                                // Fragment response if necessary (single fragment for now)
                                self.dl.queue_data_frame(&resp_packet);
                            } else {
                                // Send ACK CF if no immediate upper response
                                self.dl.queue_control_frame(SeqCtrl::Ack, self.dl.rx_seq_nr);
                            }
                        }
                    }
                    Ok(ReceivedFrame::Control(_)) => {}
                    Err(_) => {}
                }
            }
            PlRegister::SoftReset => {
                self.registers.reset();
                self.dl.reset();
                self.apdu.reset();
            }
            _ => {
                self.registers
                    .write_register(reg, payload)
                    .map_err(VirtualChipError::RegisterError)?;
            }
        }

        Ok(())
    }

    /// Handles an I2C read transaction from the master.
    pub fn handle_read(&mut self, addr: u8, buf: &mut [u8]) -> Result<(), VirtualChipError> {
        if addr != self.registers.slave_address {
            return Err(VirtualChipError::AddressMismatch {
                expected: self.registers.slave_address,
                actual: addr,
            });
        }

        // Verify guard time invariant
        if let Err(RegisterError::GuardTimeViolation { elapsed_us, min_required_us }) =
            self.registers.check_guard_time(&self.clock)
        {
            return Err(VirtualChipError::GuardTimeViolation {
                elapsed_us,
                min_required_us,
            });
        }

        let reg = self
            .registers
            .selected_reg
            .take()
            .ok_or(VirtualChipError::NoRegisterSelectedForRead)?;

        match reg {
            PlRegister::Data => {
                let frame = self
                    .dl
                    .pop_pending_frame()
                    .unwrap_or_else(|| vec![0x80, 0x00, 0x00, 0x00, 0x00]);
                if buf.len() < frame.len() {
                    return Err(VirtualChipError::ReadBufferOverflow);
                }
                buf[..frame.len()].copy_from_slice(&frame);
            }
            PlRegister::DataRegLen => {
                let bytes = self.registers.max_frame_len.to_be_bytes();
                if buf.len() < 2 {
                    return Err(VirtualChipError::ReadBufferOverflow);
                }
                buf[0] = bytes[0];
                buf[1] = bytes[1];
            }
            PlRegister::I2cState => {
                let state_bytes = self.registers.read_i2c_state(
                    self.dl.has_pending_frame(),
                    self.dl.pending_frame_len(),
                );
                if buf.len() < 4 {
                    return Err(VirtualChipError::ReadBufferOverflow);
                }
                buf[..4].copy_from_slice(&state_bytes);
            }
            PlRegister::MaxSclFrequ => {
                let freq = self.registers.max_scl_freq_khz();
                let freq_be = freq.to_be_bytes();
                if buf.len() < 4 {
                    return Err(VirtualChipError::ReadBufferOverflow);
                }
                buf[0] = 0x00;
                buf[1] = 0x00;
                buf[2] = freq_be[0];
                buf[3] = freq_be[1];
            }
            _ => {
                return Err(VirtualChipError::InvalidRegister(reg as u8));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_virtual_optiga_read_i2c_state() {
        let clock = SimulatedClock::new();
        let mut optiga = VirtualOptiga::new(clock.clone());

        // Step 1: Select I2cState register (0x82)
        clock.advance_us(100);
        assert!(optiga.handle_write(0x30, &[0x82]).is_ok());

        // Guard time
        clock.advance_us(50);

        // Step 2: Read 4 bytes from I2cState
        let mut state = [0u8; 4];
        assert!(optiga.handle_read(0x30, &mut state).is_ok());

        // Flags should indicate soft reset supported (0x08), no response ready (0x00)
        assert_eq!(state[0], 0x08);
        assert_eq!(state[1], 0x00);
        assert_eq!(state[2], 0x00);
        assert_eq!(state[3], 0x00);
    }

    #[test]
    fn test_virtual_optiga_guard_time_violation_detection() {
        let clock = SimulatedClock::new();
        let mut optiga = VirtualOptiga::new(clock.clone());
        optiga.registers.strict_guard_time = true;

        // First write
        clock.advance_us(100);
        assert!(optiga.handle_write(0x30, &[0x82]).is_ok());

        // Second write only 10 µs later (< 50 µs guard time!)
        clock.advance_us(10);
        let res = optiga.handle_write(0x30, &[0x82]);
        assert_eq!(
            res,
            Err(VirtualChipError::GuardTimeViolation {
                elapsed_us: 10,
                min_required_us: 50,
            })
        );
    }
}
