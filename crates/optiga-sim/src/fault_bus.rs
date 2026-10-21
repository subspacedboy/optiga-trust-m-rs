//! Programmable MITM fault injecting I2C bus emulator.

use crate::virtual_chip::{VirtualChipError, VirtualOptiga};
use embedded_hal::i2c::{Error, ErrorKind, ErrorType, I2c, NoAcknowledgeSource};
use optiga_trust_m_rs::pal::OptigaI2cBus;
use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;

/// Fault rules that can be injected into the simulated I2C bus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultRule {
    /// Return NACK error on the next N write operations.
    NackNextWrites(usize),
    /// Return NACK error on the next N read operations.
    NackNextReads(usize),
    /// Corrupt a byte at `offset` by XORing with `mask` on the next read.
    CorruptNextReadByte { offset: usize, mask: u8 },
    /// Return error if master sets bitrate above `max_khz`.
    LimitMaxBitrateKhz(u16),
    /// Fail the next bitrate negotiation attempt.
    FailNextBitrateChange,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BusError {
    Nack,
    AddressNack,
    DataNack,
    BitrateNotSupported,
    Chip(VirtualChipError),
    Other,
}

impl Error for BusError {
    fn kind(&self) -> ErrorKind {
        match self {
            Self::Nack | Self::AddressNack => ErrorKind::NoAcknowledge(NoAcknowledgeSource::Address),
            Self::DataNack => ErrorKind::NoAcknowledge(NoAcknowledgeSource::Data),
            _ => ErrorKind::Other,
        }
    }
}

/// Programmable fault injecting I2C bus wrapping `VirtualOptiga`.
#[derive(Debug, Clone)]
pub struct FaultInjectingI2cBus {
    pub chip: Rc<RefCell<VirtualOptiga>>,
    pub rules: Rc<RefCell<VecDeque<FaultRule>>>,
    pub current_bitrate_khz: Rc<RefCell<u16>>,
    pub total_writes: Rc<RefCell<usize>>,
    pub total_reads: Rc<RefCell<usize>>,
}

impl FaultInjectingI2cBus {
    pub fn new(chip: VirtualOptiga) -> Self {
        Self {
            chip: Rc::new(RefCell::new(chip)),
            rules: Rc::new(RefCell::new(VecDeque::new())),
            current_bitrate_khz: Rc::new(RefCell::new(100)),
            total_writes: Rc::new(RefCell::new(0)),
            total_reads: Rc::new(RefCell::new(0)),
        }
    }

    pub fn with_shared_chip(chip: Rc<RefCell<VirtualOptiga>>) -> Self {
        Self {
            chip,
            rules: Rc::new(RefCell::new(VecDeque::new())),
            current_bitrate_khz: Rc::new(RefCell::new(100)),
            total_writes: Rc::new(RefCell::new(0)),
            total_reads: Rc::new(RefCell::new(0)),
        }
    }

    /// Adds a fault rule to the queue.
    pub fn add_rule(&self, rule: FaultRule) {
        self.rules.borrow_mut().push_back(rule);
    }

    /// Clears all pending fault rules.
    pub fn clear_rules(&self) {
        self.rules.borrow_mut().clear();
    }
}

impl ErrorType for FaultInjectingI2cBus {
    type Error = BusError;
}

impl I2c for FaultInjectingI2cBus {
    fn read(&mut self, address: u8, read: &mut [u8]) -> Result<(), Self::Error> {
        *self.total_reads.borrow_mut() += 1;

        // Check fault rules
        let mut rules = self.rules.borrow_mut();
        if let Some(FaultRule::NackNextReads(count)) = rules.front_mut() {
            if *count > 1 {
                *count -= 1;
            } else {
                rules.pop_front();
            }
            return Err(BusError::Nack);
        }
        drop(rules);

        self.chip
            .borrow_mut()
            .handle_read(address, read)
            .map_err(BusError::Chip)?;

        // Check if read byte corruption should be applied
        let mut rules = self.rules.borrow_mut();
        if let Some(FaultRule::CorruptNextReadByte { offset, mask }) = rules.front().copied() {
            if offset < read.len() {
                read[offset] ^= mask;
            }
            rules.pop_front();
        }

        Ok(())
    }

    fn write(&mut self, address: u8, write: &[u8]) -> Result<(), Self::Error> {
        *self.total_writes.borrow_mut() += 1;

        // Check fault rules
        let mut rules = self.rules.borrow_mut();
        if let Some(FaultRule::NackNextWrites(count)) = rules.front_mut() {
            if *count > 1 {
                *count -= 1;
            } else {
                rules.pop_front();
            }
            return Err(BusError::Nack);
        }
        drop(rules);

        self.chip
            .borrow_mut()
            .handle_write(address, write)
            .map_err(BusError::Chip)?;

        Ok(())
    }

    fn write_read(&mut self, address: u8, write: &[u8], read: &mut [u8]) -> Result<(), Self::Error> {
        self.write(address, write)?;
        self.read(address, read)
    }

    fn transaction(
        &mut self,
        address: u8,
        operations: &mut [embedded_hal::i2c::Operation<'_>],
    ) -> Result<(), Self::Error> {
        for op in operations {
            match op {
                embedded_hal::i2c::Operation::Read(buf) => self.read(address, buf)?,
                embedded_hal::i2c::Operation::Write(buf) => self.write(address, buf)?,
            }
        }
        Ok(())
    }
}

impl OptigaI2cBus for FaultInjectingI2cBus {
    fn set_bitrate_khz(&mut self, bitrate_khz: u16) -> Result<(), Self::Error> {
        let mut rules = self.rules.borrow_mut();
        if let Some(front) = rules.front() {
            match front {
                FaultRule::LimitMaxBitrateKhz(max) => {
                    if bitrate_khz > *max {
                        return Err(BusError::BitrateNotSupported);
                    }
                }
                FaultRule::FailNextBitrateChange => {
                    rules.pop_front();
                    return Err(BusError::BitrateNotSupported);
                }
                _ => {}
            }
        }
        *self.current_bitrate_khz.borrow_mut() = bitrate_khz;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::SimulatedClock;

    #[test]
    fn test_fault_bus_nack_rule() {
        let clock = SimulatedClock::new();
        let chip = VirtualOptiga::new(clock);
        let mut bus = FaultInjectingI2cBus::new(chip);

        // Inject 2 NACKs
        bus.add_rule(FaultRule::NackNextWrites(2));

        assert_eq!(bus.write(0x30, &[0x82]), Err(BusError::Nack));
        assert_eq!(bus.write(0x30, &[0x82]), Err(BusError::Nack));
        // Third write succeeds
        assert!(bus.write(0x30, &[0x82]).is_ok());
    }

    #[test]
    fn test_fault_bus_bitrate_limit() {
        let clock = SimulatedClock::new();
        let chip = VirtualOptiga::new(clock);
        let mut bus = FaultInjectingI2cBus::new(chip);

        bus.add_rule(FaultRule::LimitMaxBitrateKhz(400));
        assert!(bus.set_bitrate_khz(400).is_ok());
        assert_eq!(bus.set_bitrate_khz(1000), Err(BusError::BitrateNotSupported));
    }
}
