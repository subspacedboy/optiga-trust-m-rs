//! Physical Layer (`ifx_i2c::physical`) implementation.
//!
//! Handles register transactions, $50\ \mu\text{s}$ guard times, NACK retry loops,
//! reset sequences (Cold/Warm/Soft), frequency/frame size negotiation, and slave address configuration.

use crate::config::*;
use crate::error::IfxI2cError;
use crate::ifx_i2c::headers::{I2cStateStatus, PlRegister, ResetType};
use crate::pal::{MonotonicClock, OptigaI2cBus};
use embedded_hal::delay::DelayNs;
use embedded_hal::digital::OutputPin;

/// Physical Layer driver managing raw I2C register communication and reset sequences.
pub struct PhysicalLayer<I2C, D, VDD, RST> {
    pub i2c: I2C,
    pub delay: D,
    pub vdd_pin: VDD,
    pub rst_pin: RST,
    pub slave_address: u8,
    pub negotiated_frame_size: u16,
    pub negotiated_frequency_khz: u16,
}

impl<I2C, D, VDD, RST> PhysicalLayer<I2C, D, VDD, RST>
where
    I2C: OptigaI2cBus,
    D: DelayNs,
    VDD: OutputPin,
    RST: OutputPin,
{
    /// Creates a new `PhysicalLayer` instance with default configuration.
    pub fn new(i2c: I2C, delay: D, vdd_pin: VDD, rst_pin: RST) -> Self {
        Self {
            i2c,
            delay,
            vdd_pin,
            rst_pin,
            slave_address: IFX_I2C_BASE_ADDR,
            negotiated_frame_size: MIN_FRAME_SIZE as u16,
            negotiated_frequency_khz: PL_DEFAULT_FREQUENCY_KHZ,
        }
    }

    /// Sets the runtime 7-bit slave address used for I2C transactions.
    #[inline]
    pub fn set_slave_address(&mut self, addr: u8) {
        self.slave_address = addr & 0x7F;
    }

    /// Writes data to a physical register with mandatory guard time and retry polling.
    pub fn write_register(&mut self, reg: PlRegister, content: &[u8]) -> Result<(), IfxI2cError> {
        let mut tx_buf = [0u8; 1 + MAX_FRAME_SIZE];
        if content.len() > MAX_FRAME_SIZE {
            return Err(IfxI2cError::MemoryInsufficient);
        }

        tx_buf[0] = reg as u8;
        tx_buf[1..1 + content.len()].copy_from_slice(content);
        let write_len = 1 + content.len();

        let mut retry_counter = PL_POLLING_MAX_CNT;
        loop {
            match self.i2c.write(self.slave_address, &tx_buf[..write_len]) {
                Ok(()) => {
                    self.delay.delay_us(PL_GUARD_TIME_INTERVAL_US);
                    return Ok(());
                }
                Err(_) => {
                    if retry_counter == 0 {
                        return Err(IfxI2cError::FatalError);
                    }
                    retry_counter -= 1;
                    self.delay.delay_us(PL_POLLING_INTERVAL_US);
                }
            }
        }
    }

    /// Reads data from a physical register using separate Write (Phase A) and Read (Phase B)
    /// transactions separated by the mandatory $50\ \mu\text{s}$ guard time.
    pub fn read_register(&mut self, reg: PlRegister, rx_buf: &mut [u8]) -> Result<(), IfxI2cError> {
        let mut retry_counter = PL_POLLING_MAX_CNT;

        // Phase A: Write register address
        let reg_byte = [reg as u8];
        loop {
            match self.i2c.write(self.slave_address, &reg_byte) {
                Ok(()) => {
                    self.delay.delay_us(PL_GUARD_TIME_INTERVAL_US);
                    break;
                }
                Err(_) => {
                    if retry_counter == 0 {
                        return Err(IfxI2cError::FatalError);
                    }
                    retry_counter -= 1;
                    self.delay.delay_us(PL_POLLING_INTERVAL_US);
                }
            }
        }

        // Phase B: Read register payload
        loop {
            match self.i2c.read(self.slave_address, rx_buf) {
                Ok(()) => {
                    self.delay.delay_us(PL_GUARD_TIME_INTERVAL_US);
                    return Ok(());
                }
                Err(_) => {
                    if retry_counter == 0 {
                        return Err(IfxI2cError::FatalError);
                    }
                    retry_counter -= 1;
                    self.delay.delay_us(PL_POLLING_INTERVAL_US);
                }
            }
        }
    }

    /// Executes Cold, Warm, or Soft reset sequence.
    pub fn reset(&mut self, reset_type: ResetType) -> Result<(), IfxI2cError> {
        match reset_type {
            ResetType::Cold => {
                let _ = self.vdd_pin.set_low();
                let _ = self.rst_pin.set_low();
                self.delay.delay_us(RESET_LOW_TIME_US);
                let _ = self.vdd_pin.set_high();
                let _ = self.rst_pin.set_high();
                self.delay.delay_us(STARTUP_TIME_US);
                Ok(())
            }
            ResetType::Warm => {
                let _ = self.rst_pin.set_low();
                self.delay.delay_us(RESET_LOW_TIME_US);
                let _ = self.rst_pin.set_high();
                self.delay.delay_us(STARTUP_TIME_US);
                Ok(())
            }
            ResetType::Soft => {
                // Check if soft reset is supported in I2C_STATE (0x82)
                let mut state_bytes = [0u8; 4];
                self.read_register(PlRegister::I2cState, &mut state_bytes)?;
                let status = I2cStateStatus(state_bytes);
                if !status.supports_soft_reset() {
                    return Err(IfxI2cError::ProtocolError);
                }

                // Write 0x0000 to SOFT_RESET register (0x88)
                self.write_register(PlRegister::SoftReset, &[0x00, 0x00])?;
                self.delay.delay_us(STARTUP_TIME_US);
                Ok(())
            }
        }
    }

    /// Negotiates I2C bus bitrate and maximum Data Link frame size.
    pub fn negotiate(
        &mut self,
        requested_frame_size: u16,
        requested_freq_khz: u16,
    ) -> Result<(), IfxI2cError> {
        // Step 1: Set master bitrate to default 100 kHz with retries
        self.set_bitrate_with_retry(PL_DEFAULT_FREQUENCY_KHZ)?;

        // Step 2: Read slave supported max SCL frequency from 0x84
        let mut freq_buf = [0u8; 4];
        self.read_register(PlRegister::MaxSclFrequ, &mut freq_buf)?;
        let mut slave_freq = u16::from_be_bytes([freq_buf[2], freq_buf[3]]);

        // Step 3: Switch mode if requested frequency crosses the 400 kHz SM/FM threshold
        if requested_freq_khz > PL_SM_FM_MAX_FREQUENCY_KHZ
            && slave_freq <= PL_SM_FM_MAX_FREQUENCY_KHZ
        {
            // Switch to FM+ (0x04)
            self.write_register(PlRegister::I2cMode, &[0x80, 0x04])?;
            self.read_register(PlRegister::MaxSclFrequ, &mut freq_buf)?;
            slave_freq = u16::from_be_bytes([freq_buf[2], freq_buf[3]]);
        } else if requested_freq_khz <= PL_SM_FM_MAX_FREQUENCY_KHZ
            && slave_freq > PL_SM_FM_MAX_FREQUENCY_KHZ
        {
            // Switch to SM/FM (0x03)
            self.write_register(PlRegister::I2cMode, &[0x80, 0x03])?;
            self.read_register(PlRegister::MaxSclFrequ, &mut freq_buf)?;
            slave_freq = u16::from_be_bytes([freq_buf[2], freq_buf[3]]);
        }

        // Step 4: Verify requested frequency does not exceed slave capability
        if requested_freq_khz > slave_freq {
            return Err(IfxI2cError::ProtocolError);
        }

        // Step 5: Switch master bitrate to negotiated frequency
        self.set_bitrate_with_retry(requested_freq_khz)?;
        self.negotiated_frequency_khz = requested_freq_khz;

        // Step 6: Negotiate frame size via 0x81 (DATA_REG_LEN)
        let clamped_req_size = requested_frame_size.clamp(MIN_FRAME_SIZE as u16, MAX_FRAME_SIZE as u16);
        self.write_register(PlRegister::DataRegLen, &clamped_req_size.to_be_bytes())?;

        let mut len_buf = [0u8; 2];
        self.read_register(PlRegister::DataRegLen, &mut len_buf)?;
        let slave_frame_len = u16::from_be_bytes([len_buf[0], len_buf[1]]);

        // Step 7: Verify agreed frame size
        if clamped_req_size >= slave_frame_len && slave_frame_len >= MIN_FRAME_SIZE as u16 {
            self.negotiated_frame_size = slave_frame_len;
            Ok(())
        } else {
            Err(IfxI2cError::ProtocolError)
        }
    }

    /// Sends a Data Link frame by directly writing to `PlRegister::Data` (`0x80`).
    #[inline]
    pub fn send_frame(&mut self, frame: &[u8]) -> Result<(), IfxI2cError> {
        self.write_register(PlRegister::Data, frame)
    }

    /// Polls `PlRegister::I2cState` (`0x82`) until a response frame is ready, then reads it from `0x80`.
    pub fn receive_frame<CLK: MonotonicClock>(
        &mut self,
        rx_buf: &mut [u8],
        clock: &CLK,
        frame_start_time_ms: u32,
        data_poll_timeout_ms: u32,
    ) -> Result<usize, IfxI2cError> {
        let mut state_bytes = [0u8; 4];
        loop {
            self.read_register(PlRegister::I2cState, &mut state_bytes)?;
            let status = I2cStateStatus(state_bytes);

            if status.is_response_ready() {
                let len = status.response_len() as usize;
                if len > 0 && len <= self.negotiated_frame_size as usize && len <= rx_buf.len() {
                    self.read_register(PlRegister::Data, &mut rx_buf[..len])?;
                    return Ok(len);
                }
            }

            let elapsed = clock.now_ms().wrapping_sub(frame_start_time_ms);
            if elapsed < data_poll_timeout_ms {
                self.delay.delay_us(PL_DATA_POLLING_INTERVAL_US);
            } else {
                return Err(IfxI2cError::ProtocolError);
            }
        }
    }

    /// Configures a volatile or persistent 7-bit slave address via `PlRegister::BaseAddr` (`0x83`).
    pub fn write_slave_address(&mut self, new_addr: u8, persistent: bool) -> Result<(), IfxI2cError> {
        let mode = if persistent { 0x80 } else { 0x00 };
        let addr_7bit = new_addr & 0x7F;
        self.write_register(PlRegister::BaseAddr, &[mode, addr_7bit])?;
        self.slave_address = addr_7bit;
        // 10 ms delay for internal NVM programming
        self.delay.delay_ms(10);
        Ok(())
    }

    fn set_bitrate_with_retry(&mut self, bitrate_khz: u16) -> Result<(), IfxI2cError> {
        let mut retry_counter = PL_POLLING_MAX_CNT;
        loop {
            match self.i2c.set_bitrate_khz(bitrate_khz) {
                Ok(()) => return Ok(()),
                Err(_) => {
                    if retry_counter == 0 {
                        return Err(IfxI2cError::FatalError);
                    }
                    retry_counter -= 1;
                    self.delay.delay_us(PL_POLLING_INTERVAL_US);
                }
            }
        }
    }
}
