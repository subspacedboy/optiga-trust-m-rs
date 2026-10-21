//! Data Link Layer (`ifx_i2c::datalink`) implementation.
//!
//! Provides error-free, sequence-checked frame delivery over the Physical Layer,
//! wrapping upper-layer packets with 5-byte framing envelopes (FCTR, LEN, CRC-16)
//! and executing 2-bit modulo-4 ARQ with ACK/NACK/RESYNC state tracking.

use crate::config::*;
use crate::error::IfxI2cError;
use crate::ifx_i2c::headers::{
    crc16_ccitt, Fctr, FrameType, SeqCtrl,
};
use crate::ifx_i2c::physical::PhysicalLayer;
use crate::pal::{MonotonicClock, OptigaI2cBus};
use embedded_hal::delay::DelayNs;
use embedded_hal::digital::OutputPin;

/// Event result from a Data Link Layer operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DlEvent {
    /// Transmit operation succeeded (slave returned an explicit Control Frame ACK).
    TxSuccess,
    /// Receive operation succeeded; payload size in bytes returned.
    RxSuccess(usize),
    /// Transmit and Receive succeeded in a single transaction via piggybacked response.
    TxAndRxSuccess(usize),
}

/// Data Link Layer coordinator holding sequence state and framing scratch buffers.
pub struct DataLinkLayer {
    pub tx_seq_nr: u8,
    pub rx_seq_nr: u8,
    pub resynced: bool,
    tx_frame_buffer: [u8; MAX_FRAME_SIZE],
    rx_frame_buffer: [u8; MAX_FRAME_SIZE],
}

impl Default for DataLinkLayer {
    fn default() -> Self {
        Self {
            tx_seq_nr: 3,
            rx_seq_nr: 3,
            resynced: false,
            tx_frame_buffer: [0u8; MAX_FRAME_SIZE],
            rx_frame_buffer: [0u8; MAX_FRAME_SIZE],
        }
    }
}

impl DataLinkLayer {
    /// Creates a new `DataLinkLayer` in idle state (`tx_seq_nr = 3, rx_seq_nr = 3`).
    pub fn new() -> Self {
        Self::default()
    }

    /// Resets sequence counters to initial values (`3`).
    pub fn reset(&mut self) {
        self.tx_seq_nr = 3;
        self.rx_seq_nr = 3;
        self.resynced = false;
    }

    /// Transmits a payload of up to 272 bytes with ARQ retransmission and RESYNC recovery.
    pub fn send_frame<I2C, D, VDD, RST, CLK>(
        &mut self,
        pl: &mut PhysicalLayer<I2C, D, VDD, RST>,
        clock: &CLK,
        payload: &[u8],
        rx_buf: &mut [u8],
    ) -> Result<DlEvent, IfxI2cError>
    where
        I2C: OptigaI2cBus,
        D: DelayNs,
        VDD: OutputPin,
        RST: OutputPin,
        CLK: MonotonicClock,
    {
        if payload.len() > DL_MAX_PAYLOAD_SIZE {
            return Err(IfxI2cError::MemoryInsufficient);
        }

        // Advance TX sequence number modulo 4
        self.tx_seq_nr = (self.tx_seq_nr + 1) & 0x03;
        self.resynced = false;

        // Construct Data Frame in internal tx_frame_buffer
        let fctr = Fctr::new(FrameType::Data, SeqCtrl::Ack, self.tx_seq_nr, self.rx_seq_nr);
        self.tx_frame_buffer[0] = fctr.0;
        let payload_len_be = (payload.len() as u16).to_be_bytes();
        self.tx_frame_buffer[1] = payload_len_be[0];
        self.tx_frame_buffer[2] = payload_len_be[1];
        self.tx_frame_buffer[3..3 + payload.len()].copy_from_slice(payload);

        let crc = crc16_ccitt(&self.tx_frame_buffer[..3 + payload.len()]);
        let crc_be = crc.to_be_bytes();
        self.tx_frame_buffer[3 + payload.len()] = crc_be[0];
        self.tx_frame_buffer[4 + payload.len()] = crc_be[1];

        let total_tx_len = 5 + payload.len();

        let mut retransmit_counter = 0;
        loop {
            // Step 1: Send frame via Physical Layer
            pl.send_frame(&self.tx_frame_buffer[..total_tx_len])?;

            // Step 2: Poll for immediate response from slave (10 ms timeout)
            let poll_start = clock.now_ms();
            match pl.receive_frame(&mut self.rx_frame_buffer, clock, poll_start, PL_TRANS_TIMEOUT_MS) {
                Ok(rx_len) => {
                    // Validate received frame
                    match self.parse_rx_frame(rx_len) {
                        Ok(FrameType::Control) => {
                            let resp_fctr = Fctr(self.rx_frame_buffer[0]);
                            match resp_fctr.seq_ctrl() {
                                SeqCtrl::Ack => {
                                    if resp_fctr.ack_nr() == self.tx_seq_nr {
                                        return Ok(DlEvent::TxSuccess);
                                    }
                                }
                                SeqCtrl::Nack => {
                                    // Slave NACKed our frame; trigger retransmit
                                }
                                _ => {}
                            }
                        }
                        Ok(FrameType::Data) => {
                            // Piggybacked Data Frame response!
                            let resp_fctr = Fctr(self.rx_frame_buffer[0]);
                            if resp_fctr.ack_nr() == self.tx_seq_nr {
                                let expected_rx = (self.rx_seq_nr + 1) & 0x03;
                                if resp_fctr.fr_nr() == expected_rx {
                                    self.rx_seq_nr = expected_rx;
                                    let data_len = rx_len - 5;
                                    if data_len > rx_buf.len() {
                                        return Err(IfxI2cError::MemoryInsufficient);
                                    }
                                    rx_buf[..data_len].copy_from_slice(&self.rx_frame_buffer[3..3 + data_len]);

                                    // Send ACK Control Frame back to slave
                                    self.send_control_frame(pl, SeqCtrl::Ack, self.rx_seq_nr)?;
                                    return Ok(DlEvent::TxAndRxSuccess(data_len));
                                }
                            }
                        }
                        Err(_) => {
                            // Frame corrupted or invalid; trigger retransmit
                        }
                    }
                }
                Err(_) => {
                    // Receive timeout or PL error
                }
            }

            // Retry or RESYNC
            retransmit_counter += 1;
            if retransmit_counter >= DL_TRANS_REPEAT {
                self.perform_resync(pl, clock)?;
                retransmit_counter = 0;
            }
        }
    }

    /// Receives a Data Link frame from the slave (up to 180s exit timeout).
    pub fn receive_frame<I2C, D, VDD, RST, CLK>(
        &mut self,
        pl: &mut PhysicalLayer<I2C, D, VDD, RST>,
        clock: &CLK,
        rx_buf: &mut [u8],
    ) -> Result<usize, IfxI2cError>
    where
        I2C: OptigaI2cBus,
        D: DelayNs,
        VDD: OutputPin,
        RST: OutputPin,
        CLK: MonotonicClock,
    {
        let start_time = clock.now_ms();
        let mut retransmit_counter = 0;

        loop {
            let elapsed = clock.now_ms().wrapping_sub(start_time);
            if elapsed >= TL_MAX_EXIT_TIMEOUT_MS {
                return Err(IfxI2cError::ProtocolError);
            }
            let remaining_ms = TL_MAX_EXIT_TIMEOUT_MS - elapsed;

            match pl.receive_frame(&mut self.rx_frame_buffer, clock, clock.now_ms(), remaining_ms) {
                Ok(rx_len) => {
                    match self.parse_rx_frame(rx_len) {
                        Ok(FrameType::Data) => {
                            let resp_fctr = Fctr(self.rx_frame_buffer[0]);
                            let expected_fr = (self.rx_seq_nr + 1) & 0x03;

                            if resp_fctr.fr_nr() == expected_fr {
                                // Valid next Data Frame
                                self.rx_seq_nr = expected_fr;
                                let data_len = rx_len - 5;
                                if data_len > rx_buf.len() {
                                    return Err(IfxI2cError::MemoryInsufficient);
                                }
                                rx_buf[..data_len].copy_from_slice(&self.rx_frame_buffer[3..3 + data_len]);

                                // Send ACK Control Frame back to slave
                                self.send_control_frame(pl, SeqCtrl::Ack, self.rx_seq_nr)?;
                                return Ok(data_len);
                            } else if resp_fctr.fr_nr() == self.rx_seq_nr {
                                // Duplicate frame from slave: send ACK again and continue listening
                                self.send_control_frame(pl, SeqCtrl::Ack, self.rx_seq_nr)?;
                                continue;
                            } else {
                                // Sequence mismatch: send NACK for expected sequence
                                self.send_control_frame(pl, SeqCtrl::Nack, expected_fr)?;
                                continue;
                            }
                        }
                        Ok(FrameType::Control) => {
                            let resp_fctr = Fctr(self.rx_frame_buffer[0]);
                            if resp_fctr.seq_ctrl() == SeqCtrl::Resync {
                                // Slave sent RESYNC
                                self.reset();
                                self.send_control_frame(pl, SeqCtrl::Resync, 0)?;
                            }
                            continue;
                        }
                        Err(_) => {
                            // CRC mismatch: send NACK for expected sequence
                            let expected_fr = (self.rx_seq_nr + 1) & 0x03;
                            self.send_control_frame(pl, SeqCtrl::Nack, expected_fr)?;
                            continue;
                        }
                    }
                }
                Err(_) => {
                    retransmit_counter += 1;
                    if retransmit_counter >= DL_TRANS_REPEAT {
                        self.perform_resync(pl, clock)?;
                        retransmit_counter = 0;
                    }
                }
            }
        }
    }

    /// Performs a Data Link RESYNC handshake with the slave.
    pub fn perform_resync<I2C, D, VDD, RST, CLK>(
        &mut self,
        pl: &mut PhysicalLayer<I2C, D, VDD, RST>,
        clock: &CLK,
    ) -> Result<(), IfxI2cError>
    where
        I2C: OptigaI2cBus,
        D: DelayNs,
        VDD: OutputPin,
        RST: OutputPin,
        CLK: MonotonicClock,
    {
        self.reset();
        // Send RESYNC CF
        self.send_control_frame(pl, SeqCtrl::Resync, 0)?;

        // Wait for RESYNC CF response
        let start = clock.now_ms();
        if let Ok(rx_len) = pl.receive_frame(&mut self.rx_frame_buffer, clock, start, PL_TRANS_TIMEOUT_MS) {
            if rx_len == 5 {
                let fctr = Fctr(self.rx_frame_buffer[0]);
                if fctr.frame_type() == FrameType::Control && fctr.seq_ctrl() == SeqCtrl::Resync {
                    self.resynced = true;
                    return Ok(());
                }
            }
        }

        self.resynced = true;
        Ok(())
    }

    /// Sends a 5-byte Control Frame (ACK, NACK, or RESYNC).
    pub fn send_control_frame<I2C, D, VDD, RST>(
        &mut self,
        pl: &mut PhysicalLayer<I2C, D, VDD, RST>,
        seq_ctrl: SeqCtrl,
        ack_nr: u8,
    ) -> Result<(), IfxI2cError>
    where
        I2C: OptigaI2cBus,
        D: DelayNs,
        VDD: OutputPin,
        RST: OutputPin,
    {
        let fctr = Fctr::new(FrameType::Control, seq_ctrl, 0, ack_nr);
        let mut cf = [0u8; 5];
        cf[0] = fctr.0;
        cf[1] = 0x00;
        cf[2] = 0x00;
        let crc = crc16_ccitt(&cf[..3]);
        let crc_be = crc.to_be_bytes();
        cf[3] = crc_be[0];
        cf[4] = crc_be[1];

        pl.send_frame(&cf)
    }

    fn parse_rx_frame(&self, rx_len: usize) -> Result<FrameType, IfxI2cError> {
        if rx_len < 5 {
            return Err(IfxI2cError::ProtocolError);
        }

        let expected_crc = u16::from_be_bytes([self.rx_frame_buffer[rx_len - 2], self.rx_frame_buffer[rx_len - 1]]);
        let actual_crc = crc16_ccitt(&self.rx_frame_buffer[..rx_len - 2]);
        if expected_crc != actual_crc {
            return Err(IfxI2cError::ProtocolError);
        }

        let fctr = Fctr(self.rx_frame_buffer[0]);
        let declared_len = u16::from_be_bytes([self.rx_frame_buffer[1], self.rx_frame_buffer[2]]) as usize;
        if declared_len != rx_len - 5 {
            return Err(IfxI2cError::ProtocolError);
        }

        Ok(fctr.frame_type())
    }
}
