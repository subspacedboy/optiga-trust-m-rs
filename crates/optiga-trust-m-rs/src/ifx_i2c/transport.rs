//! Transport Layer (`ifx_i2c::transport`) implementation.
//!
//! Segments large upper-layer payloads into Data Link frames, prepends Packet Control (`PCTR`)
//! headers, validates chaining transitions (`g_pctr_states_table`), and reassembles multi-fragment responses.

use crate::config::*;
use crate::error::IfxI2cError;
use crate::ifx_i2c::datalink::{DataLinkLayer, DlEvent};
use crate::ifx_i2c::headers::{ChainState, Pctr};
use crate::ifx_i2c::physical::PhysicalLayer;
use crate::pal::{MonotonicClock, OptigaI2cBus};
use embedded_hal::delay::DelayNs;
use embedded_hal::digital::OutputPin;

/// Transport Layer coordinator managing fragmentation and reassembly.
pub struct TransportLayer {
    fragment_buf: [u8; DL_MAX_PAYLOAD_SIZE],
    dl_rx_scratch: [u8; DL_MAX_PAYLOAD_SIZE],
}

impl Default for TransportLayer {
    fn default() -> Self {
        Self {
            fragment_buf: [0u8; DL_MAX_PAYLOAD_SIZE],
            dl_rx_scratch: [0u8; DL_MAX_PAYLOAD_SIZE],
        }
    }
}

impl TransportLayer {
    /// Creates a new `TransportLayer` instance.
    pub fn new() -> Self {
        Self::default()
    }

    /// Transceives a complete upper-layer packet (APDU or Presentation Layer frame) over the Data Link Layer.
    pub fn transceive<I2C, D, VDD, RST, CLK>(
        &mut self,
        pl: &mut PhysicalLayer<I2C, D, VDD, RST>,
        dl: &mut DataLinkLayer,
        clock: &CLK,
        tx_packet: &[u8],
        rx_buf: &mut [u8],
        has_presentation: bool,
    ) -> Result<usize, IfxI2cError>
    where
        I2C: OptigaI2cBus,
        D: DelayNs,
        VDD: OutputPin,
        RST: OutputPin,
        CLK: MonotonicClock,
    {
        let frame_size = pl.negotiated_frame_size as usize;
        let max_packet_length = frame_size
            .checked_sub(DL_HEADER_SIZE + TL_HEADER_SIZE)
            .ok_or(IfxI2cError::ProtocolError)?;

        // Phase 1: Transmit all fragments
        let mut offset = 0;
        let mut piggybacked_len = None;

        while offset < tx_packet.len() || tx_packet.is_empty() {
            let remaining = tx_packet.len() - offset;
            let chunk_len = core::cmp::min(remaining, max_packet_length);

            let chain = if offset == 0 && remaining <= max_packet_length {
                ChainState::No
            } else if offset == 0 && remaining > max_packet_length {
                ChainState::First
            } else if offset > 0 && remaining > max_packet_length {
                ChainState::Intermediate
            } else {
                ChainState::Last
            };

            let pctr = Pctr::new(has_presentation, chain);
            self.fragment_buf[0] = pctr.0;
            self.fragment_buf[1..1 + chunk_len].copy_from_slice(&tx_packet[offset..offset + chunk_len]);
            let total_frag_len = 1 + chunk_len;

            match dl.send_frame(pl, clock, &self.fragment_buf[..total_frag_len], &mut self.dl_rx_scratch)? {
                DlEvent::TxSuccess => {
                    // Fragment acknowledged by slave Control Frame
                }
                DlEvent::TxAndRxSuccess(rx_len) => {
                    // Piggybacked response received
                    if remaining > max_packet_length {
                        // Slave replied with data before all TX fragments were transmitted!
                        return Err(IfxI2cError::ProtocolError);
                    }
                    piggybacked_len = Some(rx_len);
                }
                DlEvent::RxSuccess(_) => {}
            }

            offset += chunk_len;
            if tx_packet.is_empty() {
                break;
            }
        }

        // Phase 2: Reassemble response fragments
        let mut previous_chaining = ChainState::No;
        let mut total_received = 0;
        let mut overflow_detected = false;
        let mut is_first_rx = true;

        loop {
            let rx_len = if let Some(len) = piggybacked_len.take() {
                len
            } else {
                dl.receive_frame(pl, clock, &mut self.dl_rx_scratch)?
            };

            if rx_len < 1 {
                return Err(IfxI2cError::ProtocolError);
            }

            let pctr = Pctr(self.dl_rx_scratch[0]);
            let chain = pctr.chain_state().map_err(|_| IfxI2cError::ProtocolError)?;

            // Presence bit check on incoming fragments
            if has_presentation {
                if matches!(chain, ChainState::No | ChainState::First) && !pctr.has_presentation() {
                    return Err(IfxI2cError::ProtocolError);
                }
            } else if pctr.has_presentation() {
                return Err(IfxI2cError::ProtocolError);
            }

            // Transition validation
            if is_first_rx {
                if !matches!(chain, ChainState::No | ChainState::First) {
                    return Err(IfxI2cError::ProtocolError);
                }
                is_first_rx = false;
            } else if !Pctr::is_valid_transition(previous_chaining, chain) {
                return Err(IfxI2cError::ProtocolError);
            }

            // Length verification on First and Intermediate fragments
            if matches!(chain, ChainState::First | ChainState::Intermediate)
                && rx_len != max_packet_length + 1
            {
                return Err(IfxI2cError::ProtocolError);
            }

            let payload_len = rx_len - 1;

            // Buffer capacity check & draining logic
            if total_received + payload_len > rx_buf.len() {
                overflow_detected = true;
                if matches!(chain, ChainState::No | ChainState::Last) {
                    return Err(IfxI2cError::MemoryInsufficient);
                }
                // If First or Intermediate: continue loop to drain remaining chained frames from slave
            } else if !overflow_detected {
                rx_buf[total_received..total_received + payload_len]
                    .copy_from_slice(&self.dl_rx_scratch[1..1 + payload_len]);
                total_received += payload_len;
            }

            previous_chaining = chain;

            if matches!(chain, ChainState::No | ChainState::Last) {
                if overflow_detected {
                    return Err(IfxI2cError::MemoryInsufficient);
                }
                return Ok(total_received);
            }
        }
    }
}
