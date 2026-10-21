//! Transport Layer (`ifx_i2c::transport`) implementation.
//!
//! Segments large upper-layer payloads into Data Link frames, prepends Packet Control (`PCTR`)
//! headers, validates chaining transitions (`g_pctr_states_table`), and reassembles multi-fragment responses.

use crate::config::*;
use crate::error::IfxI2cError;
use crate::ifx_i2c::datalink::{DataLinkLayer, DlEvent};
use crate::ifx_i2c::headers::{ChainState, Pctr};
use crate::ifx_i2c::physical::PhysicalLayer;
use crate::pal::{OptigaI2cBus, OptigaTimer};
use embedded_hal::digital::OutputPin;

/// Transport Layer coordinator managing fragmentation and reassembly.
pub struct TransportLayer {
    pub(crate) fragment_buf: [u8; DL_MAX_PAYLOAD_SIZE],
    pub(crate) dl_rx_scratch: [u8; DL_MAX_PAYLOAD_SIZE],
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

    /// Transceives a complete upper-layer packet in-place using a single shared buffer `io_buf`.
    ///
    /// On entry, `io_buf[..tx_len]` contains the packet to transmit.
    /// On return, `io_buf[..rx_len]` contains the reassembled response packet.
    pub fn transceive_in_place<I2C, T, VDD, RST>(
        &mut self,
        pl: &mut PhysicalLayer<I2C, T, VDD, RST>,
        dl: &mut DataLinkLayer,
        io_buf: &mut [u8],
        tx_len: usize,
        has_presentation: bool,
    ) -> Result<usize, IfxI2cError>
    where
        I2C: OptigaI2cBus,
        T: OptigaTimer,
        VDD: OutputPin,
        RST: OutputPin,
    {
        let frame_size = pl.negotiated_frame_size as usize;
        let max_packet_length = frame_size
            .checked_sub(DL_HEADER_SIZE + TL_HEADER_SIZE)
            .ok_or(IfxI2cError::ProtocolError)?;

        let mut chaining_error_count = 0u8;
        let mut master_chaining_error_count = 0u8;

        'tx_chain: loop {
            // Phase 1: Transmit all fragments from io_buf[..tx_len]
            let mut offset = 0;
            let mut piggybacked_len = None;

            while offset < tx_len || tx_len == 0 {
                let remaining = tx_len - offset;
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
                self.fragment_buf[1..1 + chunk_len]
                    .copy_from_slice(&io_buf[offset..offset + chunk_len]);
                let total_frag_len = 1 + chunk_len;

                match dl.send_frame(
                    pl,
                    &self.fragment_buf[..total_frag_len],
                    &mut self.dl_rx_scratch,
                )? {
                    DlEvent::TxSuccess => {}
                    DlEvent::TxAndRxSuccess(rx_len) => {
                        if rx_len == 1
                            && Pctr(self.dl_rx_scratch[0]).chain_state() == Ok(ChainState::Error)
                        {
                            if chaining_error_count < TL_MAX_CHAINING_ERROR_COUNT {
                                chaining_error_count += 1;
                                continue 'tx_chain;
                            }
                            return Err(IfxI2cError::ProtocolError);
                        }
                        if remaining > max_packet_length {
                            return Err(IfxI2cError::ProtocolError);
                        }
                        piggybacked_len = Some(rx_len);
                    }
                    DlEvent::RxSuccess(_) => {}
                }

                offset += chunk_len;
                if tx_len == 0 {
                    break;
                }
            }

            // Phase 2: Reassemble response fragments into io_buf
            let mut previous_chaining = ChainState::No;
            let mut total_received = 0;
            let mut overflow_detected = false;
            let mut is_first_rx = true;

            loop {
                let rx_len = if let Some(len) = piggybacked_len.take() {
                    len
                } else {
                    dl.receive_frame(pl, &mut self.dl_rx_scratch)?
                };

                if rx_len < 1 {
                    return Err(IfxI2cError::ProtocolError);
                }

                let pctr = Pctr(self.dl_rx_scratch[0]);
                let chain = match pctr.chain_state() {
                    Ok(c) => c,
                    Err(_) => return Err(IfxI2cError::ProtocolError),
                };

                if is_first_rx && rx_len == 1 && chain == ChainState::Error {
                    if chaining_error_count < TL_MAX_CHAINING_ERROR_COUNT {
                        chaining_error_count += 1;
                        continue 'tx_chain;
                    }
                    return Err(IfxI2cError::ProtocolError);
                }

                if has_presentation {
                    if matches!(chain, ChainState::No | ChainState::First) && !pctr.has_presentation() {
                        return Err(IfxI2cError::ProtocolError);
                    }
                } else if pctr.has_presentation() {
                    return Err(IfxI2cError::ProtocolError);
                }

                let valid_transition = if is_first_rx {
                    matches!(chain, ChainState::No | ChainState::First)
                } else {
                    Pctr::is_valid_transition(previous_chaining, chain)
                };
                let valid_frag_len = !matches!(chain, ChainState::First | ChainState::Intermediate)
                    || rx_len == max_packet_length + 1;

                if !valid_transition || !valid_frag_len {
                    if master_chaining_error_count < TL_MAX_CHAINING_ERROR_COUNT {
                        master_chaining_error_count += 1;
                        let err_pkt = [Pctr::new(false, ChainState::Error).0];
                        if let DlEvent::TxAndRxSuccess(new_rx_len) =
                            dl.send_frame(pl, &err_pkt, &mut self.dl_rx_scratch)?
                        {
                            piggybacked_len = Some(new_rx_len);
                        }
                        previous_chaining = ChainState::No;
                        total_received = 0;
                        overflow_detected = false;
                        is_first_rx = true;
                        continue;
                    }
                    return Err(IfxI2cError::ProtocolError);
                }
                is_first_rx = false;

                let payload_len = rx_len - 1;

                if total_received + payload_len > io_buf.len() {
                    overflow_detected = true;
                    if matches!(chain, ChainState::No | ChainState::Last) {
                        return Err(IfxI2cError::MemoryInsufficient);
                    }
                } else if !overflow_detected {
                    io_buf[total_received..total_received + payload_len]
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

    /// Transceives a complete upper-layer packet (APDU or Presentation Layer frame) over the Data Link Layer.
    pub fn transceive<I2C, T, VDD, RST>(
        &mut self,
        pl: &mut PhysicalLayer<I2C, T, VDD, RST>,
        dl: &mut DataLinkLayer,
        tx_packet: &[u8],
        rx_buf: &mut [u8],
        has_presentation: bool,
    ) -> Result<usize, IfxI2cError>
    where
        I2C: OptigaI2cBus,
        T: OptigaTimer,
        VDD: OutputPin,
        RST: OutputPin,
    {
        let frame_size = pl.negotiated_frame_size as usize;
        let max_packet_length = frame_size
            .checked_sub(DL_HEADER_SIZE + TL_HEADER_SIZE)
            .ok_or(IfxI2cError::ProtocolError)?;

        let mut chaining_error_count = 0u8;
        let mut master_chaining_error_count = 0u8;

        'tx_chain: loop {
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
                self.fragment_buf[1..1 + chunk_len]
                    .copy_from_slice(&tx_packet[offset..offset + chunk_len]);
                let total_frag_len = 1 + chunk_len;

                match dl.send_frame(
                    pl,
                    &self.fragment_buf[..total_frag_len],
                    &mut self.dl_rx_scratch,
                )? {
                    DlEvent::TxSuccess => {
                        // Fragment acknowledged by slave Control Frame
                    }
                    DlEvent::TxAndRxSuccess(rx_len) => {
                        // Check if slave replied with a Chaining Error (0x07)
                        if rx_len == 1
                            && Pctr(self.dl_rx_scratch[0]).chain_state() == Ok(ChainState::Error)
                        {
                            if chaining_error_count < TL_MAX_CHAINING_ERROR_COUNT {
                                chaining_error_count += 1;
                                continue 'tx_chain;
                            }
                            return Err(IfxI2cError::ProtocolError);
                        }
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
                    dl.receive_frame(pl, &mut self.dl_rx_scratch)?
                };

                if rx_len < 1 {
                    return Err(IfxI2cError::ProtocolError);
                }

                let pctr = Pctr(self.dl_rx_scratch[0]);
                let chain = match pctr.chain_state() {
                    Ok(c) => c,
                    Err(_) => return Err(IfxI2cError::ProtocolError),
                };

                // If slave sent Chaining Error (0x07) on first RX packet, resend TX chain once
                if is_first_rx && rx_len == 1 && chain == ChainState::Error {
                    if chaining_error_count < TL_MAX_CHAINING_ERROR_COUNT {
                        chaining_error_count += 1;
                        continue 'tx_chain;
                    }
                    return Err(IfxI2cError::ProtocolError);
                }

                // Presence bit check on incoming fragments
                if has_presentation {
                    if matches!(chain, ChainState::No | ChainState::First) && !pctr.has_presentation() {
                        return Err(IfxI2cError::ProtocolError);
                    }
                } else if pctr.has_presentation() {
                    return Err(IfxI2cError::ProtocolError);
                }

                // Transition & fragment length validation
                let valid_transition = if is_first_rx {
                    matches!(chain, ChainState::No | ChainState::First)
                } else {
                    Pctr::is_valid_transition(previous_chaining, chain)
                };
                let valid_frag_len = !matches!(chain, ChainState::First | ChainState::Intermediate)
                    || rx_len == max_packet_length + 1;

                if !valid_transition || !valid_frag_len {
                    if master_chaining_error_count < TL_MAX_CHAINING_ERROR_COUNT {
                        master_chaining_error_count += 1;
                        let err_pkt = [Pctr::new(false, ChainState::Error).0];
                        if let DlEvent::TxAndRxSuccess(new_rx_len) =
                            dl.send_frame(pl, &err_pkt, &mut self.dl_rx_scratch)?
                        {
                            piggybacked_len = Some(new_rx_len);
                        }
                        previous_chaining = ChainState::No;
                        total_received = 0;
                        overflow_detected = false;
                        is_first_rx = true;
                        continue;
                    }
                    return Err(IfxI2cError::ProtocolError);
                }
                is_first_rx = false;

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
}
