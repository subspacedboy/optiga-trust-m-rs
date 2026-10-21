//! Native `embedded-hal-async` driver support (`asynch`).
//!
//! Provides non-blocking `async`/`.await` equivalents of the 4-layer `ifx_i2c` stack,
//! `OptigaCmd`, `OptigaUtil`, `OptigaCrypt`, `OptigaBuilder`, and `OptigaTrustM`.
//! All pure framing, CRC-16, TLV, and cryptographic record logic is shared directly
//! with the synchronous driver without heap allocations or `unsafe` code.

use crate::cmd::opcodes;
use crate::cmd::tlv::{TlvReader, TlvWriter};
use crate::cmd::types::{EccCurve, KdfAlg, KeyUsage, Oid, RngType, SessionSlot};
use crate::cmd::OPTIGA_CMD_CLEAR_LAST_ERROR;
use crate::config::*;
use crate::crypt::ecc_r_s_padding_check;
use crate::error::{DeviceError, IfxI2cError, OptigaError};
use crate::ifx_i2c::datalink::DlEvent;
use crate::ifx_i2c::headers::{
     crc16_ccitt, ChainState, Fctr, FrameType, I2cStateStatus, Pctr, PlRegister, ProtectionConfig,
    ProtectionLevel, ResetType, Sctr, SeqCtrl,
};
use crate::ifx_i2c::presentation::RxRecordOutcome;
pub use crate::ifx_i2c::{DataLinkLayer, PresentationLayer, TransportLayer};
use crate::pal::rust_crypto::RustCryptoBackend;
use crate::pal::{
    AsyncOptigaI2cBus, AsyncOptigaTimer, Datastore, DatastoreId, HostCrypto, NoDatastore, NoPin,
};
use embedded_hal::digital::OutputPin;
use zeroize::Zeroize;

/// Asynchronous Physical Layer driver managing raw I2C register communication and reset sequences.
pub struct PhysicalLayer<I2C, T, VDD = NoPin, RST = NoPin> {
    pub i2c: I2C,
    pub delay: T,
    pub vdd_pin: VDD,
    pub rst_pin: RST,
    pub slave_address: u8,
    pub configured_base_address: u8,
    pub negotiated_frame_size: u16,
    pub negotiated_frequency_khz: u16,
}

impl<I2C, T, VDD, RST> PhysicalLayer<I2C, T, VDD, RST>
where
    I2C: AsyncOptigaI2cBus,
    T: AsyncOptigaTimer,
    VDD: OutputPin,
    RST: OutputPin,
{
    /// Creates a new asynchronous `PhysicalLayer` instance with default configuration.
    pub fn new(i2c: I2C, delay: T, vdd_pin: VDD, rst_pin: RST) -> Self {
        Self {
            i2c,
            delay,
            vdd_pin,
            rst_pin,
            slave_address: IFX_I2C_BASE_ADDR,
            configured_base_address: IFX_I2C_BASE_ADDR,
            negotiated_frame_size: MIN_FRAME_SIZE as u16,
            negotiated_frequency_khz: PL_DEFAULT_FREQUENCY_KHZ,
        }
    }

    /// Sets the runtime and base 7-bit slave address used for I2C transactions.
    #[inline]
    pub fn set_slave_address(&mut self, addr: u8) {
        let addr_7bit = addr & 0x7F;
        self.slave_address = addr_7bit;
        self.configured_base_address = addr_7bit;
    }

    /// Writes data to a physical register with mandatory guard time and non-blocking retry polling.
    pub async fn write_register(
        &mut self,
        reg: PlRegister,
        content: &[u8],
    ) -> Result<(), IfxI2cError> {
        let mut tx_buf = [0u8; 1 + MAX_FRAME_SIZE];
        if content.len() > MAX_FRAME_SIZE {
            return Err(IfxI2cError::MemoryInsufficient);
        }

        tx_buf[0] = reg as u8;
        tx_buf[1..1 + content.len()].copy_from_slice(content);
        let write_len = 1 + content.len();

        let mut retry_counter = PL_POLLING_MAX_CNT;
        loop {
            match self.i2c.write(self.slave_address, &tx_buf[..write_len]).await {
                Ok(()) => {
                    self.delay.delay_us(PL_GUARD_TIME_INTERVAL_US).await;
                    return Ok(());
                }
                Err(_) => {
                    if retry_counter == 0 {
                        return Err(IfxI2cError::FatalError);
                    }
                    retry_counter -= 1;
                    self.delay.delay_us(PL_POLLING_INTERVAL_US).await;
                }
            }
        }
    }

    /// Reads data from a physical register using separate Write (Phase A) and Read (Phase B)
    /// transactions separated by the mandatory $50\ \mu\text{s}$ guard time.
    pub async fn read_register(
        &mut self,
        reg: PlRegister,
        rx_buf: &mut [u8],
    ) -> Result<(), IfxI2cError> {
        let mut retry_counter = PL_POLLING_MAX_CNT;

        // Phase A: Write register address
        let reg_byte = [reg as u8];
        loop {
            match self.i2c.write(self.slave_address, &reg_byte).await {
                Ok(()) => {
                    self.delay.delay_us(PL_GUARD_TIME_INTERVAL_US).await;
                    break;
                }
                Err(_) => {
                    if retry_counter == 0 {
                        return Err(IfxI2cError::FatalError);
                    }
                    retry_counter -= 1;
                    self.delay.delay_us(PL_POLLING_INTERVAL_US).await;
                }
            }
        }

        // Phase B: Read register payload
        loop {
            match self.i2c.read(self.slave_address, rx_buf).await {
                Ok(()) => {
                    self.delay.delay_us(PL_GUARD_TIME_INTERVAL_US).await;
                    return Ok(());
                }
                Err(_) => {
                    if retry_counter == 0 {
                        return Err(IfxI2cError::FatalError);
                    }
                    retry_counter -= 1;
                    self.delay.delay_us(PL_POLLING_INTERVAL_US).await;
                }
            }
        }
    }

    /// Executes Cold, Warm, or Soft reset sequence asynchronously.
    pub async fn reset(&mut self, reset_type: ResetType) -> Result<(), IfxI2cError> {
        match reset_type {
            ResetType::Cold => {
                let _ = self.vdd_pin.set_low();
                let _ = self.rst_pin.set_low();
                self.delay.delay_us(RESET_LOW_TIME_US).await;
                let _ = self.vdd_pin.set_high();
                let _ = self.rst_pin.set_high();
                self.slave_address = self.configured_base_address;
                self.delay.delay_us(STARTUP_TIME_US).await;
                Ok(())
            }
            ResetType::Warm => {
                let _ = self.rst_pin.set_low();
                self.delay.delay_us(RESET_LOW_TIME_US).await;
                let _ = self.rst_pin.set_high();
                self.slave_address = self.configured_base_address;
                self.delay.delay_us(STARTUP_TIME_US).await;
                Ok(())
            }
            ResetType::Soft => {
                let mut state_bytes = [0u8; 4];
                self.read_register(PlRegister::I2cState, &mut state_bytes)
                    .await?;
                let status = I2cStateStatus(state_bytes);
                if !status.supports_soft_reset() {
                    return Err(IfxI2cError::ProtocolError);
                }

                self.write_register(PlRegister::SoftReset, &[0x00, 0x00])
                    .await?;
                self.slave_address = self.configured_base_address;
                self.delay.delay_us(STARTUP_TIME_US).await;
                Ok(())
            }
        }
    }

    /// Negotiates I2C bus bitrate and maximum Data Link frame size asynchronously.
    pub async fn negotiate(
        &mut self,
        requested_frame_size: u16,
        requested_freq_khz: u16,
    ) -> Result<(), IfxI2cError> {
        self.set_bitrate_with_retry(PL_DEFAULT_FREQUENCY_KHZ).await?;

        let mut freq_buf = [0u8; 4];
        self.read_register(PlRegister::MaxSclFrequ, &mut freq_buf)
            .await?;
        let mut slave_freq = u16::from_be_bytes([freq_buf[2], freq_buf[3]]);

        if requested_freq_khz > PL_SM_FM_MAX_FREQUENCY_KHZ
            && slave_freq <= PL_SM_FM_MAX_FREQUENCY_KHZ
        {
            self.write_register(PlRegister::I2cMode, &[0x80, 0x04])
                .await?;
            self.read_register(PlRegister::MaxSclFrequ, &mut freq_buf)
                .await?;
            slave_freq = u16::from_be_bytes([freq_buf[2], freq_buf[3]]);
        } else if requested_freq_khz <= PL_SM_FM_MAX_FREQUENCY_KHZ
            && slave_freq > PL_SM_FM_MAX_FREQUENCY_KHZ
        {
            self.write_register(PlRegister::I2cMode, &[0x80, 0x03])
                .await?;
            self.read_register(PlRegister::MaxSclFrequ, &mut freq_buf)
                .await?;
            slave_freq = u16::from_be_bytes([freq_buf[2], freq_buf[3]]);
        }

        if requested_freq_khz > slave_freq {
            return Err(IfxI2cError::ProtocolError);
        }

        self.set_bitrate_with_retry(requested_freq_khz).await?;
        self.negotiated_frequency_khz = requested_freq_khz;

        let clamped_req_size =
            requested_frame_size.clamp(MIN_FRAME_SIZE as u16, MAX_FRAME_SIZE as u16);
        self.write_register(PlRegister::DataRegLen, &clamped_req_size.to_be_bytes())
            .await?;

        let mut len_buf = [0u8; 2];
        self.read_register(PlRegister::DataRegLen, &mut len_buf)
            .await?;
        let slave_frame_len = u16::from_be_bytes([len_buf[0], len_buf[1]]);

        if clamped_req_size >= slave_frame_len && slave_frame_len >= MIN_FRAME_SIZE as u16 {
            self.negotiated_frame_size = slave_frame_len;
            Ok(())
        } else {
            Err(IfxI2cError::ProtocolError)
        }
    }

    /// Sends a Data Link frame by directly writing to `PlRegister::Data` (`0x80`).
    #[inline]
    pub async fn send_frame(&mut self, frame: &[u8]) -> Result<(), IfxI2cError> {
        self.write_register(PlRegister::Data, frame).await
    }

    /// Polls `PlRegister::I2cState` (`0x82`) until a response frame is ready, then reads it from `0x80`.
    pub async fn receive_frame(
        &mut self,
        rx_buf: &mut [u8],
        frame_start_time_ms: u32,
        data_poll_timeout_ms: u32,
    ) -> Result<usize, IfxI2cError> {
        let mut state_bytes = [0u8; 4];
        loop {
            self.read_register(PlRegister::I2cState, &mut state_bytes)
                .await?;
            let status = I2cStateStatus(state_bytes);

            if status.is_response_ready() {
                let len = status.response_len() as usize;
                if len > 0 && len <= self.negotiated_frame_size as usize && len <= rx_buf.len() {
                    self.read_register(PlRegister::Data, &mut rx_buf[..len])
                        .await?;
                    return Ok(len);
                }
            }

            let elapsed = self.delay.now_ms().wrapping_sub(frame_start_time_ms);
            if elapsed < data_poll_timeout_ms {
                self.delay.delay_us(PL_DATA_POLLING_INTERVAL_US).await;
            } else {
                return Err(IfxI2cError::ProtocolError);
            }
        }
    }

    /// Configures a volatile or persistent 7-bit slave address via `PlRegister::BaseAddr` (`0x83`).
    pub async fn write_slave_address(
        &mut self,
        new_addr: u8,
        persistent: bool,
    ) -> Result<(), IfxI2cError> {
        let mode = if persistent { 0x80 } else { 0x00 };
        let addr_7bit = new_addr & 0x7F;
        self.write_register(PlRegister::BaseAddr, &[mode, addr_7bit])
            .await?;
        self.slave_address = addr_7bit;
        if persistent {
            self.configured_base_address = addr_7bit;
        }
        self.delay.delay_ms(10).await;
        Ok(())
    }

    async fn set_bitrate_with_retry(&mut self, bitrate_khz: u16) -> Result<(), IfxI2cError> {
        let mut retry_counter = PL_POLLING_MAX_CNT;
        loop {
            match self.i2c.set_bitrate_khz(bitrate_khz).await {
                Ok(()) => return Ok(()),
                Err(_) => {
                    if retry_counter == 0 {
                        return Err(IfxI2cError::FatalError);
                    }
                    retry_counter -= 1;
                    self.delay.delay_us(PL_POLLING_INTERVAL_US).await;
                }
            }
        }
    }
}

impl DataLinkLayer {
    /// Asynchronously transmits a payload of up to 272 bytes with ARQ retransmission and RESYNC recovery.
    pub async fn send_frame_async<I2C, T, VDD, RST>(
        &mut self,
        pl: &mut PhysicalLayer<I2C, T, VDD, RST>,
        payload: &[u8],
        rx_buf: &mut [u8],
    ) -> Result<DlEvent, IfxI2cError>
    where
        I2C: AsyncOptigaI2cBus,
        T: AsyncOptigaTimer,
        VDD: OutputPin,
        RST: OutputPin,
    {
        if payload.len() > DL_MAX_PAYLOAD_SIZE {
            return Err(IfxI2cError::MemoryInsufficient);
        }

        self.tx_seq_nr = (self.tx_seq_nr + 1) & 0x03;
        self.resynced = false;
        let mut already_resynced = false;

        let payload_len_be = (payload.len() as u16).to_be_bytes();
        self.tx_frame_buffer[1] = payload_len_be[0];
        self.tx_frame_buffer[2] = payload_len_be[1];
        self.tx_frame_buffer[3..3 + payload.len()].copy_from_slice(payload);
        let total_tx_len = 5 + payload.len();

        let mut retransmit_counter = 0;
        loop {
            if self.resynced {
                self.tx_seq_nr = (self.tx_seq_nr + 1) & 0x03;
                self.resynced = false;
            }

            let fctr = Fctr::new(FrameType::Data, SeqCtrl::Ack, self.tx_seq_nr, self.rx_seq_nr);
            self.tx_frame_buffer[0] = fctr.0;
            let crc = crc16_ccitt(&self.tx_frame_buffer[..3 + payload.len()]).to_be_bytes();
            self.tx_frame_buffer[3 + payload.len()] = crc[0];
            self.tx_frame_buffer[4 + payload.len()] = crc[1];

            pl.send_frame(&self.tx_frame_buffer[..total_tx_len]).await?;

            'wait_ack: loop {
                let poll_start = pl.delay.now_ms();
                match pl
                    .receive_frame(&mut self.rx_frame_buffer, poll_start, PL_TRANS_TIMEOUT_MS)
                    .await
                {
                    Ok(rx_len) => match self.parse_rx_frame(rx_len) {
                        Ok(FrameType::Control) => {
                            let resp_fctr = Fctr(self.rx_frame_buffer[0]);
                            if resp_fctr.seq_ctrl() == SeqCtrl::Ack
                                && resp_fctr.ack_nr() == self.tx_seq_nr
                            {
                                return Ok(DlEvent::TxSuccess);
                            }
                            break 'wait_ack;
                        }
                        Ok(FrameType::Data) => {
                            let resp_fctr = Fctr(self.rx_frame_buffer[0]);
                            let expected_rx = (self.rx_seq_nr + 1) & 0x03;
                            if resp_fctr.ack_nr() == self.tx_seq_nr
                                && resp_fctr.seq_ctrl() == SeqCtrl::Ack
                            {
                                if resp_fctr.fr_nr() == expected_rx {
                                    self.rx_seq_nr = expected_rx;
                                    let data_len = rx_len - 5;
                                    if data_len > rx_buf.len() {
                                        return Err(IfxI2cError::MemoryInsufficient);
                                    }
                                    rx_buf[..data_len].copy_from_slice(
                                        &self.rx_frame_buffer[3..3 + data_len],
                                    );
                                    self.send_control_frame_async(pl, SeqCtrl::Ack, self.rx_seq_nr)
                                        .await?;
                                    return Ok(DlEvent::TxAndRxSuccess(data_len));
                                } else if resp_fctr.fr_nr() == self.rx_seq_nr {
                                    self.send_control_frame_async(pl, SeqCtrl::Ack, self.rx_seq_nr)
                                        .await?;
                                    continue 'wait_ack;
                                } else {
                                    self.send_control_frame_async(pl, SeqCtrl::Nack, expected_rx)
                                        .await?;
                                    continue 'wait_ack;
                                }
                            }
                            break 'wait_ack;
                        }
                        Err(_) => {
                            if rx_len > 5
                                && Fctr(self.rx_frame_buffer[0]).frame_type() == FrameType::Data
                            {
                                retransmit_counter += 1;
                                if retransmit_counter >= DL_TRANS_REPEAT {
                                    break 'wait_ack;
                                }
                                let expected_rx = (self.rx_seq_nr + 1) & 0x03;
                                self.send_control_frame_async(pl, SeqCtrl::Nack, expected_rx)
                                    .await?;
                                continue 'wait_ack;
                            }
                            break 'wait_ack;
                        }
                    },
                    Err(_) => break 'wait_ack,
                }
            }

            retransmit_counter += 1;
            if retransmit_counter >= DL_TRANS_REPEAT {
                if already_resynced {
                    return Err(IfxI2cError::ProtocolError);
                }
                self.perform_resync_async(pl).await?;
                already_resynced = true;
                retransmit_counter = 0;
            }
        }
    }

    /// Asynchronously receives a Data Link frame from the slave (up to 180s exit timeout).
    pub async fn receive_frame_async<I2C, T, VDD, RST>(
        &mut self,
        pl: &mut PhysicalLayer<I2C, T, VDD, RST>,
        rx_buf: &mut [u8],
    ) -> Result<usize, IfxI2cError>
    where
        I2C: AsyncOptigaI2cBus,
        T: AsyncOptigaTimer,
        VDD: OutputPin,
        RST: OutputPin,
    {
        let start_time = pl.delay.now_ms();
        let mut retransmit_counter = 0;
        let mut already_resynced = false;

        loop {
            let now = pl.delay.now_ms();
            let elapsed = now.wrapping_sub(start_time);
            if elapsed >= TL_MAX_EXIT_TIMEOUT_MS {
                return Err(IfxI2cError::ProtocolError);
            }
            let remaining_ms = TL_MAX_EXIT_TIMEOUT_MS - elapsed;

            match pl
                .receive_frame(&mut self.rx_frame_buffer, now, remaining_ms)
                .await
            {
                Ok(rx_len) => match self.parse_rx_frame(rx_len) {
                    Ok(FrameType::Data) => {
                        let resp_fctr = Fctr(self.rx_frame_buffer[0]);
                        let expected_fr = (self.rx_seq_nr + 1) & 0x03;

                        if resp_fctr.fr_nr() == expected_fr {
                            self.rx_seq_nr = expected_fr;
                            let data_len = rx_len - 5;
                            if data_len > rx_buf.len() {
                                return Err(IfxI2cError::MemoryInsufficient);
                            }
                            rx_buf[..data_len]
                                .copy_from_slice(&self.rx_frame_buffer[3..3 + data_len]);
                            self.send_control_frame_async(pl, SeqCtrl::Ack, self.rx_seq_nr)
                                .await?;
                            return Ok(data_len);
                        } else if resp_fctr.fr_nr() == self.rx_seq_nr {
                            self.send_control_frame_async(pl, SeqCtrl::Ack, self.rx_seq_nr)
                                .await?;
                            continue;
                        } else {
                            self.send_control_frame_async(pl, SeqCtrl::Nack, expected_fr)
                                .await?;
                            continue;
                        }
                    }
                    Ok(FrameType::Control) => {
                        let resp_fctr = Fctr(self.rx_frame_buffer[0]);
                        if resp_fctr.seq_ctrl() == SeqCtrl::Resync {
                            self.reset();
                            self.send_control_frame_async(pl, SeqCtrl::Resync, 0).await?;
                        }
                        continue;
                    }
                    Err(_) => {
                        let expected_fr = (self.rx_seq_nr + 1) & 0x03;
                        self.send_control_frame_async(pl, SeqCtrl::Nack, expected_fr)
                            .await?;
                        continue;
                    }
                },
                Err(_) => {
                    retransmit_counter += 1;
                    if retransmit_counter >= DL_TRANS_REPEAT {
                        if already_resynced {
                            return Err(IfxI2cError::ProtocolError);
                        }
                        self.perform_resync_async(pl).await?;
                        already_resynced = true;
                        retransmit_counter = 0;
                    }
                }
            }
        }
    }

    /// Asynchronously performs a Data Link RESYNC handshake with the slave.
    pub async fn perform_resync_async<I2C, T, VDD, RST>(
        &mut self,
        pl: &mut PhysicalLayer<I2C, T, VDD, RST>,
    ) -> Result<(), IfxI2cError>
    where
        I2C: AsyncOptigaI2cBus,
        T: AsyncOptigaTimer,
        VDD: OutputPin,
        RST: OutputPin,
    {
        self.reset();
        self.send_control_frame_async(pl, SeqCtrl::Resync, 0).await?;

        let start = pl.delay.now_ms();
        if let Ok(rx_len) = pl
            .receive_frame(&mut self.rx_frame_buffer, start, PL_TRANS_TIMEOUT_MS)
            .await
        {
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

    /// Asynchronously sends a 5-byte Control Frame (ACK, NACK, or RESYNC).
    pub async fn send_control_frame_async<I2C, T, VDD, RST>(
        &mut self,
        pl: &mut PhysicalLayer<I2C, T, VDD, RST>,
        seq_ctrl: SeqCtrl,
        ack_nr: u8,
    ) -> Result<(), IfxI2cError>
    where
        I2C: AsyncOptigaI2cBus,
        T: AsyncOptigaTimer,
        VDD: OutputPin,
        RST: OutputPin,
    {
        let cf = Self::encode_control_frame(seq_ctrl, ack_nr);
        pl.send_frame(&cf).await
    }
}

impl TransportLayer {
    /// Asynchronously transceives a complete upper-layer packet in-place using `io_buf`.
    pub async fn transceive_in_place_async<I2C, T, VDD, RST>(
        &mut self,
        pl: &mut PhysicalLayer<I2C, T, VDD, RST>,
        dl: &mut DataLinkLayer,
        io_buf: &mut [u8],
        tx_len: usize,
        has_presentation: bool,
    ) -> Result<usize, IfxI2cError>
    where
        I2C: AsyncOptigaI2cBus,
        T: AsyncOptigaTimer,
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

                match dl
                    .send_frame_async(
                        pl,
                        &self.fragment_buf[..total_frag_len],
                        &mut self.dl_rx_scratch,
                    )
                    .await?
                {
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

            let mut previous_chaining = ChainState::No;
            let mut total_received = 0;
            let mut overflow_detected = false;
            let mut is_first_rx = true;

            loop {
                let rx_len = if let Some(len) = piggybacked_len.take() {
                    len
                } else {
                    dl.receive_frame_async(pl, &mut self.dl_rx_scratch).await?
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
                    if matches!(chain, ChainState::No | ChainState::First)
                        && !pctr.has_presentation()
                    {
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
                        if let DlEvent::TxAndRxSuccess(new_rx_len) = dl
                            .send_frame_async(pl, &err_pkt, &mut self.dl_rx_scratch)
                            .await?
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

    /// Asynchronously transceives a complete upper-layer packet over the Data Link Layer.
    pub async fn transceive_async<I2C, T, VDD, RST>(
        &mut self,
        pl: &mut PhysicalLayer<I2C, T, VDD, RST>,
        dl: &mut DataLinkLayer,
        tx_packet: &[u8],
        rx_buf: &mut [u8],
        has_presentation: bool,
    ) -> Result<usize, IfxI2cError>
    where
        I2C: AsyncOptigaI2cBus,
        T: AsyncOptigaTimer,
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

                match dl
                    .send_frame_async(
                        pl,
                        &self.fragment_buf[..total_frag_len],
                        &mut self.dl_rx_scratch,
                    )
                    .await?
                {
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
                if tx_packet.is_empty() {
                    break;
                }
            }

            let mut previous_chaining = ChainState::No;
            let mut total_received = 0;
            let mut overflow_detected = false;
            let mut is_first_rx = true;

            loop {
                let rx_len = if let Some(len) = piggybacked_len.take() {
                    len
                } else {
                    dl.receive_frame_async(pl, &mut self.dl_rx_scratch).await?
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
                    if matches!(chain, ChainState::No | ChainState::First)
                        && !pctr.has_presentation()
                    {
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
                        if let DlEvent::TxAndRxSuccess(new_rx_len) = dl
                            .send_frame_async(pl, &err_pkt, &mut self.dl_rx_scratch)
                            .await?
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

                if total_received + payload_len > rx_buf.len() {
                    overflow_detected = true;
                    if matches!(chain, ChainState::No | ChainState::Last) {
                        return Err(IfxI2cError::MemoryInsufficient);
                    }
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

impl<CRYPTO, DS> PresentationLayer<CRYPTO, DS>
where
    CRYPTO: HostCrypto,
    DS: Datastore,
{
    /// Asynchronously performs the 4-step TLS 1.2 PRF SHA-256 mutual handshake with the OPTIGA slave.
    pub async fn do_handshake_async<I2C, T, VDD, RST>(
        &mut self,
        pl: &mut PhysicalLayer<I2C, T, VDD, RST>,
        dl: &mut DataLinkLayer,
        tl: &mut TransportLayer,
    ) -> Result<(), IfxI2cError>
    where
        I2C: AsyncOptigaI2cBus,
        T: AsyncOptigaTimer,
        VDD: OutputPin,
        RST: OutputPin,
    {
        let mut secret = [0u8; 64];
        let secret_len = self.prepare_handshake(&mut secret)?;

        let master_hello = [0x00, 0x01];
        let rx_len = match tl
            .transceive_async(pl, dl, &master_hello, &mut self.record_buf, true)
            .await
        {
            Ok(len) => len,
            Err(e) => {
                secret.zeroize();
                return Err(e);
            }
        };

        let mut slave_random = [0u8; 32];
        let tx_finished = self.process_slave_hello_and_build_master_finished(
            rx_len,
            &mut secret,
            secret_len,
            &mut slave_random,
        )?;

        let rx_len = tl
            .transceive_async(pl, dl, &tx_finished, &mut self.record_buf, true)
            .await?;
        self.verify_slave_finished(rx_len, &slave_random)
    }

    /// Asynchronously transceives an APDU command payload in-place using `apdu_buf[..tx_len]` as input
    /// and writing the response into `apdu_buf[..rx_len]`.
    pub async fn transceive_in_place_async<I2C, T, VDD, RST>(
        &mut self,
        pl: &mut PhysicalLayer<I2C, T, VDD, RST>,
        dl: &mut DataLinkLayer,
        tl: &mut TransportLayer,
        apdu_buf: &mut [u8],
        tx_len: usize,
        protection: ProtectionConfig,
    ) -> Result<usize, IfxI2cError>
    where
        I2C: AsyncOptigaI2cBus,
        T: AsyncOptigaTimer,
        VDD: OutputPin,
        RST: OutputPin,
    {
        if tx_len > OPTIGA_MAX_COMMS_BUFFER_SIZE || tx_len > apdu_buf.len() {
            return Err(IfxI2cError::MemoryInsufficient);
        }

        if self.requires_handshake(protection) {
            self.do_handshake_async(pl, dl, tl).await?;
        }

        let sctr = Sctr::new_record(protection.level);
        self.saved_sctr = sctr.0;

        let mut data_retransmit_counter = 0;
        let mut decryption_failure_counter = 0;

        loop {
            let total_tx_len =
                self.encode_tx_record(&apdu_buf[..tx_len], sctr, protection.level)?;

            let mut rx_raw_len = tl
                .transceive_in_place_async(pl, dl, &mut self.record_buf, total_tx_len, true)
                .await?;

            loop {
                match self.decode_rx_record(
                    rx_raw_len,
                    apdu_buf,
                    protection.level,
                    &mut data_retransmit_counter,
                    &mut decryption_failure_counter,
                )? {
                    RxRecordOutcome::Success(plain_len) => return Ok(plain_len),
                    RxRecordOutcome::RetryMasterTx => break,
                    RxRecordOutcome::SendIntegrityAlert => {
                        let alert = [Sctr::INTEGRITY_VIOLATED_ALERT.0];
                        rx_raw_len = tl
                            .transceive_async(pl, dl, &alert, &mut self.record_buf, true)
                            .await?;
                    }
                }
            }
        }
    }

    /// Asynchronously transceives an APDU command payload under the requested protection level.
    pub async fn transceive_async<I2C, T, VDD, RST>(
        &mut self,
        pl: &mut PhysicalLayer<I2C, T, VDD, RST>,
        dl: &mut DataLinkLayer,
        tl: &mut TransportLayer,
        tx_payload: &[u8],
        rx_payload: &mut [u8],
        protection: ProtectionConfig,
    ) -> Result<usize, IfxI2cError>
    where
        I2C: AsyncOptigaI2cBus,
        T: AsyncOptigaTimer,
        VDD: OutputPin,
        RST: OutputPin,
    {
        if tx_payload.len() > OPTIGA_MAX_COMMS_BUFFER_SIZE {
            return Err(IfxI2cError::MemoryInsufficient);
        }

        if self.requires_handshake(protection) {
            self.do_handshake_async(pl, dl, tl).await?;
        }

        let sctr = Sctr::new_record(protection.level);
        self.saved_sctr = sctr.0;

        let mut data_retransmit_counter = 0;
        let mut decryption_failure_counter = 0;

        loop {
            let total_tx_len = self.encode_tx_record(tx_payload, sctr, protection.level)?;

            let mut rx_raw_len = tl
                .transceive_in_place_async(pl, dl, &mut self.record_buf, total_tx_len, true)
                .await?;

            loop {
                match self.decode_rx_record(
                    rx_raw_len,
                    rx_payload,
                    protection.level,
                    &mut data_retransmit_counter,
                    &mut decryption_failure_counter,
                )? {
                    RxRecordOutcome::Success(plain_len) => return Ok(plain_len),
                    RxRecordOutcome::RetryMasterTx => break,
                    RxRecordOutcome::SendIntegrityAlert => {
                        let alert = [Sctr::INTEGRITY_VIOLATED_ALERT.0];
                        rx_raw_len = tl
                            .transceive_async(pl, dl, &alert, &mut self.record_buf, true)
                            .await?;
                    }
                }
            }
        }
    }

    /// Asynchronously saves the active session context across hibernate.
    pub async fn save_context_async<I2C, T, VDD, RST>(
        &mut self,
        pl: &mut PhysicalLayer<I2C, T, VDD, RST>,
        dl: &mut DataLinkLayer,
        tl: &mut TransportLayer,
    ) -> Result<(), IfxI2cError>
    where
        I2C: AsyncOptigaI2cBus,
        T: AsyncOptigaTimer,
        VDD: OutputPin,
        RST: OutputPin,
    {
        if !self.negotiation_state {
            return Ok(());
        }

        let rx_len = tl
            .transceive_async(pl, dl, &[0x60], &mut self.record_buf, true)
            .await?;
        self.finish_save_context(rx_len)
    }

    /// Asynchronously restores a previously saved session context after hibernate.
    pub async fn restore_context_async<I2C, T, VDD, RST>(
        &mut self,
        pl: &mut PhysicalLayer<I2C, T, VDD, RST>,
        dl: &mut DataLinkLayer,
        tl: &mut TransportLayer,
    ) -> Result<(), IfxI2cError>
    where
        I2C: AsyncOptigaI2cBus,
        T: AsyncOptigaTimer,
        VDD: OutputPin,
        RST: OutputPin,
    {
        let Some((saved, msg)) = self.prepare_restore_context()? else {
            return Ok(());
        };

        let rx_len = tl
            .transceive_async(pl, dl, &msg, &mut self.record_buf, true)
            .await?;
        self.finish_restore_context(rx_len, saved)
    }
}

/// Top-level asynchronous coordinator of the 4-layer `ifx_i2c` protocol stack.
pub struct IfxI2cStack<
    I2C,
    T,
    VDD = NoPin,
    RST = NoPin,
    CRYPTO = RustCryptoBackend,
    DS = NoDatastore,
> {
    pub pl: PhysicalLayer<I2C, T, VDD, RST>,
    pub dl: DataLinkLayer,
    pub tl: TransportLayer,
    pub prl: PresentationLayer<CRYPTO, DS>,
}

impl<I2C, T, VDD, RST, CRYPTO, DS> IfxI2cStack<I2C, T, VDD, RST, CRYPTO, DS>
where
    I2C: AsyncOptigaI2cBus,
    T: AsyncOptigaTimer,
    VDD: OutputPin,
    RST: OutputPin,
    CRYPTO: HostCrypto,
    DS: Datastore,
{
    /// Creates a new asynchronous `IfxI2cStack` with the given hardware peripherals, timer, and crypto/storage providers.
    pub fn new(
        i2c: I2C,
        timer: T,
        vdd_pin: VDD,
        rst_pin: RST,
        crypto: CRYPTO,
        datastore: DS,
    ) -> Self {
        Self {
            pl: PhysicalLayer::new(i2c, timer, vdd_pin, rst_pin),
            dl: DataLinkLayer::new(),
            tl: TransportLayer::new(),
            prl: PresentationLayer::new(crypto, datastore),
        }
    }

    /// Initializes and negotiates the stack asynchronously.
    pub async fn open(
        &mut self,
        reset_type: ResetType,
        frame_size: u16,
        freq_khz: u16,
    ) -> Result<(), IfxI2cError> {
        self.pl.reset(reset_type).await?;
        self.pl.negotiate(frame_size, freq_khz).await?;
        self.dl.reset();
        self.prl.reset();
        Ok(())
    }

    /// Executes a stack reset (Cold, Warm, or Soft) asynchronously and clears protocol state.
    pub async fn reset(&mut self, reset_type: ResetType) -> Result<(), IfxI2cError> {
        self.pl.reset(reset_type).await?;
        self.dl.reset();
        self.prl.reset();
        Ok(())
    }

    /// Transceives an APDU command payload over the stack asynchronously.
    pub async fn transceive(
        &mut self,
        tx: &[u8],
        rx: &mut [u8],
        protection: ProtectionConfig,
    ) -> Result<usize, IfxI2cError> {
        self.prl
            .transceive_async(&mut self.pl, &mut self.dl, &mut self.tl, tx, rx, protection)
            .await
    }

    /// Transceives an APDU command payload in-place asynchronously.
    pub async fn transceive_in_place(
        &mut self,
        apdu_buf: &mut [u8],
        tx_len: usize,
        protection: ProtectionConfig,
    ) -> Result<usize, IfxI2cError> {
        self.prl
            .transceive_in_place_async(
                &mut self.pl,
                &mut self.dl,
                &mut self.tl,
                apdu_buf,
                tx_len,
                protection,
            )
            .await
    }

    /// Saves session context and closes the active connection asynchronously.
    pub async fn close(&mut self, save_context: bool) -> Result<(), IfxI2cError> {
        if save_context {
            self.prl
                .save_context_async(&mut self.pl, &mut self.dl, &mut self.tl)
                .await?;
        } else {
            self.prl.reset();
        }
        Ok(())
    }

    /// Restores a previously saved session context across hibernate cycles asynchronously.
    pub async fn restore_context(&mut self) -> Result<(), IfxI2cError> {
        self.prl
            .restore_context_async(&mut self.pl, &mut self.dl, &mut self.tl)
            .await
    }

    /// Configures a new 7-bit I2C slave address asynchronously.
    pub async fn set_slave_address(
        &mut self,
        addr: u8,
        persistent: bool,
    ) -> Result<(), IfxI2cError> {
        self.pl.write_slave_address(addr, persistent).await
    }
}

/// Asynchronous Command Layer executing APDUs with automatic `0xF1C2` device error retrieval.
pub struct OptigaCmd<
    I2C,
    T,
    VDD = NoPin,
    RST = NoPin,
    CRYPTO = RustCryptoBackend,
    DS = NoDatastore,
> {
    pub stack: IfxI2cStack<I2C, T, VDD, RST, CRYPTO, DS>,
    apdu_buf: [u8; 1557],
    session_slots_mask: u8,
}

impl<I2C, T, VDD, RST, CRYPTO, DS> OptigaCmd<I2C, T, VDD, RST, CRYPTO, DS>
where
    I2C: AsyncOptigaI2cBus,
    T: AsyncOptigaTimer,
    VDD: OutputPin,
    RST: OutputPin,
    CRYPTO: HostCrypto,
    DS: Datastore,
{
    /// Creates a new asynchronous `OptigaCmd` instance wrapping `stack`.
    pub fn new(stack: IfxI2cStack<I2C, T, VDD, RST, CRYPTO, DS>) -> Self {
        Self {
            stack,
            apdu_buf: [0u8; 1557],
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

    /// Asynchronously executes an APDU command by building `in_data` in-place inside `OptigaCmd`'s internal
    /// buffer and processing `out_data` via a closure, requiring zero stack buffers.
    pub async fn execute_with_response<F, R, Out>(
        &mut self,
        cmd: u8,
        param: u8,
        build_in_data: F,
        process_out_data: R,
        protection: ProtectionConfig,
    ) -> Result<Out, OptigaError>
    where
        F: FnOnce(&mut [u8]) -> Result<usize, OptigaError>,
        R: FnOnce(&[u8]) -> Result<Out, OptigaError>,
    {
        let in_len = build_in_data(&mut self.apdu_buf[4..])?;
        if in_len > 1553 {
            return Err(OptigaError::MemoryInsufficient);
        }

        self.apdu_buf[0] = cmd | OPTIGA_CMD_CLEAR_LAST_ERROR;
        self.apdu_buf[1] = param;
        let in_len_be = (in_len as u16).to_be_bytes();
        self.apdu_buf[2] = in_len_be[0];
        self.apdu_buf[3] = in_len_be[1];
        let total_apdu_len = 4 + in_len;

        let rx_len = self
            .stack
            .transceive_in_place(&mut self.apdu_buf, total_apdu_len, protection)
            .await
            .map_err(OptigaError::Comms)?;

        if rx_len < 4 {
            return Err(OptigaError::CommandError);
        }

        let sta = self.apdu_buf[0];
        if sta == 0x00 {
            let out_len = u16::from_be_bytes([self.apdu_buf[2], self.apdu_buf[3]]) as usize;
            if rx_len < 4 + out_len {
                return Err(OptigaError::MemoryInsufficient);
            }
            process_out_data(&self.apdu_buf[4..4 + out_len])
        } else {
            let device_err = self.read_last_error_code(protection).await?;
            Err(OptigaError::Device(device_err))
        }
    }

    /// Asynchronously executes an APDU command by building `in_data` in-place inside `OptigaCmd`'s internal
    /// buffer and copying response data into `rx_out`.
    pub async fn execute_with<F>(
        &mut self,
        cmd: u8,
        param: u8,
        build_in_data: F,
        rx_out: &mut [u8],
        protection: ProtectionConfig,
    ) -> Result<usize, OptigaError>
    where
        F: FnOnce(&mut [u8]) -> Result<usize, OptigaError>,
    {
        self.execute_with_response(
            cmd,
            param,
            build_in_data,
            |out_data| {
                if out_data.len() > rx_out.len() {
                    return Err(OptigaError::MemoryInsufficient);
                }
                rx_out[..out_data.len()].copy_from_slice(out_data);
                Ok(out_data.len())
            },
            protection,
        )
        .await
    }

    /// Asynchronously executes an APDU command over the stack.
    pub async fn execute(
        &mut self,
        cmd: u8,
        param: u8,
        in_data: &[u8],
        rx_out: &mut [u8],
        protection: ProtectionConfig,
    ) -> Result<usize, OptigaError> {
        self.execute_with(
            cmd,
            param,
            |buf| {
                if in_data.len() > buf.len() {
                    return Err(OptigaError::MemoryInsufficient);
                }
                buf[..in_data.len()].copy_from_slice(in_data);
                Ok(in_data.len())
            },
            rx_out,
            protection,
        )
        .await
    }

    async fn read_last_error_code(
        &mut self,
        protection: ProtectionConfig,
    ) -> Result<DeviceError, OptigaError> {
        let get_err_apdu = [
            opcodes::GET_DATA_OBJECT,
            0x00,
            0x00,
            0x06,
            0xF1,
            0xC2,
            0x00,
            0x00,
            0x00,
            0x01,
        ];

        self.apdu_buf[..get_err_apdu.len()].copy_from_slice(&get_err_apdu);
        let rx_len = self
            .stack
            .transceive_in_place(
                &mut self.apdu_buf,
                get_err_apdu.len(),
                ProtectionConfig {
                    level: if self.stack.prl.negotiation_state {
                        protection.level
                    } else {
                        ProtectionLevel::None
                    },
                    force_reestablish: false,
                },
            )
            .await
            .map_err(OptigaError::Comms)?;

        if rx_len >= 5 && self.apdu_buf[0] == 0x00 {
            Ok(DeviceError::from(self.apdu_buf[4]))
        } else {
            Ok(DeviceError::GeneralError)
        }
    }
}

/// High-level asynchronous utility service for OPTIGA data objects, counters, and application lifecycle.
pub struct OptigaUtil<
    'a,
    I2C,
    T,
    VDD = NoPin,
    RST = NoPin,
    CRYPTO = RustCryptoBackend,
    DS = NoDatastore,
> {
    pub cmd: &'a mut OptigaCmd<I2C, T, VDD, RST, CRYPTO, DS>,
    pub protection: ProtectionConfig,
}

impl<'a, I2C, T, VDD, RST, CRYPTO, DS> OptigaUtil<'a, I2C, T, VDD, RST, CRYPTO, DS>
where
    I2C: AsyncOptigaI2cBus,
    T: AsyncOptigaTimer,
    VDD: OutputPin,
    RST: OutputPin,
    CRYPTO: HostCrypto,
    DS: Datastore,
{
    /// Creates a new asynchronous `OptigaUtil` handle borrowing `cmd`.
    pub fn new(cmd: &'a mut OptigaCmd<I2C, T, VDD, RST, CRYPTO, DS>) -> Self {
        Self {
            cmd,
            protection: ProtectionConfig::default(),
        }
    }

    /// Sets the default protection configuration for utility operations.
    pub fn set_protection(&mut self, protection: ProtectionConfig) {
        self.protection = protection;
    }

    /// Opens the OPTIGA application context (`0x70`) asynchronously.
    pub async fn open_application(
        &mut self,
        restore_from_hibernate: bool,
    ) -> Result<(), OptigaError> {
        let mut out = [0u8; 16];
        if restore_from_hibernate {
            let mut handle = [0u8; 8];
            let len = self
                .cmd
                .stack
                .prl
                .datastore
                .read(DatastoreId::HibernateContext, &mut handle)
                .map_err(|_| OptigaError::DatastoreError)?;
            if len < 8 || handle == [0u8; 8] {
                return Err(OptigaError::CommandError);
            }
            self.cmd
                .stack
                .prl
                .datastore
                .write(DatastoreId::HibernateContext, &[0u8; 8])
                .map_err(|_| OptigaError::DatastoreError)?;

            let mut in_data = [0u8; 24];
            in_data[..16].copy_from_slice(&OPTIGA_APPLICATION_ID);
            in_data[16..24].copy_from_slice(&handle);
            self.cmd
                .execute(
                    opcodes::OPEN_APPLICATION,
                    0x01,
                    &in_data,
                    &mut out,
                    self.protection,
                )
                .await?;
        } else {
            self.cmd
                .execute(
                    opcodes::OPEN_APPLICATION,
                    0x00,
                    &OPTIGA_APPLICATION_ID,
                    &mut out,
                    self.protection,
                )
                .await?;
        }
        Ok(())
    }

    /// Closes the OPTIGA application context (`0x71`) asynchronously.
    pub async fn close_application(&mut self, hibernate: bool) -> Result<(), OptigaError> {
        let param = if hibernate { 0x01 } else { 0x00 };
        let mut out = [0u8; 16];
        let len = self
            .cmd
            .execute(
                opcodes::CLOSE_APPLICATION,
                param,
                &[],
                &mut out,
                self.protection,
            )
            .await?;

        if hibernate {
            if len != 8 {
                return Err(OptigaError::CommandError);
            }
            self.cmd
                .stack
                .prl
                .datastore
                .write(DatastoreId::HibernateContext, &out[..8])
                .map_err(|_| OptigaError::DatastoreError)?;
        }
        Ok(())
    }

    /// Reads data from a data object starting at `offset` asynchronously.
    pub async fn read_data(
        &mut self,
        oid: Oid,
        offset: u16,
        out_buf: &mut [u8],
    ) -> Result<usize, OptigaError> {
        let read_len = u16::try_from(out_buf.len()).map_err(|_| OptigaError::InvalidInput)?;
        let oid_be = oid.as_u16().to_be_bytes();
        let off_be = offset.to_be_bytes();
        let len_be = read_len.to_be_bytes();

        let in_data = [
            oid_be[0], oid_be[1], off_be[0], off_be[1], len_be[0], len_be[1],
        ];

        self.cmd
            .execute(
                opcodes::GET_DATA_OBJECT,
                0x00,
                &in_data,
                out_buf,
                self.protection,
            )
            .await
    }

    /// Writes data to a data object starting at `offset` asynchronously without stack buffer allocation.
    pub async fn write_data(
        &mut self,
        oid: Oid,
        offset: u16,
        data: &[u8],
        erase_and_write: bool,
    ) -> Result<(), OptigaError> {
        let oid_be = oid.as_u16().to_be_bytes();
        let off_be = offset.to_be_bytes();
        let param = if erase_and_write { 0x40 } else { 0x00 };
        let mut out = [0u8; 4];

        self.cmd
            .execute_with(
                opcodes::SET_DATA_OBJECT,
                param,
                |buf| {
                    if 4 + data.len() > buf.len() {
                        return Err(OptigaError::MemoryInsufficient);
                    }
                    buf[0] = oid_be[0];
                    buf[1] = oid_be[1];
                    buf[2] = off_be[0];
                    buf[3] = off_be[1];
                    buf[4..4 + data.len()].copy_from_slice(data);
                    Ok(4 + data.len())
                },
                &mut out,
                self.protection,
            )
            .await?;
        Ok(())
    }

    /// Reads metadata from a data object or key OID asynchronously.
    pub async fn read_metadata(
        &mut self,
        oid: Oid,
        out_buf: &mut [u8],
    ) -> Result<usize, OptigaError> {
        let read_len = u16::try_from(out_buf.len()).map_err(|_| OptigaError::InvalidInput)?;
        let oid_be = oid.as_u16().to_be_bytes();
        let len_be = read_len.to_be_bytes();

        let in_data = [oid_be[0], oid_be[1], 0x00, 0x00, len_be[0], len_be[1]];

        self.cmd
            .execute(
                opcodes::GET_DATA_OBJECT,
                0x01,
                &in_data,
                out_buf,
                self.protection,
            )
            .await
    }

    /// Writes metadata to a data object or key OID asynchronously (`SetDataObject` with `Param = 0x01`).
    pub async fn write_metadata(&mut self, oid: Oid, metadata: &[u8]) -> Result<(), OptigaError> {
        if metadata.is_empty() {
            return Err(OptigaError::InvalidInput);
        }
        let oid_be = oid.as_u16().to_be_bytes();
        let mut out = [0u8; 4];

        self.cmd
            .execute_with(
                opcodes::SET_DATA_OBJECT,
                0x01,
                |buf| {
                    if 4 + metadata.len() > buf.len() {
                        return Err(OptigaError::MemoryInsufficient);
                    }
                    buf[0] = oid_be[0];
                    buf[1] = oid_be[1];
                    buf[2] = 0x00;
                    buf[3] = 0x00;
                    buf[4..4 + metadata.len()].copy_from_slice(metadata);
                    Ok(4 + metadata.len())
                },
                &mut out,
                self.protection,
            )
            .await?;
        Ok(())
    }

    /// Reads a 32-bit monotonic counter value asynchronously.
    pub async fn read_monotonic_counter(&mut self, counter_oid: Oid) -> Result<u32, OptigaError> {
        let mut buf = [0u8; 4];
        let len = self.read_data(counter_oid, 0, &mut buf).await?;
        if len < 4 {
            return Err(OptigaError::CommandError);
        }
        Ok(u32::from_be_bytes(buf))
    }

    /// Increments a monotonic counter by `count` asynchronously (`SetDataObject` with `Param = 0x02`).
    pub async fn increment_monotonic_counter(
        &mut self,
        counter_oid: Oid,
        count: u8,
    ) -> Result<(), OptigaError> {
        let oid_be = counter_oid.as_u16().to_be_bytes();
        let in_data = [oid_be[0], oid_be[1], 0x00, 0x00, count];
        let mut out = [0u8; 4];
        self.cmd
            .execute(
                opcodes::SET_DATA_OBJECT,
                0x02,
                &in_data,
                &mut out,
                self.protection,
            )
            .await?;
        Ok(())
    }

    /// Starts a Protected Update sequence asynchronously (`SetObjectProtected` `0x03`, Tag `0x82`).
    pub async fn protected_update_start(
        &mut self,
        manifest_version: u8,
        manifest: &[u8],
    ) -> Result<(), OptigaError> {
        let mut out = [0u8; 4];
        self.cmd
            .execute_with(
                opcodes::SET_OBJECT_PROTECTED,
                manifest_version,
                |buf| {
                    let mut writer = TlvWriter::new(buf);
                    writer.write_tlv(0x82, manifest)?;
                    Ok(writer.len())
                },
                &mut out,
                self.protection,
            )
            .await?;
        Ok(())
    }

    /// Continues a Protected Update sequence asynchronously (`SetObjectProtected` `0x03`, Tag `0x83`).
    pub async fn protected_update_continue(
        &mut self,
        fragment: &[u8],
    ) -> Result<(), OptigaError> {
        let mut out = [0u8; 4];
        self.cmd
            .execute_with(
                opcodes::SET_OBJECT_PROTECTED,
                0x00,
                |buf| {
                    let mut writer = TlvWriter::new(buf);
                    writer.write_tlv(0x83, fragment)?;
                    Ok(writer.len())
                },
                &mut out,
                self.protection,
            )
            .await?;
        Ok(())
    }

    /// Finalizes a Protected Update sequence asynchronously (`SetObjectProtected` `0x03`, Tag `0x81`).
    pub async fn protected_update_final(&mut self, fragment: &[u8]) -> Result<(), OptigaError> {
        let mut out = [0u8; 4];
        self.cmd
            .execute_with(
                opcodes::SET_OBJECT_PROTECTED,
                0x00,
                |buf| {
                    let mut writer = TlvWriter::new(buf);
                    writer.write_tlv(0x81, fragment)?;
                    Ok(writer.len())
                },
                &mut out,
                self.protection,
            )
            .await?;
        Ok(())
    }

    /// Executes a complete Protected Update (Start -> Continue* -> Final) asynchronously.
    pub async fn protected_update(
        &mut self,
        manifest_version: u8,
        manifest: &[u8],
        fragments: &[&[u8]],
    ) -> Result<(), OptigaError> {
        if fragments.is_empty() {
            return Err(OptigaError::InvalidInput);
        }
        self.protected_update_start(manifest_version, manifest)
            .await?;
        for frag in &fragments[..fragments.len() - 1] {
            self.protected_update_continue(frag).await?;
        }
        self.protected_update_final(fragments[fragments.len() - 1])
            .await
    }
}

/// High-level asynchronous cryptographic service for OPTIGA operations.
pub struct OptigaCrypt<
    'a,
    I2C,
    T,
    VDD = NoPin,
    RST = NoPin,
    CRYPTO = RustCryptoBackend,
    DS = NoDatastore,
> {
    pub cmd: &'a mut OptigaCmd<I2C, T, VDD, RST, CRYPTO, DS>,
    pub protection: ProtectionConfig,
}

impl<'a, I2C, T, VDD, RST, CRYPTO, DS> OptigaCrypt<'a, I2C, T, VDD, RST, CRYPTO, DS>
where
    I2C: AsyncOptigaI2cBus,
    T: AsyncOptigaTimer,
    VDD: OutputPin,
    RST: OutputPin,
    CRYPTO: HostCrypto,
    DS: Datastore,
{
    /// Creates a new asynchronous `OptigaCrypt` service borrowing `cmd`.
    pub fn new(cmd: &'a mut OptigaCmd<I2C, T, VDD, RST, CRYPTO, DS>) -> Self {
        Self {
            cmd,
            protection: ProtectionConfig::default(),
        }
    }

    /// Sets the protection configuration for cryptographic operations.
    pub fn set_protection(&mut self, protection: ProtectionConfig) {
        self.protection = protection;
    }

    /// Fills `out_buf` (8..=256 bytes) with hardware random bytes from OPTIGA's TRNG asynchronously.
    pub async fn get_random(&mut self, out_buf: &mut [u8]) -> Result<(), OptigaError> {
        self.get_random_with_type(RngType::Trng, out_buf).await
    }

    /// Fills `out_buf` (8..=256 bytes) with hardware random bytes using `rng_type` (TRNG or DRNG) asynchronously.
    pub async fn get_random_with_type(
        &mut self,
        rng_type: RngType,
        out_buf: &mut [u8],
    ) -> Result<(), OptigaError> {
        if !(8..=256).contains(&out_buf.len()) {
            return Err(OptigaError::InvalidInput);
        }
        let req_len = out_buf.len() as u16;
        let in_data = req_len.to_be_bytes();

        let len = self
            .cmd
            .execute(
                opcodes::GET_RANDOM,
                rng_type as u8,
                &in_data,
                out_buf,
                self.protection,
            )
            .await?;
        if len != out_buf.len() {
            return Err(OptigaError::CommandError);
        }
        Ok(())
    }

    /// Computes a one-shot SHA-256 digest of `data` using OPTIGA (`CalcHash` `0x30`, `Param = 0xE2`) asynchronously.
    pub async fn hash_sha256(
        &mut self,
        data: &[u8],
        digest_out: &mut [u8; 32],
    ) -> Result<(), OptigaError> {
        self.cmd
            .execute_with_response(
                opcodes::CALC_HASH,
                0xE2,
                |buf| {
                    let mut writer = TlvWriter::new(buf);
                    writer.write_tlv(0x00, data)?;
                    Ok(writer.len())
                },
                |out_data| {
                    let mut reader = TlvReader::new(out_data);
                    let digest = reader.find_tag(0x00).ok_or(OptigaError::CommandError)?;
                    if digest.len() != 32 {
                        return Err(OptigaError::CommandError);
                    }
                    digest_out.copy_from_slice(digest);
                    Ok(())
                },
                self.protection,
            )
            .await
    }

    /// Computes a SHA-256 digest over the contents of an on-chip data object OID (`CalcHash` Tag `0x06`) asynchronously.
    pub async fn hash_oid_sha256(
        &mut self,
        oid: Oid,
        offset: u16,
        length: u16,
        digest_out: &mut [u8; 32],
    ) -> Result<(), OptigaError> {
        let oid_be = oid.as_u16().to_be_bytes();
        let off_be = offset.to_be_bytes();
        let len_be = length.to_be_bytes();
        let oid_spec = [
            oid_be[0], oid_be[1], off_be[0], off_be[1], len_be[0], len_be[1],
        ];

        self.cmd
            .execute_with_response(
                opcodes::CALC_HASH,
                0xE2,
                |buf| {
                    let mut writer = TlvWriter::new(buf);
                    writer.write_tlv(0x06, &oid_spec)?;
                    Ok(writer.len())
                },
                |out_data| {
                    let mut reader = TlvReader::new(out_data);
                    let digest = reader.find_tag(0x00).ok_or(OptigaError::CommandError)?;
                    if digest.len() != 32 {
                        return Err(OptigaError::CommandError);
                    }
                    digest_out.copy_from_slice(digest);
                    Ok(())
                },
                self.protection,
            )
            .await
    }

    /// Generates an ECC keypair on-chip and stores the private key in `private_key_oid` asynchronously.
    pub async fn ecc_generate_keypair(
        &mut self,
        curve: EccCurve,
        private_key_oid: Oid,
        usage: KeyUsage,
        pubkey_out: &mut [u8],
    ) -> Result<usize, OptigaError> {
        let oid_be = private_key_oid.as_u16().to_be_bytes();

        self.cmd
            .execute_with_response(
                opcodes::GEN_KEYPAIR,
                curve as u8,
                |buf| {
                    let mut writer = TlvWriter::new(buf);
                    writer.write_tlv(0x01, &oid_be)?;
                    writer.write_tlv(0x02, &[usage.0])?;
                    Ok(writer.len())
                },
                |out_data| {
                    let mut reader = TlvReader::new(out_data);
                    let pubkey = reader.find_tag(0x02).ok_or(OptigaError::CommandError)?;
                    if pubkey.len() > pubkey_out.len() {
                        return Err(OptigaError::MemoryInsufficient);
                    }
                    pubkey_out[..pubkey.len()].copy_from_slice(pubkey);
                    Ok(pubkey.len())
                },
                self.protection,
            )
            .await
    }

    /// Generates an ECC keypair on-chip and exports both the private key and public key to the host asynchronously.
    pub async fn ecc_generate_keypair_export(
        &mut self,
        curve: EccCurve,
        private_key_out: &mut [u8],
        pubkey_out: &mut [u8],
    ) -> Result<(usize, usize), OptigaError> {
        self.cmd
            .execute_with_response(
                opcodes::GEN_KEYPAIR,
                curve as u8,
                |buf| {
                    let mut writer = TlvWriter::new(buf);
                    writer.write_tlv(0x07, &[])?;
                    Ok(writer.len())
                },
                |out_data| {
                    let mut reader = TlvReader::new(out_data);
                    let privkey = reader.find_tag(0x01).ok_or(OptigaError::CommandError)?;
                    let pubkey = reader.find_tag(0x02).ok_or(OptigaError::CommandError)?;
                    if privkey.len() > private_key_out.len() || pubkey.len() > pubkey_out.len() {
                        return Err(OptigaError::MemoryInsufficient);
                    }
                    private_key_out[..privkey.len()].copy_from_slice(privkey);
                    pubkey_out[..pubkey.len()].copy_from_slice(pubkey);
                    Ok((privkey.len(), pubkey.len()))
                },
                self.protection,
            )
            .await
    }

    /// Generates an ECC keypair on-chip in an ephemeral session slot (`0xE100..=0xE103`) asynchronously.
    pub async fn generate_keypair_in_session(
        &mut self,
        curve: EccCurve,
        usage: KeyUsage,
        pubkey_out: &mut [u8],
    ) -> Result<SessionSlot, OptigaError> {
        let slot = self.cmd.acquire_session_slot()?;
        let slot_oid = slot.oid();
        match self
            .ecc_generate_keypair(curve, slot_oid, usage, pubkey_out)
            .await
        {
            Ok(_) => Ok(slot),
            Err(e) => {
                self.cmd.release_session_slot(slot);
                Err(e)
            }
        }
    }

    /// Signs `digest` using ECDSA (FIPS 186-3) with the private key located at `key_oid` asynchronously.
    pub async fn ecdsa_sign(
        &mut self,
        digest: &[u8],
        key_oid: Oid,
        signature_out: &mut [u8],
    ) -> Result<usize, OptigaError> {
        let oid_be = key_oid.as_u16().to_be_bytes();

        self.cmd
            .execute_with_response(
                opcodes::CALC_SIGN,
                0x11,
                |buf| {
                    let mut writer = TlvWriter::new(buf);
                    writer.write_tlv(0x01, digest)?;
                    writer.write_tlv(0x03, &oid_be)?;
                    Ok(writer.len())
                },
                |out_data| {
                    if out_data.len() > signature_out.len() {
                        return Err(OptigaError::MemoryInsufficient);
                    }
                    signature_out[..out_data.len()].copy_from_slice(out_data);
                    ecc_r_s_padding_check(signature_out, out_data.len())
                },
                self.protection,
            )
            .await
    }

    /// Signs `digest` using ECDSA with the ephemeral private key in `session_slot` asynchronously.
    pub async fn ecdsa_sign_with_session(
        &mut self,
        digest: &[u8],
        session_slot: &SessionSlot,
        signature_out: &mut [u8],
    ) -> Result<usize, OptigaError> {
        self.ecdsa_sign(digest, session_slot.oid(), signature_out)
            .await
    }

    /// Verifies an ECDSA signature over `digest` using the provided host `pubkey` asynchronously.
    pub async fn ecdsa_verify(
        &mut self,
        digest: &[u8],
        signature: &[u8],
        pubkey: &[u8],
        curve: EccCurve,
    ) -> Result<bool, OptigaError> {
        let mut rx = [0u8; 4];
        let res = self
            .cmd
            .execute_with(
                opcodes::VERIFY_SIGN,
                0x11,
                |buf| {
                    let mut writer = TlvWriter::new(buf);
                    writer.write_tlv(0x01, digest)?;
                    writer.write_tlv(0x02, signature)?;
                    writer.write_tlv(0x05, &[curve as u8])?;
                    writer.write_tlv(0x06, pubkey)?;
                    Ok(writer.len())
                },
                &mut rx,
                self.protection,
            )
            .await;
        match res {
            Ok(_) => Ok(true),
            Err(OptigaError::Device(DeviceError::SignatureVerificationFailure)) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Verifies an ECDSA signature over `digest` using an on-chip public key or certificate OID (`Tag 0x04`) asynchronously.
    pub async fn ecdsa_verify_with_oid(
        &mut self,
        digest: &[u8],
        signature: &[u8],
        public_key_or_cert_oid: Oid,
    ) -> Result<bool, OptigaError> {
        let oid_be = public_key_or_cert_oid.as_u16().to_be_bytes();
        let mut rx = [0u8; 4];
        let res = self
            .cmd
            .execute_with(
                opcodes::VERIFY_SIGN,
                0x11,
                |buf| {
                    let mut writer = TlvWriter::new(buf);
                    writer.write_tlv(0x01, digest)?;
                    writer.write_tlv(0x02, signature)?;
                    writer.write_tlv(0x04, &oid_be)?;
                    Ok(writer.len())
                },
                &mut rx,
                self.protection,
            )
            .await;
        match res {
            Ok(_) => Ok(true),
            Err(OptigaError::Device(DeviceError::SignatureVerificationFailure)) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Performs ECDH key agreement deriving a shared secret from `priv_key_oid` and `peer_pubkey` asynchronously.
    pub async fn ecdh(
        &mut self,
        priv_key_oid: Oid,
        peer_pubkey: &[u8],
        curve: EccCurve,
        shared_secret_out: &mut [u8],
    ) -> Result<usize, OptigaError> {
        let oid_be = priv_key_oid.as_u16().to_be_bytes();
        let expected_len = curve.shared_secret_len();
        if shared_secret_out.len() < expected_len {
            return Err(OptigaError::MemoryInsufficient);
        }

        self.cmd
            .execute_with_response(
                opcodes::CALC_SSEC,
                0x01,
                |buf| {
                    let mut writer = TlvWriter::new(buf);
                    writer.write_tlv(0x01, &oid_be)?;
                    writer.write_tlv(0x05, &[curve as u8])?;
                    writer.write_tlv(0x06, peer_pubkey)?;
                    writer.write_tlv(0x07, &[])?;
                    Ok(writer.len())
                },
                |out_data| {
                    if out_data.len() != expected_len {
                        return Err(OptigaError::CommandError);
                    }
                    shared_secret_out[..expected_len].copy_from_slice(out_data);
                    Ok(expected_len)
                },
                self.protection,
            )
            .await
    }

    /// Performs ECDH key agreement and stores the resulting shared secret inside an on-chip
    /// `SessionSlot` (`Tag 0x08`) asynchronously.
    pub async fn ecdh_to_session(
        &mut self,
        priv_key_oid: Oid,
        peer_pubkey: &[u8],
        curve: EccCurve,
    ) -> Result<SessionSlot, OptigaError> {
        let slot = self.cmd.acquire_session_slot()?;
        let priv_oid_be = priv_key_oid.as_u16().to_be_bytes();
        let session_oid_be = slot.oid().as_u16().to_be_bytes();

        let mut rx = [0u8; 4];
        let res = self
            .cmd
            .execute_with(
                opcodes::CALC_SSEC,
                0x01,
                |buf| {
                    let mut writer = TlvWriter::new(buf);
                    writer.write_tlv(0x01, &priv_oid_be)?;
                    writer.write_tlv(0x05, &[curve as u8])?;
                    writer.write_tlv(0x06, peer_pubkey)?;
                    writer.write_tlv(0x08, &session_oid_be)?;
                    Ok(writer.len())
                },
                &mut rx,
                self.protection,
            )
            .await;
        match res {
            Ok(_) => Ok(slot),
            Err(e) => {
                self.cmd.release_session_slot(slot);
                Err(e)
            }
        }
    }

    /// Derives a key (`DeriveKey` `0x34`) from `secret_oid` and exports the derived key into `derived_key_out` asynchronously.
    pub async fn derive_key_to_host(
        &mut self,
        alg: KdfAlg,
        secret_oid: Oid,
        label: &[u8],
        seed_or_salt: &[u8],
        info: Option<&[u8]>,
        derived_key_out: &mut [u8],
    ) -> Result<(), OptigaError> {
        if derived_key_out.is_empty() || derived_key_out.len() > 1553 {
            return Err(OptigaError::InvalidInput);
        }
        let secret_oid_be = secret_oid.as_u16().to_be_bytes();
        let req_len = derived_key_out.len();
        let wire_key_len = (req_len.max(16) as u16).to_be_bytes();

        self.cmd
            .execute_with_response(
                opcodes::DERIVE_KEY,
                alg as u8,
                |buf| {
                    let mut writer = TlvWriter::new(buf);
                    writer.write_tlv(0x01, &secret_oid_be)?;
                    writer.write_tlv(0x03, &wire_key_len)?;
                    if let Some(info_bytes) = info {
                        if !info_bytes.is_empty() {
                            writer.write_tlv(0x04, info_bytes)?;
                        }
                    }
                    writer.write_tlv_concat(0x02, label, seed_or_salt)?;
                    writer.write_tlv(0x07, &[])?;
                    Ok(writer.len())
                },
                |out_data| {
                    if out_data.len() < req_len {
                        return Err(OptigaError::CommandError);
                    }
                    derived_key_out.copy_from_slice(&out_data[..req_len]);
                    Ok(())
                },
                self.protection,
            )
            .await
    }

    /// Derives a key (`DeriveKey` `0x34`) from `secret_oid` and stores the derived key in `target_session` asynchronously.
    #[allow(clippy::too_many_arguments)]
    pub async fn derive_key_to_session(
        &mut self,
        alg: KdfAlg,
        secret_oid: Oid,
        label: &[u8],
        seed_or_salt: &[u8],
        info: Option<&[u8]>,
        derived_key_len: u16,
        target_session: &SessionSlot,
    ) -> Result<(), OptigaError> {
        if derived_key_len == 0 {
            return Err(OptigaError::InvalidInput);
        }
        let secret_oid_be = secret_oid.as_u16().to_be_bytes();
        let wire_key_len = derived_key_len.max(16).to_be_bytes();
        let target_oid_be = target_session.oid().as_u16().to_be_bytes();
        let mut rx = [0u8; 4];

        self.cmd
            .execute_with(
                opcodes::DERIVE_KEY,
                alg as u8,
                |buf| {
                    let mut writer = TlvWriter::new(buf);
                    writer.write_tlv(0x01, &secret_oid_be)?;
                    writer.write_tlv(0x03, &wire_key_len)?;
                    if let Some(info_bytes) = info {
                        if !info_bytes.is_empty() {
                            writer.write_tlv(0x04, info_bytes)?;
                        }
                    }
                    writer.write_tlv_concat(0x02, label, seed_or_salt)?;
                    writer.write_tlv(0x08, &target_oid_be)?;
                    Ok(writer.len())
                },
                &mut rx,
                self.protection,
            )
            .await?;
        Ok(())
    }
}

/// Trait bundling all hardware and cryptographic types for an asynchronous OPTIGA board configuration.
pub trait OptigaPlatform {
    type I2c: AsyncOptigaI2cBus;
    type Timer: AsyncOptigaTimer;
    type VddPin: OutputPin;
    type RstPin: OutputPin;
    type Crypto: HostCrypto;
    type Datastore: Datastore;
}

/// Type alias projecting an [`OptigaPlatform`] implementation into a concrete asynchronous [`OptigaTrustM`] instance.
pub type OptigaFor<P> = OptigaTrustM<
    <P as OptigaPlatform>::I2c,
    <P as OptigaPlatform>::Timer,
    <P as OptigaPlatform>::VddPin,
    <P as OptigaPlatform>::RstPin,
    <P as OptigaPlatform>::Crypto,
    <P as OptigaPlatform>::Datastore,
>;

/// Fluent builder for constructing an asynchronous [`OptigaTrustM`] instance with sensible defaults.
pub struct OptigaBuilder<
    I2C,
    T,
    VDD = NoPin,
    RST = NoPin,
    CRYPTO = RustCryptoBackend,
    DS = NoDatastore,
> {
    i2c: I2C,
    timer: T,
    vdd_pin: VDD,
    rst_pin: RST,
    crypto: CRYPTO,
    datastore: DS,
    slave_address: u8,
}

impl<I2C, T> OptigaBuilder<I2C, T, NoPin, NoPin, RustCryptoBackend, NoDatastore>
where
    I2C: AsyncOptigaI2cBus,
    T: AsyncOptigaTimer,
{
    /// Creates a new builder with the required asynchronous I2C bus and timer, defaulting
    /// GPIO pins to [`NoPin`], crypto to [`RustCryptoBackend`], and datastore to [`NoDatastore`].
    pub fn new(i2c: I2C, timer: T) -> Self {
        Self {
            i2c,
            timer,
            vdd_pin: NoPin,
            rst_pin: NoPin,
            crypto: RustCryptoBackend,
            datastore: NoDatastore,
            slave_address: IFX_I2C_BASE_ADDR,
        }
    }
}

impl<I2C, T, VDD, RST, CRYPTO, DS> OptigaBuilder<I2C, T, VDD, RST, CRYPTO, DS>
where
    I2C: AsyncOptigaI2cBus,
    T: AsyncOptigaTimer,
    VDD: OutputPin,
    RST: OutputPin,
    CRYPTO: HostCrypto,
    DS: Datastore,
{
    /// Configures the `VDD` power switch pin used for `ResetType::Cold`.
    pub fn with_vdd_pin<NewVdd: OutputPin>(
        self,
        vdd_pin: NewVdd,
    ) -> OptigaBuilder<I2C, T, NewVdd, RST, CRYPTO, DS> {
        OptigaBuilder {
            i2c: self.i2c,
            timer: self.timer,
            vdd_pin,
            rst_pin: self.rst_pin,
            crypto: self.crypto,
            datastore: self.datastore,
            slave_address: self.slave_address,
        }
    }

    /// Configures the `RESET` pin used for `ResetType::Warm` and `ResetType::Cold`.
    pub fn with_reset_pin<NewRst: OutputPin>(
        self,
        rst_pin: NewRst,
    ) -> OptigaBuilder<I2C, T, VDD, NewRst, CRYPTO, DS> {
        OptigaBuilder {
            i2c: self.i2c,
            timer: self.timer,
            vdd_pin: self.vdd_pin,
            rst_pin,
            crypto: self.crypto,
            datastore: self.datastore,
            slave_address: self.slave_address,
        }
    }

    /// Configures both `VDD` and `RESET` pins.
    pub fn with_pins<NewVdd: OutputPin, NewRst: OutputPin>(
        self,
        vdd_pin: NewVdd,
        rst_pin: NewRst,
    ) -> OptigaBuilder<I2C, T, NewVdd, NewRst, CRYPTO, DS> {
        OptigaBuilder {
            i2c: self.i2c,
            timer: self.timer,
            vdd_pin,
            rst_pin,
            crypto: self.crypto,
            datastore: self.datastore,
            slave_address: self.slave_address,
        }
    }

    /// Configures a custom [`HostCrypto`] backend for Presentation Layer shielded connections.
    pub fn with_crypto<NewCrypto: HostCrypto>(
        self,
        crypto: NewCrypto,
    ) -> OptigaBuilder<I2C, T, VDD, RST, NewCrypto, DS> {
        OptigaBuilder {
            i2c: self.i2c,
            timer: self.timer,
            vdd_pin: self.vdd_pin,
            rst_pin: self.rst_pin,
            crypto,
            datastore: self.datastore,
            slave_address: self.slave_address,
        }
    }

    /// Configures a [`Datastore`] for platform binding shared secrets and hibernate context persistence.
    pub fn with_datastore<NewDs: Datastore>(
        self,
        datastore: NewDs,
    ) -> OptigaBuilder<I2C, T, VDD, RST, CRYPTO, NewDs> {
        OptigaBuilder {
            i2c: self.i2c,
            timer: self.timer,
            vdd_pin: self.vdd_pin,
            rst_pin: self.rst_pin,
            crypto: self.crypto,
            datastore,
            slave_address: self.slave_address,
        }
    }

    /// Configures a custom initial 7-bit I2C slave address (default `0x30`).
    pub fn with_slave_address(mut self, addr: u8) -> Self {
        self.slave_address = addr & 0x7F;
        self
    }

    /// Builds the configured asynchronous [`OptigaTrustM`] driver instance.
    pub fn build(self) -> OptigaTrustM<I2C, T, VDD, RST, CRYPTO, DS> {
        let mut dev = OptigaTrustM::new(
            self.i2c,
            self.timer,
            self.vdd_pin,
            self.rst_pin,
            self.crypto,
            self.datastore,
        );
        dev.cmd.stack.pl.set_slave_address(self.slave_address);
        dev
    }
}

/// Top-level asynchronous OPTIGA Trust M device instance providing safe, owned access to Utility and Cryptographic services.
pub struct OptigaTrustM<
    I2C,
    T,
    VDD = NoPin,
    RST = NoPin,
    CRYPTO = RustCryptoBackend,
    DS = NoDatastore,
> {
    pub cmd: OptigaCmd<I2C, T, VDD, RST, CRYPTO, DS>,
}

impl<I2C, T> OptigaTrustM<I2C, T, NoPin, NoPin, RustCryptoBackend, NoDatastore>
where
    I2C: AsyncOptigaI2cBus,
    T: AsyncOptigaTimer,
{
    /// Starts a fluent [`OptigaBuilder`] for configuring an asynchronous `OptigaTrustM` instance.
    pub fn builder(
        i2c: I2C,
        timer: T,
    ) -> OptigaBuilder<I2C, T, NoPin, NoPin, RustCryptoBackend, NoDatastore> {
        OptigaBuilder::new(i2c, timer)
    }
}

impl<I2C, T, DS> OptigaTrustM<I2C, T, NoPin, NoPin, RustCryptoBackend, DS>
where
    I2C: AsyncOptigaI2cBus,
    T: AsyncOptigaTimer,
    DS: Datastore,
{
    /// Convenience constructor for boards where `VDD` and `RESET` pins are hardwired (using `ResetType::Soft`)
    /// and the default `RustCryptoBackend` is used.
    pub fn new_with_soft_reset(i2c: I2C, timer: T, datastore: DS) -> Self {
        Self::new(i2c, timer, NoPin, NoPin, RustCryptoBackend, datastore)
    }
}

impl<I2C, T, VDD, RST, CRYPTO, DS> OptigaTrustM<I2C, T, VDD, RST, CRYPTO, DS>
where
    I2C: AsyncOptigaI2cBus,
    T: AsyncOptigaTimer,
    VDD: OutputPin,
    RST: OutputPin,
    CRYPTO: HostCrypto,
    DS: Datastore,
{
    /// Creates a new asynchronous `OptigaTrustM` instance wrapping the given hardware bus, timer, and crypto providers.
    pub fn new(
        i2c: I2C,
        timer: T,
        vdd_pin: VDD,
        rst_pin: RST,
        crypto: CRYPTO,
        datastore: DS,
    ) -> Self {
        let stack = IfxI2cStack::new(i2c, timer, vdd_pin, rst_pin, crypto, datastore);
        let cmd = OptigaCmd::new(stack);
        Self { cmd }
    }

    /// Initializes and negotiates communication with the OPTIGA chip asynchronously.
    pub async fn open(
        &mut self,
        reset_type: ResetType,
        frame_size: u16,
        freq_khz: u16,
    ) -> Result<(), OptigaError> {
        self.cmd
            .stack
            .open(reset_type, frame_size, freq_khz)
            .await
            .map_err(OptigaError::Comms)
    }

    /// Releases a previously acquired volatile session slot (`0xE100..=0xE103`).
    #[inline]
    pub fn release_session_slot(&mut self, slot: SessionSlot) {
        self.cmd.release_session_slot(slot);
    }

    /// Borrows the asynchronous utility service (`OptigaUtil`).
    pub fn util(&mut self) -> OptigaUtil<'_, I2C, T, VDD, RST, CRYPTO, DS> {
        OptigaUtil::new(&mut self.cmd)
    }

    /// Borrows the asynchronous cryptographic service (`OptigaCrypt`).
    pub fn crypt(&mut self) -> OptigaCrypt<'_, I2C, T, VDD, RST, CRYPTO, DS> {
        OptigaCrypt::new(&mut self.cmd)
    }
}
