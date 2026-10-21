//! Presentation Layer (`ifx_i2c::presentation`) implementation.
//!
//! Implements OPTIGA™ Shielded Connection (Infineon I2C Protocol v2.03 Presentation Layer):
//! - 4-step TLS 1.2 PRF SHA-256 session key derivation (`MasterHello`/`SlaveHello`/`MasterFinished`/`SlaveFinished`)
//! - AES-128-CCM-8 authenticated encryption for records (`None`, `Master`, `Slave`, `Full`)
//! - Strictly encapsulated record scratch buffer (eliminating C's 5-byte/13-byte offset hacks)
//! - Sequence rollover threshold renegotiation (`0xFFFFFFF0`) and integrity alert recovery
//! - Session Context Save & Restore (`ManageContext`) across hibernate cycles.

use crate::config::*;
use crate::error::IfxI2cError;
use crate::ifx_i2c::datalink::DataLinkLayer;
use crate::ifx_i2c::headers::{
    ProtectionConfig, ProtectionLevel, Sctr,
};
use crate::ifx_i2c::physical::PhysicalLayer;
use crate::ifx_i2c::transport::TransportLayer;
use crate::pal::rust_crypto::RustCryptoBackend;
use crate::pal::{Datastore, DatastoreId, HostCrypto, NoDatastore, OptigaI2cBus, OptigaTimer};
use embedded_hal::digital::OutputPin;
use zeroize::Zeroize;

/// Total Presentation Layer record buffer capacity (1557 + 13 = 1570 bytes).
const RECORD_BUFFER_SIZE: usize = OPTIGA_MAX_COMMS_BUFFER_SIZE + PRL_OVERHEAD_SIZE;

/// Outcome of decoding a Presentation Layer response record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RxRecordOutcome {
    /// Decrypted/validated plaintext of length `usize` written to `rx_payload`.
    Success(usize),
    /// Slave reported `IntegrityViolated` alert on Master/Full TX; re-encrypt and retransmit.
    RetryMasterTx,
    /// Master detected MAC tag failure on Slave/Full RX; send `INTEGRITY_VIOLATED_ALERT` `[0x44]` and await retransmission.
    SendIntegrityAlert,
}

/// Serialized session context stored in `DatastoreId::ManageContext` (51 bytes).
#[derive(Debug, Clone)]
pub struct SavedSessionContext {
    pub session_key: [u8; 40],
    pub master_sequence_number: u32,
    pub save_slave_sequence_number: u32,
    pub active: bool,
}

impl Zeroize for SavedSessionContext {
    fn zeroize(&mut self) {
        self.session_key.zeroize();
        self.master_sequence_number = 0;
        self.save_slave_sequence_number = 0;
        self.active = false;
    }
}

impl Drop for SavedSessionContext {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl SavedSessionContext {
    pub fn serialize(&self, buf: &mut [u8]) -> Result<usize, IfxI2cError> {
        if buf.len() < 49 {
            return Err(IfxI2cError::MemoryInsufficient);
        }
        buf[0..40].copy_from_slice(&self.session_key);
        buf[40..44].copy_from_slice(&self.master_sequence_number.to_be_bytes());
        buf[44..48].copy_from_slice(&self.save_slave_sequence_number.to_be_bytes());
        buf[48] = if self.active { 1 } else { 0 };
        Ok(49)
    }

    pub fn deserialize(buf: &[u8]) -> Result<Self, IfxI2cError> {
        if buf.len() < 49 {
            return Err(IfxI2cError::MemoryInsufficient);
        }
        let mut session_key = [0u8; 40];
        session_key.copy_from_slice(&buf[0..40]);
        let master_sequence_number = u32::from_be_bytes(buf[40..44].try_into().unwrap());
        let save_slave_sequence_number = u32::from_be_bytes(buf[44..48].try_into().unwrap());
        let active = buf[48] != 0;
        Ok(Self {
            session_key,
            master_sequence_number,
            save_slave_sequence_number,
            active,
        })
    }
}

/// Presentation Layer coordinator managing Shielded Connections.
pub struct PresentationLayer<CRYPTO = RustCryptoBackend, DS = NoDatastore> {
    pub crypto: CRYPTO,
    pub datastore: DS,
    pub(crate) session_key: [u8; 40],
    pub master_sequence_number: u32,
    pub save_slave_sequence_number: u32,
    pub negotiation_state: bool,
    pub(crate) saved_sctr: u8,
    pub(crate) record_buf: [u8; RECORD_BUFFER_SIZE],
}

impl<CRYPTO, DS> PresentationLayer<CRYPTO, DS>
where
    CRYPTO: HostCrypto,
    DS: Datastore,
{
    /// Creates a new `PresentationLayer` instance.
    pub fn new(crypto: CRYPTO, datastore: DS) -> Self {
        Self {
            crypto,
            datastore,
            session_key: [0u8; 40],
            master_sequence_number: 0,
            save_slave_sequence_number: 0,
            negotiation_state: false,
            saved_sctr: 0,
            record_buf: [0u8; RECORD_BUFFER_SIZE],
        }
    }

    /// Resets active session state and zeroizes session keys.
    pub fn reset(&mut self) {
        self.session_key.zeroize();
        self.master_sequence_number = 0;
        self.save_slave_sequence_number = 0;
        self.negotiation_state = false;
        self.saved_sctr = 0;
    }

    /// Performs the 4-step TLS 1.2 PRF SHA-256 mutual handshake with the OPTIGA slave.
    pub fn do_handshake<I2C, T, VDD, RST>(
        &mut self,
        pl: &mut PhysicalLayer<I2C, T, VDD, RST>,
        dl: &mut DataLinkLayer,
        tl: &mut TransportLayer,
    ) -> Result<(), IfxI2cError>
    where
        I2C: OptigaI2cBus,
        T: OptigaTimer,
        VDD: OutputPin,
        RST: OutputPin,
    {
        let mut secret = [0u8; 64];
        let secret_len = self.prepare_handshake(&mut secret)?;

        // Step 2: Send MasterHello [SCTR=0x00, ProtoVer=0x01] (2 bytes)
        let master_hello = [0x00, 0x01];
        let rx_len = match tl.transceive(
            pl,
            dl,
            &master_hello,
            &mut self.record_buf,
            true, // Presentation layer presence bit set
        ) {
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

        let rx_len = tl.transceive(pl, dl, &tx_finished, &mut self.record_buf, true)?;
        self.verify_slave_finished(rx_len, &slave_random)
    }

    pub(crate) fn prepare_handshake(&mut self, secret: &mut [u8; 64]) -> Result<usize, IfxI2cError> {
        self.reset();
        // Clear any previously saved session context in datastore
        let _ = self
            .datastore
            .write(DatastoreId::ManageContext, &[0u8; 49]);

        // Step 1: Read platform binding shared secret from datastore
        self.datastore
            .read(DatastoreId::PlatformBindingSharedSecret, secret)
            .map_err(|_| IfxI2cError::HandshakeError)
    }

    pub(crate) fn process_slave_hello_and_build_master_finished(
        &mut self,
        rx_len: usize,
        secret: &mut [u8; 64],
        secret_len: usize,
        slave_random: &mut [u8; 32],
    ) -> Result<[u8; 49], IfxI2cError> {
        // Step 3: Verify SlaveHello [0x00, 0x01, Rnd(32B), SlaveSeq(4B BE)] (38 bytes)
        if rx_len != 38 || self.record_buf[0] != 0x00 || self.record_buf[1] != 0x01 {
            secret.zeroize();
            return Err(IfxI2cError::HandshakeError);
        }

        slave_random.copy_from_slice(&self.record_buf[2..34]);
        let slave_seq = u32::from_be_bytes(self.record_buf[34..38].try_into().unwrap());
        self.save_slave_sequence_number = slave_seq;

        // Derive 40-byte session key block using TLS 1.2 PRF
        let prf_res = self.crypto.tls_prf_sha256(
            &secret[..secret_len],
            b"Platform Binding",
            slave_random,
            &mut self.session_key,
        );
        secret.zeroize();
        prf_res.map_err(|_| IfxI2cError::HandshakeError)?;

        // Extract MasterEncKey
        let mut master_enc_key = [0u8; 16];
        master_enc_key.copy_from_slice(&self.session_key[0..16]);

        // Step 4: Construct MasterFinished:
        // Plaintext = Rnd(32B) || SlaveSeq(4B BE) (36 bytes)
        let mut finished_plaintext = [0u8; 36];
        finished_plaintext[0..32].copy_from_slice(slave_random);
        finished_plaintext[32..36].copy_from_slice(&slave_seq.to_be_bytes());

        // Nonce = MasterEncNonce[32..36] || SlaveSeq(4B BE)
        let mut nonce = [0u8; 8];
        nonce[0..4].copy_from_slice(&self.session_key[32..36]);
        nonce[4..8].copy_from_slice(&slave_seq.to_be_bytes());

        // AAD = [SCTR=0x08, SlaveSeq(4B BE), ProtoVer=0x01, PlainLen=0x0024] (8 bytes)
        let mut aad = [0u8; 8];
        aad[0] = 0x08;
        aad[1..5].copy_from_slice(&slave_seq.to_be_bytes());
        aad[5] = 0x01;
        aad[6..8].copy_from_slice(&36u16.to_be_bytes());

        // Encrypt in-place
        let tag = self
            .crypto
            .aes128_ccm_8_encrypt(&master_enc_key, &nonce, &aad, &mut finished_plaintext)
            .map_err(|_| {
                master_enc_key.zeroize();
                self.reset();
                IfxI2cError::HandshakeError
            })?;
        master_enc_key.zeroize();

        // Send MasterFinished: [0x08, SlaveSeq(4B), Ciphertext(36B), Tag(8B)] (49 bytes)
        let mut tx_finished = [0u8; 49];
        tx_finished[0] = 0x08;
        tx_finished[1..5].copy_from_slice(&slave_seq.to_be_bytes());
        tx_finished[5..41].copy_from_slice(&finished_plaintext);
        tx_finished[41..49].copy_from_slice(&tag);
        Ok(tx_finished)
    }

    pub(crate) fn verify_slave_finished(
        &mut self,
        rx_len: usize,
        slave_random: &[u8; 32],
    ) -> Result<(), IfxI2cError> {
        // Step 5: Verify SlaveFinished [0x08, MasterSeq(4B), Ciphertext(36B), Tag(8B)] (49 bytes)
        if rx_len != 49 || self.record_buf[0] != 0x08 {
            self.reset();
            return Err(IfxI2cError::HandshakeError);
        }

        let master_seq = u32::from_be_bytes(self.record_buf[1..5].try_into().unwrap());
        self.master_sequence_number = master_seq;

        let mut master_dec_key = [0u8; 16];
        master_dec_key.copy_from_slice(&self.session_key[16..32]);

        // Decrypt SlaveFinished
        let mut slave_nonce = [0u8; 8];
        slave_nonce[0..4].copy_from_slice(&self.session_key[36..40]);
        slave_nonce[4..8].copy_from_slice(&master_seq.to_be_bytes());

        let mut slave_aad = [0u8; 8];
        slave_aad[0] = 0x08;
        slave_aad[1..5].copy_from_slice(&master_seq.to_be_bytes());
        slave_aad[5] = 0x01;
        slave_aad[6..8].copy_from_slice(&36u16.to_be_bytes());

        let mut tag_in = [0u8; 8];
        tag_in.copy_from_slice(&self.record_buf[41..49]);

        let mut slave_payload = [0u8; 36];
        slave_payload.copy_from_slice(&self.record_buf[5..41]);

        let dec_res = self.crypto.aes128_ccm_8_decrypt(
            &master_dec_key,
            &slave_nonce,
            &slave_aad,
            &mut slave_payload,
            &tag_in,
        );
        master_dec_key.zeroize();

        if dec_res.is_err() {
            self.reset();
            return Err(IfxI2cError::HandshakeError);
        }

        // Verify decrypted payload matches Rnd || MasterSeq
        if slave_payload[0..32] != *slave_random || slave_payload[32..36] != master_seq.to_be_bytes() {
            self.reset();
            return Err(IfxI2cError::HandshakeError);
        }

        self.negotiation_state = true;
        Ok(())
    }

    pub(crate) fn requires_handshake(&self, protection: ProtectionConfig) -> bool {
        if protection.level == ProtectionLevel::None {
            return false;
        }
        if protection.force_reestablish || !self.negotiation_state {
            return true;
        }
        let master_rollover = matches!(
            protection.level,
            ProtectionLevel::Master | ProtectionLevel::Full
        ) && self.master_sequence_number >= PRL_SEQUENCE_THRESHOLD;
        let slave_rollover = matches!(
            protection.level,
            ProtectionLevel::Slave | ProtectionLevel::Full
        ) && self.save_slave_sequence_number >= PRL_SEQUENCE_THRESHOLD;
        master_rollover || slave_rollover
    }

    /// Transceives an APDU command payload in-place using `apdu_buf[..tx_len]` as input
    /// and writing the response into `apdu_buf[..rx_len]`.
    pub fn transceive_in_place<I2C, T, VDD, RST>(
        &mut self,
        pl: &mut PhysicalLayer<I2C, T, VDD, RST>,
        dl: &mut DataLinkLayer,
        tl: &mut TransportLayer,
        apdu_buf: &mut [u8],
        tx_len: usize,
        protection: ProtectionConfig,
    ) -> Result<usize, IfxI2cError>
    where
        I2C: OptigaI2cBus,
        T: OptigaTimer,
        VDD: OutputPin,
        RST: OutputPin,
    {
        if tx_len > OPTIGA_MAX_COMMS_BUFFER_SIZE || tx_len > apdu_buf.len() {
            return Err(IfxI2cError::MemoryInsufficient);
        }

        if self.requires_handshake(protection) {
            self.do_handshake(pl, dl, tl)?;
        }

        let sctr = Sctr::new_record(protection.level);
        self.saved_sctr = sctr.0;

        let mut data_retransmit_counter = 0;
        let mut decryption_failure_counter = 0;

        loop {
            let total_tx_len = self.encode_tx_record(&apdu_buf[..tx_len], sctr, protection.level)?;

            // Transceive record in-place inside self.record_buf via Transport Layer
            let mut rx_raw_len = tl.transceive_in_place(
                pl,
                dl,
                &mut self.record_buf,
                total_tx_len,
                true,
            )?;

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
                        rx_raw_len = tl.transceive(pl, dl, &alert, &mut self.record_buf, true)?;
                    }
                }
            }
        }
    }

    /// Transceives an APDU command payload under the requested protection level.
    pub fn transceive<I2C, T, VDD, RST>(
        &mut self,
        pl: &mut PhysicalLayer<I2C, T, VDD, RST>,
        dl: &mut DataLinkLayer,
        tl: &mut TransportLayer,
        tx_payload: &[u8],
        rx_payload: &mut [u8],
        protection: ProtectionConfig,
    ) -> Result<usize, IfxI2cError>
    where
        I2C: OptigaI2cBus,
        T: OptigaTimer,
        VDD: OutputPin,
        RST: OutputPin,
    {
        if tx_payload.len() > OPTIGA_MAX_COMMS_BUFFER_SIZE {
            return Err(IfxI2cError::MemoryInsufficient);
        }

        if self.requires_handshake(protection) {
            self.do_handshake(pl, dl, tl)?;
        }

        let sctr = Sctr::new_record(protection.level);
        self.saved_sctr = sctr.0;

        let mut data_retransmit_counter = 0;
        let mut decryption_failure_counter = 0;

        loop {
            let total_tx_len = self.encode_tx_record(tx_payload, sctr, protection.level)?;

            // Transceive record in-place inside self.record_buf via Transport Layer
            let mut rx_raw_len = tl.transceive_in_place(
                pl,
                dl,
                &mut self.record_buf,
                total_tx_len,
                true,
            )?;

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
                        rx_raw_len = tl.transceive(pl, dl, &alert, &mut self.record_buf, true)?;
                    }
                }
            }
        }
    }

    pub(crate) fn encode_tx_record(
        &mut self,
        tx_payload: &[u8],
        sctr: Sctr,
        level: ProtectionLevel,
    ) -> Result<usize, IfxI2cError> {
        match level {
            ProtectionLevel::Master | ProtectionLevel::Full => {
                self.master_sequence_number = self.master_sequence_number.wrapping_add(1);
                self.record_buf[0] = sctr.0;
                self.record_buf[1..5]
                    .copy_from_slice(&self.master_sequence_number.to_be_bytes());
                self.record_buf[5..5 + tx_payload.len()].copy_from_slice(tx_payload);

                let mut enc_key = [0u8; 16];
                enc_key.copy_from_slice(&self.session_key[0..16]);

                let mut nonce = [0u8; 8];
                nonce[0..4].copy_from_slice(&self.session_key[32..36]);
                nonce[4..8].copy_from_slice(&self.master_sequence_number.to_be_bytes());

                let mut aad = [0u8; 8];
                aad[0] = sctr.0;
                aad[1..5].copy_from_slice(&self.master_sequence_number.to_be_bytes());
                aad[5] = 0x01;
                aad[6..8].copy_from_slice(&(tx_payload.len() as u16).to_be_bytes());

                let tag = self
                    .crypto
                    .aes128_ccm_8_encrypt(
                        &enc_key,
                        &nonce,
                        &aad,
                        &mut self.record_buf[5..5 + tx_payload.len()],
                    )
                    .map_err(|_| {
                        enc_key.zeroize();
                        IfxI2cError::SessionError
                    })?;
                enc_key.zeroize();

                self.record_buf[5 + tx_payload.len()..13 + tx_payload.len()]
                    .copy_from_slice(&tag);
                Ok(tx_payload.len() + 13)
            }
            ProtectionLevel::None | ProtectionLevel::Slave => {
                self.record_buf[0] = sctr.0;
                self.record_buf[1..1 + tx_payload.len()].copy_from_slice(tx_payload);
                Ok(tx_payload.len() + 1)
            }
        }
    }

    pub(crate) fn decode_rx_record(
        &mut self,
        rx_raw_len: usize,
        rx_payload: &mut [u8],
        level: ProtectionLevel,
        data_retransmit_counter: &mut u8,
        decryption_failure_counter: &mut u8,
    ) -> Result<RxRecordOutcome, IfxI2cError> {
        if rx_raw_len < 1 {
            return Err(IfxI2cError::ProtocolError);
        }

        let resp_sctr = self.record_buf[0];
        if resp_sctr & 0x40 != 0 {
            // Alert received
            if resp_sctr == Sctr::INTEGRITY_VIOLATED_ALERT.0
                && rx_raw_len == 1
                && matches!(level, ProtectionLevel::Master | ProtectionLevel::Full)
                && *data_retransmit_counter < PRL_TRANS_REPEAT
            {
                *data_retransmit_counter += 1;
                return Ok(RxRecordOutcome::RetryMasterTx);
            }

            self.reset();
            return Err(IfxI2cError::SessionError);
        }

        if resp_sctr != self.saved_sctr {
            self.reset();
            return Err(IfxI2cError::SessionError);
        }

        match level {
            ProtectionLevel::Slave | ProtectionLevel::Full => {
                if rx_raw_len <= 13 {
                    self.reset();
                    return Err(IfxI2cError::SessionError);
                }

                let slave_seq =
                    u32::from_be_bytes(self.record_buf[1..5].try_into().unwrap());
                if slave_seq <= self.save_slave_sequence_number
                    || slave_seq
                        > self.save_slave_sequence_number + (PRL_TRANS_REPEAT as u32)
                {
                    self.reset();
                    return Err(IfxI2cError::SessionError);
                }

                let plain_len = rx_raw_len - 13;
                let mut dec_key = [0u8; 16];
                dec_key.copy_from_slice(&self.session_key[16..32]);

                let mut nonce = [0u8; 8];
                nonce[0..4].copy_from_slice(&self.session_key[36..40]);
                nonce[4..8].copy_from_slice(&slave_seq.to_be_bytes());

                let mut aad = [0u8; 8];
                aad[0] = resp_sctr;
                aad[1..5].copy_from_slice(&slave_seq.to_be_bytes());
                aad[5] = 0x01;
                aad[6..8].copy_from_slice(&(plain_len as u16).to_be_bytes());

                let mut tag = [0u8; 8];
                tag.copy_from_slice(&self.record_buf[5 + plain_len..13 + plain_len]);

                let dec_res = self.crypto.aes128_ccm_8_decrypt(
                    &dec_key,
                    &nonce,
                    &aad,
                    &mut self.record_buf[5..5 + plain_len],
                    &tag,
                );
                dec_key.zeroize();

                if dec_res.is_err() {
                    if *decryption_failure_counter < PRL_TRANS_REPEAT {
                        *decryption_failure_counter += 1;
                        return Ok(RxRecordOutcome::SendIntegrityAlert);
                    } else {
                        self.reset();
                        return Err(IfxI2cError::SessionError);
                    }
                }

                self.save_slave_sequence_number = slave_seq;

                if plain_len > rx_payload.len() {
                    return Err(IfxI2cError::MemoryInsufficient);
                }
                rx_payload[..plain_len]
                    .copy_from_slice(&self.record_buf[5..5 + plain_len]);
                Ok(RxRecordOutcome::Success(plain_len))
            }
            ProtectionLevel::None | ProtectionLevel::Master => {
                if rx_raw_len <= 1 {
                    return Err(IfxI2cError::ProtocolError);
                }
                let plain_len = rx_raw_len - 1;
                if plain_len > rx_payload.len() {
                    return Err(IfxI2cError::MemoryInsufficient);
                }
                rx_payload[..plain_len]
                    .copy_from_slice(&self.record_buf[1..rx_raw_len]);
                Ok(RxRecordOutcome::Success(plain_len))
            }
        }
    }

    /// Saves the active session context across hibernate.
    pub fn save_context<I2C, T, VDD, RST>(
        &mut self,
        pl: &mut PhysicalLayer<I2C, T, VDD, RST>,
        dl: &mut DataLinkLayer,
        tl: &mut TransportLayer,
    ) -> Result<(), IfxI2cError>
    where
        I2C: OptigaI2cBus,
        T: OptigaTimer,
        VDD: OutputPin,
        RST: OutputPin,
    {
        if !self.negotiation_state {
            return Ok(());
        }

        // Send SaveContext command [0x60]
        let rx_len = tl.transceive(pl, dl, &[0x60], &mut self.record_buf, true)?;
        self.finish_save_context(rx_len)
    }

    pub(crate) fn finish_save_context(&mut self, rx_len: usize) -> Result<(), IfxI2cError> {
        if rx_len < 1 || (self.record_buf[0] & 0xFC) != 0x64 {
            return Err(IfxI2cError::SessionError);
        }

        // Save serialized session context in datastore
        let saved = SavedSessionContext {
            session_key: self.session_key,
            master_sequence_number: self.master_sequence_number,
            save_slave_sequence_number: self.save_slave_sequence_number,
            active: true,
        };
        let mut buf = [0u8; 64];
        let len = saved.serialize(&mut buf)?;
        self.datastore
            .write(DatastoreId::ManageContext, &buf[..len])
            .map_err(|_| IfxI2cError::SessionError)?;

        self.reset();
        Ok(())
    }

    /// Restores a previously saved session context after hibernate.
    pub fn restore_context<I2C, T, VDD, RST>(
        &mut self,
        pl: &mut PhysicalLayer<I2C, T, VDD, RST>,
        dl: &mut DataLinkLayer,
        tl: &mut TransportLayer,
    ) -> Result<(), IfxI2cError>
    where
        I2C: OptigaI2cBus,
        T: OptigaTimer,
        VDD: OutputPin,
        RST: OutputPin,
    {
        let Some((saved, msg)) = self.prepare_restore_context()? else {
            return Ok(());
        };

        let rx_len = tl.transceive(pl, dl, &msg, &mut self.record_buf, true)?;
        self.finish_restore_context(rx_len, saved)
    }

    pub(crate) fn prepare_restore_context(
        &mut self,
    ) -> Result<Option<(SavedSessionContext, [u8; 5])>, IfxI2cError> {
        let mut buf = [0u8; 64];
        let len = self
            .datastore
            .read(DatastoreId::ManageContext, &mut buf)
            .map_err(|_| IfxI2cError::SessionError)?;
        let saved = SavedSessionContext::deserialize(&buf[..len])?;

        if !saved.active {
            return Ok(None);
        }

        // Send RestoreContext [0x68, slave_seq(4B)]
        let mut msg = [0u8; 5];
        msg[0] = 0x68;
        msg[1..5].copy_from_slice(&saved.save_slave_sequence_number.to_be_bytes());
        Ok(Some((saved, msg)))
    }

    pub(crate) fn finish_restore_context(
        &mut self,
        rx_len: usize,
        saved: SavedSessionContext,
    ) -> Result<(), IfxI2cError> {
        if rx_len < 1 || (self.record_buf[0] & 0xFC) != 0x6C {
            return Err(IfxI2cError::SessionError);
        }

        self.session_key = saved.session_key;
        self.master_sequence_number = saved.master_sequence_number;
        self.save_slave_sequence_number = saved.save_slave_sequence_number;
        self.negotiation_state = true;
        Ok(())
    }
}
