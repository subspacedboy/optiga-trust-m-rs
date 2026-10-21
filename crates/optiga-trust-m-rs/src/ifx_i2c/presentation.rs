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
use crate::pal::{Datastore, DatastoreId, HostCrypto, MonotonicClock, OptigaI2cBus};
use embedded_hal::delay::DelayNs;
use embedded_hal::digital::OutputPin;
use zeroize::Zeroize;

/// Total Presentation Layer record buffer capacity (1557 + 13 = 1570 bytes).
const RECORD_BUFFER_SIZE: usize = OPTIGA_MAX_COMMS_BUFFER_SIZE + PRL_OVERHEAD_SIZE;

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
pub struct PresentationLayer<CRYPTO, DS> {
    pub crypto: CRYPTO,
    pub datastore: DS,
    session_key: [u8; 40],
    pub master_sequence_number: u32,
    pub save_slave_sequence_number: u32,
    pub negotiation_state: bool,
    saved_sctr: u8,
    tx_record_buf: [u8; RECORD_BUFFER_SIZE],
    rx_record_buf: [u8; RECORD_BUFFER_SIZE],
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
            tx_record_buf: [0u8; RECORD_BUFFER_SIZE],
            rx_record_buf: [0u8; RECORD_BUFFER_SIZE],
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
    pub fn do_handshake<I2C, D, VDD, RST, CLK>(
        &mut self,
        pl: &mut PhysicalLayer<I2C, D, VDD, RST>,
        dl: &mut DataLinkLayer,
        tl: &mut TransportLayer,
        clock: &CLK,
    ) -> Result<(), IfxI2cError>
    where
        I2C: OptigaI2cBus,
        D: DelayNs,
        VDD: OutputPin,
        RST: OutputPin,
        CLK: MonotonicClock,
    {
        // Step 1: Read platform binding shared secret from datastore
        let mut secret = [0u8; 64];
        let secret_len = self
            .datastore
            .read(DatastoreId::PlatformBindingSharedSecret, &mut secret)
            .map_err(|_| IfxI2cError::HandshakeError)?;

        // Step 2: Send MasterHello [SCTR=0x00, ProtoVer=0x01] (2 bytes)
        let master_hello = [0x00, 0x01];
        let rx_len = tl.transceive(
            pl,
            dl,
            clock,
            &master_hello,
            &mut self.rx_record_buf,
            true, // Presentation layer presence bit set
        )?;

        // Step 3: Verify SlaveHello [0x00, 0x01, Rnd(32B), SlaveSeq(4B BE)] (38 bytes)
        if rx_len != 38 || self.rx_record_buf[0] != 0x00 || self.rx_record_buf[1] != 0x01 {
            secret.zeroize();
            return Err(IfxI2cError::HandshakeError);
        }

        let mut slave_random = [0u8; 32];
        slave_random.copy_from_slice(&self.rx_record_buf[2..34]);
        let slave_seq = u32::from_be_bytes(self.rx_record_buf[34..38].try_into().unwrap());
        self.save_slave_sequence_number = slave_seq;

        // Derive 40-byte session key block using TLS 1.2 PRF
        self.crypto
            .tls_prf_sha256(
                &secret[..secret_len],
                b"Platform Binding",
                &slave_random,
                &mut self.session_key,
            )
            .map_err(|_| IfxI2cError::HandshakeError)?;
        secret.zeroize();

        // Extract key slices
        let mut master_enc_key = [0u8; 16];
        master_enc_key.copy_from_slice(&self.session_key[0..16]);
        let mut master_dec_key = [0u8; 16];
        master_dec_key.copy_from_slice(&self.session_key[16..32]);

        // Step 4: Construct MasterFinished:
        // Plaintext = Rnd(32B) || SlaveSeq(4B BE) (36 bytes)
        let mut finished_plaintext = [0u8; 36];
        finished_plaintext[0..32].copy_from_slice(&slave_random);
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
            .map_err(|_| IfxI2cError::HandshakeError)?;

        // Send MasterFinished: [0x08, SlaveSeq(4B), Ciphertext(36B), Tag(8B)] (49 bytes)
        let mut tx_finished = [0u8; 49];
        tx_finished[0] = 0x08;
        tx_finished[1..5].copy_from_slice(&slave_seq.to_be_bytes());
        tx_finished[5..41].copy_from_slice(&finished_plaintext);
        tx_finished[41..49].copy_from_slice(&tag);

        let rx_len = tl.transceive(pl, dl, clock, &tx_finished, &mut self.rx_record_buf, true)?;

        // Step 5: Verify SlaveFinished [0x08, MasterSeq(4B), Ciphertext(36B), Tag(8B)] (49 bytes)
        if rx_len != 49 || self.rx_record_buf[0] != 0x08 {
            self.reset();
            return Err(IfxI2cError::HandshakeError);
        }

        let master_seq = u32::from_be_bytes(self.rx_record_buf[1..5].try_into().unwrap());
        self.master_sequence_number = master_seq;

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
        tag_in.copy_from_slice(&self.rx_record_buf[41..49]);

        let mut slave_payload = [0u8; 36];
        slave_payload.copy_from_slice(&self.rx_record_buf[5..41]);

        if self
            .crypto
            .aes128_ccm_8_decrypt(&master_dec_key, &slave_nonce, &slave_aad, &mut slave_payload, &tag_in)
            .is_err()
        {
            self.reset();
            return Err(IfxI2cError::HandshakeError);
        }

        // Verify decrypted payload matches Rnd || MasterSeq
        if slave_payload[0..32] != slave_random || slave_payload[32..36] != master_seq.to_be_bytes() {
            self.reset();
            return Err(IfxI2cError::HandshakeError);
        }

        self.negotiation_state = true;
        Ok(())
    }

    /// Transceives an APDU command payload under the requested protection level.
    #[allow(clippy::too_many_arguments)]
    pub fn transceive<I2C, D, VDD, RST, CLK>(
        &mut self,
        pl: &mut PhysicalLayer<I2C, D, VDD, RST>,
        dl: &mut DataLinkLayer,
        tl: &mut TransportLayer,
        clock: &CLK,
        tx_payload: &[u8],
        rx_payload: &mut [u8],
        protection: ProtectionConfig,
    ) -> Result<usize, IfxI2cError>
    where
        I2C: OptigaI2cBus,
        D: DelayNs,
        VDD: OutputPin,
        RST: OutputPin,
        CLK: MonotonicClock,
    {
        // Check if handshake is required
        if (protection.force_reestablish
            || !self.negotiation_state
            || self.master_sequence_number >= PRL_SEQUENCE_THRESHOLD
            || self.save_slave_sequence_number >= PRL_SEQUENCE_THRESHOLD)
            && protection.level != ProtectionLevel::None
        {
            self.do_handshake(pl, dl, tl, clock)?;
        }

        let sctr = Sctr::new_record(protection.level);
        self.saved_sctr = sctr.0;

        let total_tx_len = match protection.level {
            ProtectionLevel::Master | ProtectionLevel::Full => {
                self.master_sequence_number = self.master_sequence_number.wrapping_add(1);
                self.tx_record_buf[0] = sctr.0;
                self.tx_record_buf[1..5].copy_from_slice(&self.master_sequence_number.to_be_bytes());
                self.tx_record_buf[5..5 + tx_payload.len()].copy_from_slice(tx_payload);

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
                        &mut self.tx_record_buf[5..5 + tx_payload.len()],
                    )
                    .map_err(|_| IfxI2cError::SessionError)?;

                self.tx_record_buf[5 + tx_payload.len()..13 + tx_payload.len()].copy_from_slice(&tag);
                tx_payload.len() + 13
            }
            ProtectionLevel::None | ProtectionLevel::Slave => {
                self.tx_record_buf[0] = sctr.0;
                self.tx_record_buf[1..1 + tx_payload.len()].copy_from_slice(tx_payload);
                tx_payload.len() + 1
            }
        };

        // Transceive record via Transport Layer
        let rx_raw_len = tl.transceive(
            pl,
            dl,
            clock,
            &self.tx_record_buf[..total_tx_len],
            &mut self.rx_record_buf,
            true,
        )?;

        // Verify incoming record response
        if rx_raw_len < 1 {
            return Err(IfxI2cError::ProtocolError);
        }

        let resp_sctr = self.rx_record_buf[0];
        if resp_sctr & 0x40 != 0 {
            // Alert received
            self.reset();
            return Err(IfxI2cError::SessionError);
        }

        if resp_sctr != self.saved_sctr {
            self.reset();
            return Err(IfxI2cError::SessionError);
        }

        match protection.level {
            ProtectionLevel::Slave | ProtectionLevel::Full => {
                if rx_raw_len <= 13 {
                    return Err(IfxI2cError::ProtocolError);
                }

                let slave_seq = u32::from_be_bytes(self.rx_record_buf[1..5].try_into().unwrap());
                if slave_seq <= self.save_slave_sequence_number
                    || slave_seq > self.save_slave_sequence_number + (PRL_TRANS_REPEAT as u32)
                {
                    self.reset();
                    return Err(IfxI2cError::SessionError);
                }
                self.save_slave_sequence_number = slave_seq;

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
                tag.copy_from_slice(&self.rx_record_buf[5 + plain_len..13 + plain_len]);

                if self
                    .crypto
                    .aes128_ccm_8_decrypt(
                        &dec_key,
                        &nonce,
                        &aad,
                        &mut self.rx_record_buf[5..5 + plain_len],
                        &tag,
                    )
                    .is_err()
                {
                    self.reset();
                    return Err(IfxI2cError::SessionError);
                }

                if plain_len > rx_payload.len() {
                    return Err(IfxI2cError::MemoryInsufficient);
                }
                rx_payload[..plain_len].copy_from_slice(&self.rx_record_buf[5..5 + plain_len]);
                Ok(plain_len)
            }
            ProtectionLevel::None | ProtectionLevel::Master => {
                let plain_len = rx_raw_len - 1;
                if plain_len > rx_payload.len() {
                    return Err(IfxI2cError::MemoryInsufficient);
                }
                rx_payload[..plain_len].copy_from_slice(&self.rx_record_buf[1..rx_raw_len]);
                Ok(plain_len)
            }
        }
    }

    /// Saves the active session context across hibernate.
    pub fn save_context<I2C, D, VDD, RST, CLK>(
        &mut self,
        pl: &mut PhysicalLayer<I2C, D, VDD, RST>,
        dl: &mut DataLinkLayer,
        tl: &mut TransportLayer,
        clock: &CLK,
    ) -> Result<(), IfxI2cError>
    where
        I2C: OptigaI2cBus,
        D: DelayNs,
        VDD: OutputPin,
        RST: OutputPin,
        CLK: MonotonicClock,
    {
        if !self.negotiation_state {
            return Ok(());
        }

        // Send SaveContext command [0x60]
        let rx_len = tl.transceive(pl, dl, clock, &[0x60], &mut self.rx_record_buf, true)?;
        if rx_len < 1 || (self.rx_record_buf[0] & 0xFC) != 0x64 {
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
    pub fn restore_context<I2C, D, VDD, RST, CLK>(
        &mut self,
        pl: &mut PhysicalLayer<I2C, D, VDD, RST>,
        dl: &mut DataLinkLayer,
        tl: &mut TransportLayer,
        clock: &CLK,
    ) -> Result<(), IfxI2cError>
    where
        I2C: OptigaI2cBus,
        D: DelayNs,
        VDD: OutputPin,
        RST: OutputPin,
        CLK: MonotonicClock,
    {
        let mut buf = [0u8; 64];
        let len = self
            .datastore
            .read(DatastoreId::ManageContext, &mut buf)
            .map_err(|_| IfxI2cError::SessionError)?;
        let saved = SavedSessionContext::deserialize(&buf[..len])?;

        if !saved.active {
            return Ok(());
        }

        // Send RestoreContext [0x68, slave_seq(4B)]
        let mut msg = [0u8; 5];
        msg[0] = 0x68;
        msg[1..5].copy_from_slice(&saved.save_slave_sequence_number.to_be_bytes());

        let rx_len = tl.transceive(pl, dl, clock, &msg, &mut self.rx_record_buf, true)?;
        if rx_len < 1 || (self.rx_record_buf[0] & 0xFC) != 0x6C {
            return Err(IfxI2cError::SessionError);
        }

        self.session_key = saved.session_key;
        self.master_sequence_number = saved.master_sequence_number;
        self.save_slave_sequence_number = saved.save_slave_sequence_number;
        self.negotiation_state = true;
        Ok(())
    }
}
