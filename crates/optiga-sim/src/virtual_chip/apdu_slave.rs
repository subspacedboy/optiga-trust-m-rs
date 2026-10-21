//! Simulated APDU and Presentation Layer responder for OPTIGA Trust M.

use optiga_trust_m_rs::ifx_i2c::headers::{ChainState, Pctr, Sctr};
use optiga_trust_m_rs::pal::rust_crypto::RustCryptoBackend;
use optiga_trust_m_rs::pal::HostCrypto;

/// Virtual slave APDU and Presentation Layer processor.
#[derive(Debug)]
pub struct VirtualApduEngine {
    pub last_error_code: u8,
    pub session_key: Option<[u8; 40]>,
    pub slave_seq: u32,
    pub master_seq: u32,
    pub rx_apdu_buf: Vec<u8>,
    pub force_next_command_failure: bool,
    pub app_opened: bool,
    pub slave_random: [u8; 32],
    pub last_sent_response_apdu: Option<(u8, Vec<u8>)>,
}

impl Default for VirtualApduEngine {
    fn default() -> Self {
        Self {
            last_error_code: 0x00,
            session_key: None,
            slave_seq: 1,
            master_seq: 0,
            rx_apdu_buf: Vec::new(),
            force_next_command_failure: false,
            app_opened: false,
            slave_random: [0x42; 32],
            last_sent_response_apdu: None,
        }
    }
}

impl VirtualApduEngine {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn reset(&mut self) {
        self.session_key = None;
        self.slave_seq = 1;
        self.master_seq = 0;
        self.rx_apdu_buf.clear();
        self.force_next_command_failure = false;
        self.app_opened = false;
    }

    /// Processes an incoming Transport Layer fragment.
    ///
    /// Returns `Some(response_packet)` when a full message is completed.
    pub fn process_tl_packet(
        &mut self,
        packet: &[u8],
        shared_secret: &[u8],
    ) -> Option<Vec<u8>> {
        if packet.is_empty() {
            return None;
        }

        let pctr = Pctr(packet[0]);
        let chain = pctr.chain_state().ok()?;
        let fragment_payload = &packet[1..];

        match chain {
            ChainState::No => {
                self.rx_apdu_buf.clear();
                self.rx_apdu_buf.extend_from_slice(fragment_payload);
                self.dispatch_message(pctr.has_presentation(), shared_secret)
            }
            ChainState::First => {
                self.rx_apdu_buf.clear();
                self.rx_apdu_buf.extend_from_slice(fragment_payload);
                None
            }
            ChainState::Intermediate => {
                self.rx_apdu_buf.extend_from_slice(fragment_payload);
                None
            }
            ChainState::Last => {
                self.rx_apdu_buf.extend_from_slice(fragment_payload);
                self.dispatch_message(pctr.has_presentation(), shared_secret)
            }
            ChainState::Error => {
                self.rx_apdu_buf.clear();
                None
            }
        }
    }

    fn dispatch_message(
        &mut self,
        has_presentation: bool,
        shared_secret: &[u8],
    ) -> Option<Vec<u8>> {
        if has_presentation {
            self.process_prl_message(shared_secret)
        } else {
            let resp_apdu = self.process_apdu(&self.rx_apdu_buf.clone());
            // Wrap in TL header (Pctr: No Chaining, No Presentation)
            let pctr = Pctr::new(false, ChainState::No);
            let mut out = vec![pctr.0];
            out.extend_from_slice(&resp_apdu);
            Some(out)
        }
    }

    fn process_prl_message(&mut self, shared_secret: &[u8]) -> Option<Vec<u8>> {
        if self.rx_apdu_buf.is_empty() {
            return None;
        }

        let sctr = Sctr(self.rx_apdu_buf[0]);
        if sctr.is_handshake() {
            if sctr == Sctr::MASTER_HELLO && self.rx_apdu_buf.len() == 2 {
                // Reply with SlaveHello: [0x00, 0x01, Rnd(32B), SlaveSeq(4B)]
                let mut out_payload = Vec::with_capacity(38);
                out_payload.push(0x00); // SCTR
                out_payload.push(0x01); // ProtoVer
                out_payload.extend_from_slice(&self.slave_random);
                out_payload.extend_from_slice(&self.slave_seq.to_be_bytes());

                // Derive session key
                let mut crypto = RustCryptoBackend;
                let mut session_key = [0u8; 40];
                let _ = crypto.tls_prf_sha256(
                    shared_secret,
                    b"Platform Binding",
                    &self.slave_random,
                    &mut session_key,
                );
                self.session_key = Some(session_key);

                // Wrap in TL packet (PCTR: No Chaining, Presence = true)
                let pctr = Pctr::new(true, ChainState::No);
                let mut packet = vec![pctr.0];
                packet.extend_from_slice(&out_payload);
                return Some(packet);
            } else if sctr == Sctr::MASTER_FINISHED && self.rx_apdu_buf.len() == 49 {
                // MasterFinished received: [0x08, SlaveSeq(4B), Ciphertext(36B), Tag(8B)]
                if let Some(session_key) = self.session_key {
                    let mut dec_key = [0u8; 16];
                    dec_key.copy_from_slice(&session_key[16..32]);

                    let slave_seq_in =
                        u32::from_be_bytes(self.rx_apdu_buf[1..5].try_into().unwrap());
                    if slave_seq_in != self.slave_seq {
                        return None;
                    }

                    // Form SlaveFinished:
                    // Plaintext = Rnd(32B) || MasterSeq(4B BE)
                    self.master_seq += 1;
                    let mut plaintext = Vec::with_capacity(36);
                    plaintext.extend_from_slice(&self.slave_random);
                    plaintext.extend_from_slice(&self.master_seq.to_be_bytes());

                    // Nonce = DecNonce[36..40] || MasterSeq
                    let mut nonce = [0u8; 8];
                    nonce[0..4].copy_from_slice(&session_key[36..40]);
                    nonce[4..8].copy_from_slice(&self.master_seq.to_be_bytes());

                    // AAD = [0x08, MasterSeq(4B), 0x01, 0x00, 0x24]
                    let mut aad = [0u8; 8];
                    aad[0] = 0x08;
                    aad[1..5].copy_from_slice(&self.master_seq.to_be_bytes());
                    aad[5] = 0x01;
                    aad[6..8].copy_from_slice(&36u16.to_be_bytes());

                    let mut crypto = RustCryptoBackend;
                    let tag = crypto
                        .aes128_ccm_8_encrypt(&dec_key, &nonce, &aad, &mut plaintext)
                        .ok()?;

                    let mut out_payload = Vec::with_capacity(49);
                    out_payload.push(0x08);
                    out_payload.extend_from_slice(&self.master_seq.to_be_bytes());
                    out_payload.extend_from_slice(&plaintext);
                    out_payload.extend_from_slice(&tag);

                    let pctr = Pctr::new(true, ChainState::No);
                    let mut packet = vec![pctr.0];
                    packet.extend_from_slice(&out_payload);
                    return Some(packet);
                }
            }
        } else if sctr.is_record_exchange() {
            let level = sctr.protection_level();
            let apdu_in = match level {
                optiga_trust_m_rs::ifx_i2c::headers::ProtectionLevel::Master
                | optiga_trust_m_rs::ifx_i2c::headers::ProtectionLevel::Full => {
                    let session_key = self.session_key?;
                    let mut enc_key = [0u8; 16];
                    enc_key.copy_from_slice(&session_key[0..16]);

                    if self.rx_apdu_buf.len() <= 13 {
                        return None;
                    }
                    let master_seq = u32::from_be_bytes(self.rx_apdu_buf[1..5].try_into().unwrap());
                    self.master_seq = master_seq;

                    let plain_len = self.rx_apdu_buf.len() - 13;
                    let mut nonce = [0u8; 8];
                    nonce[0..4].copy_from_slice(&session_key[32..36]);
                    nonce[4..8].copy_from_slice(&master_seq.to_be_bytes());

                    let mut aad = [0u8; 8];
                    aad[0] = sctr.0;
                    aad[1..5].copy_from_slice(&master_seq.to_be_bytes());
                    aad[5] = 0x01;
                    aad[6..8].copy_from_slice(&(plain_len as u16).to_be_bytes());

                    let mut tag = [0u8; 8];
                    tag.copy_from_slice(&self.rx_apdu_buf[5 + plain_len..13 + plain_len]);

                    let mut payload = self.rx_apdu_buf[5..5 + plain_len].to_vec();
                    let mut crypto = RustCryptoBackend;
                    crypto
                        .aes128_ccm_8_decrypt(&enc_key, &nonce, &aad, &mut payload, &tag)
                        .ok()?;
                    payload
                }
                optiga_trust_m_rs::ifx_i2c::headers::ProtectionLevel::None
                | optiga_trust_m_rs::ifx_i2c::headers::ProtectionLevel::Slave => {
                    self.rx_apdu_buf[1..].to_vec()
                }
            };

            let resp_apdu = self.process_apdu(&apdu_in);
            self.last_sent_response_apdu = Some((sctr.0, resp_apdu.clone()));

            // Construct response record
            let mut record_out = Vec::new();
            record_out.push(sctr.0);

            match level {
                optiga_trust_m_rs::ifx_i2c::headers::ProtectionLevel::Slave
                | optiga_trust_m_rs::ifx_i2c::headers::ProtectionLevel::Full => {
                    let session_key = self.session_key?;
                    let mut dec_key = [0u8; 16];
                    dec_key.copy_from_slice(&session_key[16..32]);

                    self.slave_seq += 1;
                    record_out.extend_from_slice(&self.slave_seq.to_be_bytes());

                    let mut nonce = [0u8; 8];
                    nonce[0..4].copy_from_slice(&session_key[36..40]);
                    nonce[4..8].copy_from_slice(&self.slave_seq.to_be_bytes());

                    let mut aad = [0u8; 8];
                    aad[0] = sctr.0;
                    aad[1..5].copy_from_slice(&self.slave_seq.to_be_bytes());
                    aad[5] = 0x01;
                    aad[6..8].copy_from_slice(&(resp_apdu.len() as u16).to_be_bytes());

                    let mut payload = resp_apdu;
                    let mut crypto = RustCryptoBackend;
                    let tag = crypto
                        .aes128_ccm_8_encrypt(&dec_key, &nonce, &aad, &mut payload)
                        .ok()?;

                    record_out.extend_from_slice(&payload);
                    record_out.extend_from_slice(&tag);
                }
                optiga_trust_m_rs::ifx_i2c::headers::ProtectionLevel::None
                | optiga_trust_m_rs::ifx_i2c::headers::ProtectionLevel::Master => {
                    record_out.extend_from_slice(&resp_apdu);
                }
            }

            let pctr = Pctr::new(true, ChainState::No);
            let mut packet = vec![pctr.0];
            packet.extend_from_slice(&record_out);
            return Some(packet);
        } else if sctr.is_alert() {
            if sctr == Sctr::INTEGRITY_VIOLATED_ALERT {
                // Slave retransmits last encrypted record with incremented slave_seq
                let session_key = self.session_key?;
                let (saved_sctr, resp_apdu) = self.last_sent_response_apdu.clone()?;
                let mut dec_key = [0u8; 16];
                dec_key.copy_from_slice(&session_key[16..32]);

                self.slave_seq += 1;
                let mut record_out = Vec::new();
                record_out.push(saved_sctr);
                record_out.extend_from_slice(&self.slave_seq.to_be_bytes());

                let mut nonce = [0u8; 8];
                nonce[0..4].copy_from_slice(&session_key[36..40]);
                nonce[4..8].copy_from_slice(&self.slave_seq.to_be_bytes());

                let mut aad = [0u8; 8];
                aad[0] = saved_sctr;
                aad[1..5].copy_from_slice(&self.slave_seq.to_be_bytes());
                aad[5] = 0x01;
                aad[6..8].copy_from_slice(&(resp_apdu.len() as u16).to_be_bytes());

                let mut payload = resp_apdu;
                let mut crypto = RustCryptoBackend;
                let tag = crypto
                    .aes128_ccm_8_encrypt(&dec_key, &nonce, &aad, &mut payload)
                    .ok()?;

                record_out.extend_from_slice(&payload);
                record_out.extend_from_slice(&tag);

                let pctr = Pctr::new(true, ChainState::No);
                let mut packet = vec![pctr.0];
                packet.extend_from_slice(&record_out);
                return Some(packet);
            }
        } else if sctr.is_manage_context() {
            if sctr == Sctr::SAVE_CONTEXT {
                // Reply with ContextSaved [0x64]
                let pctr = Pctr::new(true, ChainState::No);
                return Some(vec![pctr.0, 0x64]);
            } else if sctr == Sctr::RESTORE_CONTEXT && self.rx_apdu_buf.len() == 5 {
                // Reply with ContextRestored [0x6C, slave_seq(4B)]
                let pctr = Pctr::new(true, ChainState::No);
                let mut out = vec![pctr.0, 0x6C];
                out.extend_from_slice(&self.slave_seq.to_be_bytes());
                return Some(out);
            }
        }

        None
    }

    /// Processes raw APDU bytes.
    pub fn process_apdu(&mut self, apdu: &[u8]) -> Vec<u8> {
        if apdu.len() < 4 {
            return vec![0xFF, 0x00, 0x00, 0x00];
        }

        let cmd = apdu[0] & 0x7F; // Strip 0x80 clear error flag
        let _param = apdu[1];
        let in_len = u16::from_be_bytes([apdu[2], apdu[3]]) as usize;
        let in_data = if apdu.len() >= 4 + in_len {
            &apdu[4..4 + in_len]
        } else {
            &apdu[4..]
        };

        if self.force_next_command_failure {
            self.force_next_command_failure = false;
            self.last_error_code = 0x07; // AccessConditionNotSatisfied
            return vec![0xFF, 0x00, 0x00, 0x00]; // Sta = 0xFF
        }

        match cmd {
            0x70 => {
                // OpenApplication
                self.app_opened = true;
                vec![0x00, 0x00, 0x00, 0x00] // Success
            }
            0x71 => {
                // CloseApplication
                self.app_opened = false;
                vec![0x00, 0x00, 0x00, 0x00]
            }
            0x01 => {
                // GetDataObject
                if in_data.len() >= 6 {
                    let oid = u16::from_be_bytes([in_data[0], in_data[1]]);
                    if oid == 0xF1C2 {
                        // Return last error code
                        let err = self.last_error_code;
                        return vec![0x00, 0x00, 0x00, 0x01, err];
                    }
                }
                // Return dummy 4 bytes of data
                vec![0x00, 0x00, 0x00, 0x04, 0xDE, 0xAD, 0xBE, 0xEF]
            }
            0x0C => {
                // GetRandom
                let req_len = if in_data.len() >= 2 {
                    u16::from_be_bytes([in_data[0], in_data[1]]) as usize
                } else {
                    16
                };
                let mut out = vec![0x00, 0x00];
                out.extend_from_slice(&(req_len as u16).to_be_bytes());
                for i in 0..req_len {
                    out.push((i & 0xFF) as u8);
                }
                out
            }
            0x02 => {
                // SetDataObject
                vec![0x00, 0x00, 0x00, 0x00]
            }
            0x38 => {
                // GenKeyPair: Return TLV 0x02 (64-byte public key)
                let mut pubkey = vec![0x04]; // Uncompressed point prefix
                for i in 1..65 {
                    pubkey.push(i as u8);
                }
                let mut out = vec![0x00, 0x00];
                let out_len = (3 + pubkey.len()) as u16;
                out.extend_from_slice(&out_len.to_be_bytes());
                out.push(0x02); // Tag 0x02
                out.extend_from_slice(&(pubkey.len() as u16).to_be_bytes());
                out.extend_from_slice(&pubkey);
                out
            }
            0x31 => {
                // CalcSign: Return TLV 0x02 (64-byte signature)
                let sig = vec![0x55; 64];
                let mut out = vec![0x00, 0x00];
                let out_len = (3 + sig.len()) as u16;
                out.extend_from_slice(&out_len.to_be_bytes());
                out.push(0x02); // Tag 0x02
                out.extend_from_slice(&(sig.len() as u16).to_be_bytes());
                out.extend_from_slice(&sig);
                out
            }
            0x32 => {
                // VerifySign
                vec![0x00, 0x00, 0x00, 0x00]
            }
            0x33 => {
                // CalcSSec: Return TLV 0x07 (32-byte shared secret)
                let ssec = vec![0x33; 32];
                let mut out = vec![0x00, 0x00];
                let out_len = (3 + ssec.len()) as u16;
                out.extend_from_slice(&out_len.to_be_bytes());
                out.push(0x07); // Tag 0x07
                out.extend_from_slice(&(ssec.len() as u16).to_be_bytes());
                out.extend_from_slice(&ssec);
                out
            }
            _ => {
                // Generic success
                vec![0x00, 0x00, 0x00, 0x00]
            }
        }
    }
}
