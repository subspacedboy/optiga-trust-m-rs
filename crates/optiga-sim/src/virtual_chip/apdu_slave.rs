//! Simulated APDU and Presentation Layer responder for OPTIGA Trust M.

use optiga_trust_m_rs::cmd::tlv::TlvReader;
use optiga_trust_m_rs::config::OPTIGA_APPLICATION_ID;
use optiga_trust_m_rs::ifx_i2c::headers::{ChainState, Pctr, Sctr};
use optiga_trust_m_rs::pal::rust_crypto::RustCryptoBackend;
use optiga_trust_m_rs::pal::HostCrypto;
use sha2::{Digest, Sha256};

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
        let param = apdu[1];
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
                // OpenApplication: verify 16-byte OPTIGA_APPLICATION_ID (or 24 bytes on hibernate restore)
                let valid = if param == 0x01 {
                    in_data.len() == 24 && in_data[..16] == OPTIGA_APPLICATION_ID
                } else {
                    in_data.is_empty() || (in_data.len() == 16 && in_data == OPTIGA_APPLICATION_ID)
                };
                if !valid {
                    self.last_error_code = 0x02; // InvalidCommandField
                    return vec![0xFF, 0x00, 0x00, 0x00];
                }
                self.app_opened = true;
                vec![0x00, 0x00, 0x00, 0x00] // Success
            }
            0x71 => {
                // CloseApplication
                self.app_opened = false;
                if param == 0x01 {
                    // Return 8-byte hibernate context handle
                    vec![
                        0x00, 0x00, 0x00, 0x08, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8,
                    ]
                } else {
                    vec![0x00, 0x00, 0x00, 0x00]
                }
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
                    out.push(((i + 1) & 0xFF) as u8);
                }
                out
            }
            0x02 => {
                // SetDataObject: requires at least [OID(2B), Offset(2B), Data(>=1B)]
                if in_data.len() < 5 {
                    self.last_error_code = 0x02; // InvalidCommandField
                    return vec![0xFF, 0x00, 0x00, 0x00];
                }
                vec![0x00, 0x00, 0x00, 0x00]
            }
            0x03 => {
                // SetObjectProtected: verify TLV tag 0x81, 0x82, or 0x83
                let mut reader = TlvReader::new(in_data);
                if let Some((tag, _val)) = reader.next() {
                    if matches!(tag, 0x81..=0x83) {
                        return vec![0x00, 0x00, 0x00, 0x00];
                    }
                }
                self.last_error_code = 0x02;
                vec![0xFF, 0x00, 0x00, 0x00]
            }
            0x30 => {
                // CalcHash (SHA-256 = 0xE2)
                let mut reader = TlvReader::new(in_data);
                if let Some((tag, val)) = reader.next() {
                    let digest = if tag == 0x00 {
                        // StartFinal over host data
                        Sha256::digest(val)
                    } else if tag == 0x06 && val.len() == 6 {
                        // Hash over OID data [0xDE, 0xAD, 0xBE, 0xEF]
                        Sha256::digest([0xDE, 0xAD, 0xBE, 0xEF])
                    } else {
                        self.last_error_code = 0x02;
                        return vec![0xFF, 0x00, 0x00, 0x00];
                    };
                    let mut out = vec![0x00, 0x00, 0x00, 35, 0x00, 0x00, 32];
                    out.extend_from_slice(&digest);
                    return out;
                }
                self.last_error_code = 0x02;
                vec![0xFF, 0x00, 0x00, 0x00]
            }
            0x38 => {
                // GenKeyPair:
                // Either (Tag 0x01 OID + Tag 0x02 KeyUsage, NO Tag 0x07) OR (Tag 0x07 empty value ONLY)
                let mut reader = TlvReader::new(in_data);
                let has_oid = reader.find_tag(0x01).is_some();
                let has_usage = reader.find_tag(0x02).is_some();
                let export_tag = reader.find_tag(0x07);

                if (has_oid && export_tag.is_some())
                    || (!has_oid && export_tag != Some(&[][..]))
                    || (has_oid && !has_usage)
                {
                    self.last_error_code = 0x02; // InvalidCommandField
                    return vec![0xFF, 0x00, 0x00, 0x00];
                }

                let mut pubkey = vec![0x04]; // Uncompressed point prefix
                for i in 1..65 {
                    pubkey.push(i as u8);
                }

                let mut tlv_out = Vec::new();
                if export_tag.is_some() {
                    let privkey = vec![0xAA; 0x22];
                    tlv_out.push(0x01);
                    tlv_out.extend_from_slice(&(privkey.len() as u16).to_be_bytes());
                    tlv_out.extend_from_slice(&privkey);
                }
                tlv_out.push(0x02);
                tlv_out.extend_from_slice(&(pubkey.len() as u16).to_be_bytes());
                tlv_out.extend_from_slice(&pubkey);

                let mut out = vec![0x00, 0x00];
                out.extend_from_slice(&(tlv_out.len() as u16).to_be_bytes());
                out.extend_from_slice(&tlv_out);
                out
            }
            0x31 => {
                // CalcSign: Return ASN.1 DER (r, s) INTEGER pair directly in OutData
                // [0x02, 0x20, r(32B), 0x02, 0x20, s(32B)] = 68 bytes
                let mut der_sig = Vec::with_capacity(68);
                der_sig.push(0x02);
                der_sig.push(0x20);
                der_sig.extend_from_slice(&[0x55; 32]);
                der_sig.push(0x02);
                der_sig.push(0x20);
                der_sig.extend_from_slice(&[0x66; 32]);

                let mut out = vec![0x00, 0x00];
                out.extend_from_slice(&(der_sig.len() as u16).to_be_bytes());
                out.extend_from_slice(&der_sig);
                out
            }
            0x32 => {
                // VerifySign
                vec![0x00, 0x00, 0x00, 0x00]
            }
            0x33 => {
                // CalcSSec:
                // Tag 0x07 (empty value) -> export raw shared secret directly in OutData
                // Tag 0x08 (2B session OID) -> store in session, return empty OutData
                let mut reader = TlvReader::new(in_data);
                let export_tag = reader.find_tag(0x07);
                let store_tag = reader.find_tag(0x08);
                if export_tag == Some(&[][..]) {
                    let ssec = vec![0x33; 32];
                    let mut out = vec![0x00, 0x00];
                    out.extend_from_slice(&(ssec.len() as u16).to_be_bytes());
                    out.extend_from_slice(&ssec);
                    out
                } else if let Some(oid_bytes) = store_tag {
                    if oid_bytes.len() == 2 {
                        vec![0x00, 0x00, 0x00, 0x00]
                    } else {
                        self.last_error_code = 0x02;
                        vec![0xFF, 0x00, 0x00, 0x00]
                    }
                } else {
                    self.last_error_code = 0x02;
                    vec![0xFF, 0x00, 0x00, 0x00]
                }
            }
            0x34 => {
                // DeriveKey:
                // Tag 0x01 (2B secret OID), Tag 0x03 (2B key len), Tag 0x02 (derivation data),
                // Tag 0x07 (empty export) OR Tag 0x08 (2B session OID)
                let mut reader = TlvReader::new(in_data);
                let key_len_bytes = match reader.find_tag(0x03) {
                    Some(b) if b.len() == 2 => u16::from_be_bytes([b[0], b[1]]) as usize,
                    _ => {
                        self.last_error_code = 0x02;
                        return vec![0xFF, 0x00, 0x00, 0x00];
                    }
                };
                if reader.find_tag(0x07) == Some(&[][..]) {
                    let mut out = vec![0x00, 0x00];
                    out.extend_from_slice(&(key_len_bytes as u16).to_be_bytes());
                    for i in 0..key_len_bytes {
                        out.push((0xA0 + (i & 0x1F)) as u8);
                    }
                    out
                } else if reader.find_tag(0x08).map(|b| b.len()) == Some(2) {
                    vec![0x00, 0x00, 0x00, 0x00]
                } else {
                    self.last_error_code = 0x02;
                    vec![0xFF, 0x00, 0x00, 0x00]
                }
            }
            _ => {
                // Generic success
                vec![0x00, 0x00, 0x00, 0x00]
            }
        }
    }
}
