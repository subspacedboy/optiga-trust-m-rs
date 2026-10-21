//! Slave-side Data Link Layer state machine and frame codec.

use optiga_trust_m_rs::ifx_i2c::headers::{
    crc16_ccitt, Fctr, FrameType, SeqCtrl,
};
use std::collections::VecDeque;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DlError {
    FrameTooShort,
    BadCrc { expected: u16, actual: u16 },
    InvalidLengthField,
}

/// Incoming Data Link frame received from master.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceivedFrame {
    Control(Fctr),
    Data {
        fctr: Fctr,
        payload: Vec<u8>,
        is_duplicate: bool,
    },
}

/// Simulated OPTIGA slave Data Link Layer.
#[derive(Debug)]
pub struct SlaveDataLink {
    pub tx_seq_nr: u8,
    pub rx_seq_nr: u8,
    pub tx_queue: VecDeque<Vec<u8>>,
    pub last_sent_data_frame: Option<Vec<u8>>,
}

impl Default for SlaveDataLink {
    fn default() -> Self {
        Self {
            tx_seq_nr: 3,
            rx_seq_nr: 3,
            tx_queue: VecDeque::new(),
            last_sent_data_frame: None,
        }
    }
}

impl SlaveDataLink {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn reset(&mut self) {
        self.tx_seq_nr = 3;
        self.rx_seq_nr = 3;
        self.tx_queue.clear();
        self.last_sent_data_frame = None;
    }

    /// Checks if a response frame is ready to be read from `0x80`.
    pub fn has_pending_frame(&self) -> bool {
        !self.tx_queue.is_empty()
    }

    /// Returns the length in bytes of the next pending frame.
    pub fn pending_frame_len(&self) -> u16 {
        self.tx_queue.front().map(|f| f.len() as u16).unwrap_or(0)
    }

    /// Pops the next pending frame for master to read from `0x80`.
    pub fn pop_pending_frame(&mut self) -> Option<Vec<u8>> {
        self.tx_queue.pop_front()
    }

    /// Processes an incoming raw frame received via `0x80` write.
    pub fn receive_frame(&mut self, raw: &[u8]) -> Result<ReceivedFrame, DlError> {
        if raw.len() < 5 {
            return Err(DlError::FrameTooShort);
        }

        // Verify CRC-16
        let payload_len = raw.len() - 5;
        let expected_crc = u16::from_be_bytes([raw[raw.len() - 2], raw[raw.len() - 1]]);
        let actual_crc = crc16_ccitt(&raw[..raw.len() - 2]);
        if expected_crc != actual_crc {
            // Queue NACK CF with expected sequence
            let nack_acknr = (self.rx_seq_nr + 1) & 0x03;
            self.queue_control_frame(SeqCtrl::Nack, nack_acknr);
            return Err(DlError::BadCrc {
                expected: expected_crc,
                actual: actual_crc,
            });
        }

        let fctr = Fctr(raw[0]);
        let declared_len = u16::from_be_bytes([raw[1], raw[2]]) as usize;
        if declared_len != payload_len {
            return Err(DlError::InvalidLengthField);
        }

        match fctr.frame_type() {
            FrameType::Control => {
                match fctr.seq_ctrl() {
                    SeqCtrl::Ack => {
                        // Master acknowledged our sent data frame
                        if fctr.ack_nr() == self.tx_seq_nr {
                            self.last_sent_data_frame = None;
                        }
                    }
                    SeqCtrl::Nack => {
                        // Master NACKed; re-queue last sent data frame if present
                        if let Some(ref last) = self.last_sent_data_frame {
                            self.tx_queue.push_front(last.clone());
                        }
                    }
                    SeqCtrl::Resync => {
                        // Reset sequences
                        self.reset();
                        // Reply with RESYNC CF
                        self.queue_control_frame(SeqCtrl::Resync, 0);
                    }
                    SeqCtrl::Rfu => {}
                }
                Ok(ReceivedFrame::Control(fctr))
            }
            FrameType::Data => {
                let fr_nr = fctr.fr_nr();
                let expected_next = (self.rx_seq_nr + 1) & 0x03;
                let payload = raw[3..3 + payload_len].to_vec();

                if fr_nr == expected_next {
                    // Valid new data frame
                    self.rx_seq_nr = fr_nr;
                    // Master acknowledged our previous tx_seq_nr via fctr.ack_nr()
                    if fctr.ack_nr() == self.tx_seq_nr {
                        self.last_sent_data_frame = None;
                    }
                    Ok(ReceivedFrame::Data {
                        fctr,
                        payload,
                        is_duplicate: false,
                    })
                } else if fr_nr == self.rx_seq_nr {
                    // Duplicate frame from master: re-send ACK for rx_seq_nr
                    self.queue_control_frame(SeqCtrl::Ack, self.rx_seq_nr);
                    Ok(ReceivedFrame::Data {
                        fctr,
                        payload,
                        is_duplicate: true,
                    })
                } else {
                    // Out-of-sequence frame: send NACK for expected
                    self.queue_control_frame(SeqCtrl::Nack, expected_next);
                    Ok(ReceivedFrame::Data {
                        fctr,
                        payload,
                        is_duplicate: false,
                    })
                }
            }
        }
    }

    /// Queues a Control Frame (ACK, NACK, RESYNC).
    pub fn queue_control_frame(&mut self, seq_ctrl: SeqCtrl, ack_nr: u8) {
        let fctr = Fctr::new(FrameType::Control, seq_ctrl, 0, ack_nr);
        let mut frame = vec![fctr.0, 0x00, 0x00];
        let crc = crc16_ccitt(&frame);
        frame.extend_from_slice(&crc.to_be_bytes());
        self.tx_queue.push_back(frame);
    }

    /// Encodes and queues a Data Frame with the given payload.
    pub fn queue_data_frame(&mut self, payload: &[u8]) {
        self.tx_seq_nr = (self.tx_seq_nr + 1) & 0x03;
        let fctr = Fctr::new(FrameType::Data, SeqCtrl::Ack, self.tx_seq_nr, self.rx_seq_nr);
        let len_be = (payload.len() as u16).to_be_bytes();

        let mut frame = Vec::with_capacity(5 + payload.len());
        frame.push(fctr.0);
        frame.extend_from_slice(&len_be);
        frame.extend_from_slice(payload);

        let crc = crc16_ccitt(&frame);
        frame.extend_from_slice(&crc.to_be_bytes());

        self.last_sent_data_frame = Some(frame.clone());
        self.tx_queue.push_back(frame);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_slave_dl_receive_valid_data_frame() {
        let mut dl = SlaveDataLink::new();

        // Master sends DF: FRNR = 0, ACKNR = 3, payload = [0xAA, 0xBB]
        let fctr = Fctr::new(FrameType::Data, SeqCtrl::Ack, 0, 3);
        let mut raw = vec![fctr.0, 0x00, 0x02, 0xAA, 0xBB];
        let crc = crc16_ccitt(&raw);
        raw.extend_from_slice(&crc.to_be_bytes());

        let res = dl.receive_frame(&raw).unwrap();
        match res {
            ReceivedFrame::Data { fctr: f, payload, is_duplicate } => {
                assert_eq!(f.fr_nr(), 0);
                assert_eq!(payload, vec![0xAA, 0xBB]);
                assert!(!is_duplicate);
            }
            _ => panic!("Expected data frame"),
        }
        assert_eq!(dl.rx_seq_nr, 0);
    }

    #[test]
    fn test_slave_dl_crc_error_emits_nack() {
        let mut dl = SlaveDataLink::new();

        // Master sends DF with invalid CRC
        let fctr = Fctr::new(FrameType::Data, SeqCtrl::Ack, 0, 3);
        let raw = vec![fctr.0, 0x00, 0x02, 0xAA, 0xBB, 0xFF, 0xFF]; // Bad CRC

        let res = dl.receive_frame(&raw);
        assert!(res.is_err());
        assert!(dl.has_pending_frame());

        let pending = dl.pop_pending_frame().unwrap();
        let resp_fctr = Fctr(pending[0]);
        assert_eq!(resp_fctr.frame_type(), FrameType::Control);
        assert_eq!(resp_fctr.seq_ctrl(), SeqCtrl::Nack);
        assert_eq!(resp_fctr.ack_nr(), 0); // Expected FRNR 0
    }
}
