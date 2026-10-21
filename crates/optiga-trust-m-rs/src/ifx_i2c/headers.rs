//! IFX I2C Protocol v2.03 wire bitfields, headers, and CRC-16 computation.

// =========================================================================
// Layer 1: Physical Layer Registers & Status
// =========================================================================

/// Virtual register file addresses of the OPTIGA Trust M Physical Layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PlRegister {
    /// `PL_REG_DATA` (`0x80`): Read/Write data frames (1..=277 bytes).
    Data = 0x80,
    /// `PL_REG_DATA_REG_LEN` (`0x81`): Max frame length (16..=277 bytes, u16 BE).
    DataRegLen = 0x81,
    /// `PL_REG_I2C_STATE` (`0x82`): Slave status & available response length (4 bytes).
    I2cState = 0x82,
    /// `PL_REG_BASE_ADDR` (`0x83`): Slave I2C base address configuration.
    BaseAddr = 0x83,
    /// `PL_REG_MAX_SCL_FREQU` (`0x84`): Max supported SCL frequency in kHz (4 bytes, u16 BE at bytes 2..=3).
    MaxSclFrequ = 0x84,
    /// `PL_REG_SOFT_RESET` (`0x88`): Triggers soft reset (`[0x00, 0x00]`).
    SoftReset = 0x88,
    /// `PL_REG_I2C_MODE` (`0x89`): I2C mode setting (`[0x80, mode]`: SM/FM `0x03`, FM+ `0x04`).
    I2cMode = 0x89,
}

/// 4-byte response layout of `PlRegister::I2cState` (`0x82`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct I2cStateStatus(pub [u8; 4]);

impl I2cStateStatus {
    /// Bit 7: Slave is currently busy processing.
    pub const FLAG_BUSY: u8 = 0x80;
    /// Bit 6: Slave has a response frame ready to be read from `DATA` (`0x80`).
    pub const FLAG_RESPONSE_READY: u8 = 0x40;
    /// Bit 3: Slave supports soft reset via `0x88`.
    pub const FLAG_SOFT_RESET_SUPPORTED: u8 = 0x08;

    #[inline]
    pub const fn is_busy(&self) -> bool {
        (self.0[0] & Self::FLAG_BUSY) != 0
    }

    #[inline]
    pub const fn is_response_ready(&self) -> bool {
        (self.0[0] & Self::FLAG_RESPONSE_READY) != 0
    }

    #[inline]
    pub const fn supports_soft_reset(&self) -> bool {
        (self.0[0] & Self::FLAG_SOFT_RESET_SUPPORTED) != 0
    }

    #[inline]
    pub const fn response_len(&self) -> u16 {
        u16::from_be_bytes([self.0[2], self.0[3]])
    }
}

/// Reset type requested on the physical layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResetType {
    /// Cold Reset: Power cycle (toggle VDD low then high, RST held low then high).
    Cold,
    /// Warm Reset: Toggle RST pin low then high while VDD remains powered.
    Warm,
    /// Soft Reset: Software register write of `0x0000` to `PlRegister::SoftReset` (`0x88`).
    Soft,
}

// =========================================================================
// Layer 2: Data Link Layer Frame Control (`FCTR`) & CRC-16
// =========================================================================

/// Frame type bit in `FCTR` (Bit 7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameType {
    Data = 0,
    Control = 1,
}

/// Sequence control operation in `FCTR` (Bits 6..=5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SeqCtrl {
    Ack = 0x00,
    Nack = 0x01,
    Resync = 0x02,
    Rfu = 0x03,
}

/// Data Link Layer Frame Control Byte (`FCTR`).
///
/// Bit 7: Frame Type (`0` = Data, `1` = Control)
/// Bits 6..=5: Sequence Control (`00` = ACK, `01` = NACK, `10` = RESYNC, `11` = RFU)
/// Bit 4: RFU (always 0)
/// Bits 3..=2: Frame Number (`0..=3`)
/// Bits 1..=0: Acknowledged Frame Number (`0..=3`)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fctr(pub u8);

impl Fctr {
    #[inline]
    pub const fn new(frame_type: FrameType, seq_ctrl: SeqCtrl, fr_nr: u8, ack_nr: u8) -> Self {
        let ftype_bit = (frame_type as u8) << 7;
        let seq_bits = (seq_ctrl as u8 & 0x03) << 5;
        let fr_bits = (fr_nr & 0x03) << 2;
        let ack_bits = ack_nr & 0x03;
        Self(ftype_bit | seq_bits | fr_bits | ack_bits)
    }

    #[inline]
    pub const fn frame_type(self) -> FrameType {
        if (self.0 & 0x80) != 0 {
            FrameType::Control
        } else {
            FrameType::Data
        }
    }

    #[inline]
    pub const fn seq_ctrl(self) -> SeqCtrl {
        match (self.0 & 0x60) >> 5 {
            0x00 => SeqCtrl::Ack,
            0x01 => SeqCtrl::Nack,
            0x02 => SeqCtrl::Resync,
            _ => SeqCtrl::Rfu,
        }
    }

    #[inline]
    pub const fn fr_nr(self) -> u8 {
        (self.0 & 0x0C) >> 2
    }

    #[inline]
    pub const fn ack_nr(self) -> u8 {
        self.0 & 0x03
    }
}

/// Computes the CRC-16/CCITT step for a single byte, using polynomial `0x1021`.
///
/// Matches [`ifx_i2c_dl_calc_crc_byte`].
#[inline]
pub const fn crc16_ccitt_byte(seed: u16, byte: u8) -> u16 {
    let h1: u16 = (seed ^ (byte as u16)) & 0x00FF;
    let h2: u16 = h1 & 0x000F;
    let h3: u16 = (h2 << 4) ^ h1;
    let h4: u16 = h3 >> 4;

    (((((h3 << 1) ^ h4) << 4) ^ h2) << 3) ^ h4 ^ (seed >> 8)
}

/// Computes reflected CRC-16/CCITT over a byte slice with initial seed `0x0000`.
pub fn crc16_ccitt(data: &[u8]) -> u16 {
    let mut crc: u16 = 0;
    let mut i = 0;
    while i < data.len() {
        crc = crc16_ccitt_byte(crc, data[i]);
        i += 1;
    }
    crc
}

// =========================================================================
// Layer 3: Transport Layer Packet Control (`PCTR`)
// =========================================================================

/// Transport Layer Chaining state (`pctr & 0x07`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ChainState {
    /// Single fragment packet (`0x00`).
    No = 0x00,
    /// First fragment of a multi-fragment packet (`0x01`).
    First = 0x01,
    /// Intermediate fragment of a multi-fragment packet (`0x02`).
    Intermediate = 0x02,
    /// Final fragment of a multi-fragment packet (`0x04`).
    Last = 0x04,
    /// Chaining error indication (`0x07`).
    Error = 0x07,
}

impl TryFrom<u8> for ChainState {
    type Error = u8;

    fn try_from(val: u8) -> Result<Self, u8> {
        match val {
            0x00 => Ok(Self::No),
            0x01 => Ok(Self::First),
            0x02 => Ok(Self::Intermediate),
            0x04 => Ok(Self::Last),
            0x07 => Ok(Self::Error),
            other => Err(other),
        }
    }
}

/// Transport Layer Packet Control Byte (`PCTR`).
///
/// Bits 7..=4: Reserved (0)
/// Bit 3: Presentation Layer Presence Bit (`0x08`)
/// Bits 2..=0: Chaining (`0` = No, `1` = First, `2` = Intermediate, `4` = Last, `7` = Error)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pctr(pub u8);

impl Pctr {
    pub const MASK_PRESENCE: u8 = 0x08;
    pub const MASK_CHAIN: u8 = 0x07;

    #[inline]
    pub const fn new(has_presentation: bool, chain: ChainState) -> Self {
        let pres = if has_presentation { Self::MASK_PRESENCE } else { 0 };
        Self(pres | (chain as u8))
    }

    #[inline]
    pub const fn has_presentation(self) -> bool {
        (self.0 & Self::MASK_PRESENCE) != 0
    }

    #[inline]
    pub fn chain_state(self) -> Result<ChainState, u8> {
        ChainState::try_from(self.0 & Self::MASK_CHAIN)
    }

    /// Validates chaining transition according to `g_pctr_states_table`.
    pub const fn is_valid_transition(prev: ChainState, curr: ChainState) -> bool {
        match curr {
            ChainState::No => matches!(prev, ChainState::No | ChainState::Last),
            ChainState::First => matches!(prev, ChainState::No | ChainState::Last),
            ChainState::Intermediate => matches!(prev, ChainState::First | ChainState::Intermediate),
            ChainState::Last => matches!(prev, ChainState::First | ChainState::Intermediate),
            ChainState::Error => matches!(prev, ChainState::Error),
        }
    }
}

// =========================================================================
// Layer 4: Presentation Layer Security Control (`SCTR`) & Protection Levels
// =========================================================================

/// Presentation Layer Protocol Type (`sctr & 0xE0`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ProtocolType {
    Handshake = 0x00,
    RecordExchange = 0x20,
    Alert = 0x40,
    ManageContext = 0x60,
}

/// Presentation Layer Protection Level (`sctr & 0x03`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ProtectionLevel {
    None = 0x00,
    Master = 0x01,
    Slave = 0x02,
    Full = 0x03,
}

/// User-specified protection configuration for APDU transactions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtectionConfig {
    pub level: ProtectionLevel,
    /// Force a fresh handshake before transceiving this command.
    pub force_reestablish: bool,
}

impl Default for ProtectionConfig {
    fn default() -> Self {
        Self {
            level: ProtectionLevel::None,
            force_reestablish: false,
        }
    }
}

/// Presentation Layer Security Control Byte (`SCTR`).
///
/// Bits 7..=5: Protocol Type (`000` = Handshake, `001` = Record, `010` = Alert, `011` = ManageContext)
/// Bits 4..=2: Message Type
/// Bits 1..=0: Protection Level
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sctr(pub u8);

impl Sctr {
    // Protocol types
    pub const PROTOCOL_HANDSHAKE: u8 = 0x00;
    pub const PROTOCOL_RECORD: u8 = 0x20;
    pub const PROTOCOL_ALERT: u8 = 0x40;
    pub const PROTOCOL_MANAGE_CONTEXT: u8 = 0x60;

    // Handshake message types
    pub const MSG_HELLO: u8 = 0x00;
    pub const MSG_FINISHED: u8 = 0x08;

    // Alert message types
    pub const MSG_ALERT_FATAL: u8 = 0x00;
    pub const MSG_ALERT_INTEGRITY_VIOLATED: u8 = 0x04;

    // Manage Context message types
    pub const MSG_SAVE_CONTEXT: u8 = 0x00;
    pub const MSG_CONTEXT_SAVED: u8 = 0x04;
    pub const MSG_RESTORE_CONTEXT: u8 = 0x08;
    pub const MSG_CONTEXT_RESTORED: u8 = 0x0C;

    // Standard pre-formed SCTR bytes
    pub const MASTER_HELLO: Self = Self(0x00);
    pub const SLAVE_HELLO: Self = Self(0x00);
    pub const MASTER_FINISHED: Self = Self(0x08);
    pub const SLAVE_FINISHED: Self = Self(0x08);
    pub const FATAL_ALERT: Self = Self(0x40);
    pub const INTEGRITY_VIOLATED_ALERT: Self = Self(0x44);
    pub const SAVE_CONTEXT: Self = Self(0x60);
    pub const CONTEXT_SAVED: Self = Self(0x64);
    pub const RESTORE_CONTEXT: Self = Self(0x68);
    pub const CONTEXT_RESTORED: Self = Self(0x6C);

    #[inline]
    pub const fn new_record(level: ProtectionLevel) -> Self {
        Self(Self::PROTOCOL_RECORD | (level as u8 & 0x03))
    }

    #[inline]
    pub const fn protocol_type(self) -> Option<ProtocolType> {
        match self.0 & 0xE0 {
            0x00 => Some(ProtocolType::Handshake),
            0x20 => Some(ProtocolType::RecordExchange),
            0x40 => Some(ProtocolType::Alert),
            0x60 => Some(ProtocolType::ManageContext),
            _ => None,
        }
    }

    #[inline]
    pub const fn protection_level(self) -> ProtectionLevel {
        match self.0 & 0x03 {
            0x01 => ProtectionLevel::Master,
            0x02 => ProtectionLevel::Slave,
            0x03 => ProtectionLevel::Full,
            _ => ProtectionLevel::None,
        }
    }

    #[inline]
    pub const fn is_handshake(self) -> bool {
        (self.0 & 0xE0) == Self::PROTOCOL_HANDSHAKE
    }

    #[inline]
    pub const fn is_record_exchange(self) -> bool {
        (self.0 & 0xE0) == Self::PROTOCOL_RECORD
    }

    #[inline]
    pub const fn is_alert(self) -> bool {
        (self.0 & 0xE0) == Self::PROTOCOL_ALERT
    }

    #[inline]
    pub const fn is_manage_context(self) -> bool {
        (self.0 & 0xE0) == Self::PROTOCOL_MANAGE_CONTEXT
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_i2c_state_status() {
        let status = I2cStateStatus([0x48, 0x00, 0x01, 0x15]);
        assert!(!status.is_busy());
        assert!(status.is_response_ready());
        assert!(status.supports_soft_reset());
        assert_eq!(status.response_len(), 277);

        let busy_status = I2cStateStatus([0x80, 0x00, 0x00, 0x00]);
        assert!(busy_status.is_busy());
        assert!(!busy_status.is_response_ready());
        assert!(!busy_status.supports_soft_reset());
        assert_eq!(busy_status.response_len(), 0);
    }

    #[test]
    fn test_fctr_roundtrip() {
        // Data frame, ACK, FRNR = 1, ACKNR = 2
        let fctr = Fctr::new(FrameType::Data, SeqCtrl::Ack, 1, 2);
        assert_eq!(fctr.frame_type(), FrameType::Data);
        assert_eq!(fctr.seq_ctrl(), SeqCtrl::Ack);
        assert_eq!(fctr.fr_nr(), 1);
        assert_eq!(fctr.ack_nr(), 2);
        assert_eq!(fctr.0, (1 << 2) | 2); // 0b00000110 = 0x06

        // Control frame, RESYNC, FRNR = 0, ACKNR = 0
        let resync_fctr = Fctr::new(FrameType::Control, SeqCtrl::Resync, 0, 0);
        assert_eq!(resync_fctr.frame_type(), FrameType::Control);
        assert_eq!(resync_fctr.seq_ctrl(), SeqCtrl::Resync);
        assert_eq!(resync_fctr.fr_nr(), 0);
        assert_eq!(resync_fctr.ack_nr(), 0);
        assert_eq!(resync_fctr.0, 0x80 | (0x02 << 5)); // 0xC0
    }

    #[test]
    fn test_crc16_ccitt() {
        // Test with standard IFX I2C Control Frame:
        // CF ACK: FCTR = 0x80 (CF, ACK, FRNR=0, ACKNR=0), LEN = 0x0000
        let cf_ack = [0x80, 0x00, 0x00];
        let crc = crc16_ccitt(&cf_ack);
        // Verify CRC byte calculation matches byte-by-byte
        let step1 = crc16_ccitt_byte(0x0000, 0x80);
        let step2 = crc16_ccitt_byte(step1, 0x00);
        let step3 = crc16_ccitt_byte(step2, 0x00);
        assert_eq!(crc, step3);

        // Bitflip changes CRC
        let cf_ack_corrupt = [0x81, 0x00, 0x00];
        assert_ne!(crc, crc16_ccitt(&cf_ack_corrupt));

        // 1-bit flip error detection over max frame size (277 bytes)
        let mut frame = [0u8; 277];
        frame[0] = 0x00; // Data frame
        frame[1] = 0x01; // Length MSB
        frame[2] = 0x10; // Length LSB (272)
        for (idx, byte) in frame[3..275].iter_mut().enumerate() {
            *byte = ((idx + 3) & 0xFF) as u8;
        }
        let base_crc = crc16_ccitt(&frame[..275]);
        for byte_idx in 0..275 {
            for bit_idx in 0..8 {
                let mut corrupted = frame;
                corrupted[byte_idx] ^= 1 << bit_idx;
                let corrupted_crc = crc16_ccitt(&corrupted[..275]);
                assert_ne!(
                    base_crc, corrupted_crc,
                    "CRC collision on 1-bit flip at byte {byte_idx} bit {bit_idx}"
                );
            }
        }
    }

    #[test]
    fn test_pctr() {
        let pctr = Pctr::new(true, ChainState::First);
        assert!(pctr.has_presentation());
        assert_eq!(pctr.chain_state(), Ok(ChainState::First));
        assert_eq!(pctr.0, 0x08 | 0x01);

        assert!(Pctr::is_valid_transition(ChainState::No, ChainState::No));
        assert!(Pctr::is_valid_transition(ChainState::No, ChainState::First));
        assert!(Pctr::is_valid_transition(ChainState::First, ChainState::Intermediate));
        assert!(Pctr::is_valid_transition(ChainState::Intermediate, ChainState::Last));
        assert!(!Pctr::is_valid_transition(ChainState::First, ChainState::First));
    }

    #[test]
    fn test_sctr() {
        let sctr = Sctr::new_record(ProtectionLevel::Full);
        assert_eq!(sctr.protocol_type(), Some(ProtocolType::RecordExchange));
        assert_eq!(sctr.protection_level(), ProtectionLevel::Full);
        assert!(sctr.is_record_exchange());

        assert_eq!(Sctr::MASTER_FINISHED.0, 0x08);
        assert!(Sctr::MASTER_FINISHED.is_handshake());
        assert_eq!(Sctr::INTEGRITY_VIOLATED_ALERT.0, 0x44);
        assert!(Sctr::INTEGRITY_VIOLATED_ALERT.is_alert());
    }
}
