//! Protocol configuration constants and timing defaults.
//!
//! Based on Infineon I2C Protocol v2.03 and OPTIGA™ Trust M specifications.

/// Default 7-bit I2C slave address of OPTIGA Trust M (`IFX_I2C_BASE_ADDR`).
pub const IFX_I2C_BASE_ADDR: u8 = 0x30;

/// Maximum supported Data Link Layer frame size in OPTIGA (`IFX_I2C_FRAME_SIZE`).
pub const MAX_FRAME_SIZE: usize = 277;

/// Minimum supported Data Link Layer frame size (`16`).
pub const MIN_FRAME_SIZE: usize = 16;

/// Physical Layer polling interval when slave NACKs or is busy (`PL_POLLING_INVERVAL_US = 1000 µs`).
pub const PL_POLLING_INTERVAL_US: u32 = 1_000;

/// Maximum Physical Layer NACK/busy polling attempts (`PL_POLLING_MAX_CNT = 200`).
pub const PL_POLLING_MAX_CNT: u16 = 200;

/// Physical Layer `I2C_STATE` (`0x82`) response polling interval (`PL_DATA_POLLING_INVERVAL_US = 5000 µs`).
pub const PL_DATA_POLLING_INTERVAL_US: u32 = 5_000;

/// Mandatory Physical Layer guard time after every I2C read/write (`PL_GUARD_TIME_INTERVAL_US = 50 µs`).
pub const PL_GUARD_TIME_INTERVAL_US: u32 = 50;

/// Default initial negotiation I2C frequency in kHz (`PL_DEFAULT_FREQUENCY = 100 kHz`).
pub const PL_DEFAULT_FREQUENCY_KHZ: u16 = 100;

/// Threshold between SM/FM (`<= 400 kHz`) and FM+ (`> 400 kHz`) (`PL_SM_FM_MAX_FREQUENCY = 400 kHz`).
pub const PL_SM_FM_MAX_FREQUENCY_KHZ: u16 = 400;

/// Maximum supported FM+ frequency in kHz (`1000 kHz`).
pub const PL_FM_PLUS_MAX_FREQUENCY_KHZ: u16 = 1_000;

/// GPIO Reset low hold time in microseconds (`RESET_LOW_TIME_MSEC = 2000` in C config, passed to µs delay = 2 ms).
pub const RESET_LOW_TIME_US: u32 = 2_000;

/// Startup delay after reset release or soft reset (`STARTUP_TIME_MSEC = 12000` passed to µs delay = 12 ms).
pub const STARTUP_TIME_US: u32 = 12_000;

/// Data Link Layer header + CRC overhead (`DL_HEADER_SIZE = 5` bytes: 1B FCTR + 2B LEN + 2B CRC).
pub const DL_HEADER_SIZE: usize = 5;

/// Data Link Layer max retransmission count before RESYNC (`DL_TRANS_REPEAT = 3`).
pub const DL_TRANS_REPEAT: u8 = 3;

/// Data Link Layer poll timeout when waiting for immediate ACK after TX (`PL_TRANS_TIMEOUT_MS = 10 ms`).
pub const PL_TRANS_TIMEOUT_MS: u32 = 10;

/// Transport Layer header size (`TL_HEADER_SIZE = 1` byte: PCTR).
pub const TL_HEADER_SIZE: usize = 1;

/// Transport Layer maximum exit timeout in milliseconds (`TL_MAX_EXIT_TIMEOUT = 180 s = 180_000 ms`).
pub const TL_MAX_EXIT_TIMEOUT_MS: u32 = 180_000;

/// Maximum Transport Layer chaining error retry count (`TL_MAX_CHAINING_ERROR_COUNT = 1`).
pub const TL_MAX_CHAINING_ERROR_COUNT: u8 = 1;

/// Unique 16-byte OPTIGA™ Trust M Application Identifier (`g_optiga_unique_application_identifier`).
pub const OPTIGA_APPLICATION_ID: [u8; 16] = [
    0xD2, 0x76, 0x00, 0x00, 0x04, 0x47, 0x65, 0x6E, 0x41, 0x75, 0x74, 0x68, 0x41, 0x70, 0x70, 0x6C,
];

/// Presentation Layer header size for protected records (`IFX_I2C_PRL_HEADER_SIZE = 5`: 1B SCTR + 4B SeqNr).
pub const PRL_HEADER_SIZE: usize = 5;

/// Presentation Layer AES-CCM MAC size (`IFX_I2C_PRL_MAC_SIZE = 8`).
pub const PRL_MAC_SIZE: usize = 8;

/// Total Presentation Layer overhead (`PRL_OVERHEAD_SIZE = 13` bytes).
pub const PRL_OVERHEAD_SIZE: usize = PRL_HEADER_SIZE + PRL_MAC_SIZE;

/// Presentation Layer max retransmission repeat count on integrity alert (`PRL_TRANS_REPEAT = 3`).
pub const PRL_TRANS_REPEAT: u8 = 3;

/// Presentation Layer sequence number threshold triggering re-handshake (`0xFFFFFFF0`).
pub const PRL_SEQUENCE_THRESHOLD: u32 = 0xFFFF_FFF0;

/// Maximum APDU communication buffer size (`OPTIGA_MAX_COMMS_BUFFER_SIZE = 0x615 = 1557` bytes).
pub const OPTIGA_MAX_COMMS_BUFFER_SIZE: usize = 1557;

/// Maximum payload length per Data Link packet (`MAX_FRAME_SIZE - DL_HEADER_SIZE = 272` bytes).
pub const DL_MAX_PAYLOAD_SIZE: usize = MAX_FRAME_SIZE - DL_HEADER_SIZE;

/// Maximum payload length per Transport fragment (`MAX_FRAME_SIZE - DL_HEADER_SIZE - TL_HEADER_SIZE = 271` bytes).
pub const TL_MAX_PAYLOAD_SIZE: usize = DL_MAX_PAYLOAD_SIZE - TL_HEADER_SIZE;
