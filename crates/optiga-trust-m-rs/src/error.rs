//! Hierarchical error types for OPTIGA™ Trust M communication and execution.

use core::fmt;

/// Errors originating from the IFX I2C Protocol Stack (`ifx_i2c`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IfxI2cError {
    /// `IFX_I2C_STACK_BUSY` (`0x0001`): Stack or bus is currently busy.
    Busy,
    /// `IFX_I2C_STACK_ERROR` (`0x0102`): General protocol error (invalid state, NACK limit, bad negotiation).
    ProtocolError,
    /// `IFX_I2C_STACK_MEM_ERROR` (`0x0104`): Receive buffer capacity insufficient for incoming packet.
    MemoryInsufficient,
    /// `IFX_I2C_FATAL_ERROR` (`0x0106`): Physical layer polling limit (`PL_POLLING_MAX_CNT = 200`) exhausted.
    FatalError,
    /// `IFX_I2C_HANDSHAKE_ERROR` (`0x0107`): Presentation layer handshake failed (PRF, Finished verify, or Alert).
    HandshakeError,
    /// `IFX_I2C_SESSION_ERROR` (`0x0108`): Established secure session was closed or desynchronized.
    SessionError,
}

impl fmt::Display for IfxI2cError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Busy => write!(f, "IFX I2C stack busy"),
            Self::ProtocolError => write!(f, "IFX I2C protocol error"),
            Self::MemoryInsufficient => write!(f, "IFX I2C memory insufficient"),
            Self::FatalError => write!(f, "IFX I2C fatal error / polling timeout"),
            Self::HandshakeError => write!(f, "IFX I2C handshake error"),
            Self::SessionError => write!(f, "IFX I2C session error"),
        }
    }
}

/// Device-level error codes read from OID `0xF1C2` when APDU `Sta == 0xFF`.
/// Reference: OPTIGA Trust M Solution Reference Manual v3.60.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceError {
    InvalidOid,
    InvalidPassword,
    InvalidParamField,
    InvalidLengthField,
    InvalidParameterInDataField,
    InternalProcessError,
    AccessConditionNotSatisfied,
    DataObjectBoundaryExceeded,
    MetadataTruncationError,
    InvalidCommandField,
    CommandOutOfSequence,
    CommandNotAvailable,
    InsufficientMemory,
    CounterThresholdLimitExceeded,
    InvalidManifest,
    InvalidPayloadVersion,
    InvalidHandShakeMessage,
    VersionMismatch,
    InsufficientCipherSuite,
    UnsupportedExtensionIdentifier,
    InvalidTrustAnchor,
    TrustAnchorExpired,
    UnsupportedTrustAnchor,
    InvalidCertificateFormat,
    UnsupportedCertificateAlgorithm,
    CerificateExpired,
    SignatureVerificationFailure,
    IntegrityValidationFailure,
    DecryptionFailure,
    GeneralError,
    Unknown(u8),
}

impl DeviceError {
    pub const fn code(&self) -> u8 {
        match self {
            Self::InvalidOid => 0x01,
            Self::InvalidPassword => 0x02,
            Self::InvalidParamField => 0x03,
            Self::InvalidLengthField => 0x04,
            Self::InvalidParameterInDataField => 0x05,
            Self::InternalProcessError => 0x06,
            Self::AccessConditionNotSatisfied => 0x07,
            Self::DataObjectBoundaryExceeded => 0x08,
            Self::MetadataTruncationError => 0x09,
            Self::InvalidCommandField => 0x0A,
            Self::CommandOutOfSequence => 0x0B,
            Self::CommandNotAvailable => 0x0C,
            Self::InsufficientMemory => 0x0D,
            Self::CounterThresholdLimitExceeded => 0x0E,
            Self::InvalidManifest => 0x0F,
            Self::InvalidPayloadVersion => 0x10,
            Self::InvalidHandShakeMessage => 0x21,
            Self::VersionMismatch => 0x22,
            Self::InsufficientCipherSuite => 0x23,
            Self::UnsupportedExtensionIdentifier => 0x24,
            Self::InvalidTrustAnchor => 0x26,
            Self::TrustAnchorExpired => 0x27,
            Self::UnsupportedTrustAnchor => 0x28,
            Self::InvalidCertificateFormat => 0x29,
            Self::UnsupportedCertificateAlgorithm => 0x2A,
            Self::CerificateExpired => 0x2B,
            Self::SignatureVerificationFailure => 0x2C,
            Self::IntegrityValidationFailure => 0x2D,
            Self::DecryptionFailure => 0x2E,
            Self::GeneralError => 0xFF,
            Self::Unknown(c) => *c,
        }
    }
}

impl From<u8> for DeviceError {
    fn from(code: u8) -> Self {
        match code {
            0x01 => Self::InvalidOid,
            0x02 => Self::InvalidPassword,
            0x03 => Self::InvalidParamField,
            0x04 => Self::InvalidLengthField,
            0x05 => Self::InvalidParameterInDataField,
            0x06 => Self::InternalProcessError,
            0x07 => Self::AccessConditionNotSatisfied,
            0x08 => Self::DataObjectBoundaryExceeded,
            0x09 => Self::MetadataTruncationError,
            0x0A => Self::InvalidCommandField,
            0x0B => Self::CommandOutOfSequence,
            0x0C => Self::CommandNotAvailable,
            0x0D => Self::InsufficientMemory,
            0x0E => Self::CounterThresholdLimitExceeded,
            0x0F => Self::InvalidManifest,
            0x10 => Self::InvalidPayloadVersion,
            0x21 => Self::InvalidHandShakeMessage,
            0x22 => Self::VersionMismatch,
            0x23 => Self::InsufficientCipherSuite,
            0x24 => Self::UnsupportedExtensionIdentifier,
            0x26 => Self::InvalidTrustAnchor,
            0x27 => Self::TrustAnchorExpired,
            0x28 => Self::UnsupportedTrustAnchor,
            0x29 => Self::InvalidCertificateFormat,
            0x2A => Self::UnsupportedCertificateAlgorithm,
            0x2B => Self::CerificateExpired,
            0x2C => Self::SignatureVerificationFailure,
            0x2D => Self::IntegrityValidationFailure,
            0x2E => Self::DecryptionFailure,
            0xFF => Self::GeneralError,
            other => Self::Unknown(other),
        }
    }
}

impl fmt::Display for DeviceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidOid => write!(f, "Invalid OID (0x01)"),
            Self::InvalidPassword => write!(f, "Invalid password (0x02)"),
            Self::InvalidParamField => write!(f, "Invalid parameter field (0x03)"),
            Self::InvalidLengthField => write!(f, "Invalid length field (0x04)"),
            Self::InvalidParameterInDataField => write!(f, "Invalid parameter in data field (0x05)"),
            Self::InternalProcessError => write!(f, "Internal process error (0x06)"),
            Self::AccessConditionNotSatisfied => write!(f, "Access condition not satisfied (0x07)"),
            Self::DataObjectBoundaryExceeded => write!(f, "Data object boundary exceeded (0x08)"),
            Self::MetadataTruncationError => write!(f, "Metadata truncation error (0x09)"),
            Self::InvalidCommandField => write!(f, "Invalid command field (0x0A)"),
            Self::CommandOutOfSequence => write!(f, "Command out of sequence (0x0B)"),
            Self::CommandNotAvailable => write!(f, "Command not available (0x0C)"),
            Self::InsufficientMemory => write!(f, "Insufficient memory (0x0D)"),
            Self::CounterThresholdLimitExceeded => write!(f, "Counter threshold limit exceeded (0x0E)"),
            Self::InvalidManifest => write!(f, "Invalid manifest (0x0F)"),
            Self::InvalidPayloadVersion => write!(f, "Invalid payload version (0x10)"),
            Self::InvalidHandShakeMessage => write!(f, "Invalid handshake message (0x21)"),
            Self::VersionMismatch => write!(f, "Version mismatch (0x22)"),
            Self::InsufficientCipherSuite => write!(f, "Insufficient cipher suite (0x23)"),
            Self::UnsupportedExtensionIdentifier => write!(f, "Unsupported extension identifier (0x24)"),
            Self::InvalidTrustAnchor => write!(f, "Invalid trust anchor (0x26)"),
            Self::TrustAnchorExpired => write!(f, "Trust anchor expired (0x27)"),
            Self::UnsupportedTrustAnchor => write!(f, "Unsupported trust anchor (0x28)"),
            Self::InvalidCertificateFormat => write!(f, "Invalid certificate format (0x29)"),
            Self::UnsupportedCertificateAlgorithm => write!(f, "Unsupported certificate algorithm (0x2A)"),
            Self::CerificateExpired => write!(f, "Certificate expired (0x2B)"),
            Self::SignatureVerificationFailure => write!(f, "Signature verification failure (0x2C)"),
            Self::IntegrityValidationFailure => write!(f, "Integrity validation failure (0x2D)"),
            Self::DecryptionFailure => write!(f, "Decryption failure (0x2E)"),
            Self::GeneralError => write!(f, "General device error (0xFF)"),
            Self::Unknown(c) => write!(f, "Unknown device error (0x{:02X})", c),
        }
    }
}

/// Top-level error returned by `OptigaCmd`, `OptigaUtil`, and `OptigaCrypt`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OptigaError {
    /// Lower-level IFX I2C communication stack error.
    Comms(IfxI2cError),
    /// Invalid arguments passed to API (`OPTIGA_CMD_ERROR_INVALID_INPUT` / `0x0203`).
    InvalidInput,
    /// Buffer too small for APDU or response (`OPTIGA_CMD_ERROR_MEMORY_INSUFFICIENT` / `0x0204`).
    MemoryInsufficient,
    /// Instance or session is already in use (`0x0305` / `0x0405`).
    InstanceInUse,
    /// Command execution error inside the state machine (`0x0202`).
    CommandError,
    /// Security chip returned APDU `Sta == 0xFF` and error code from `0xF1C2` (`0x80XX`).
    Device(DeviceError),
    /// Error reading/writing host Datastore.
    DatastoreError,
}

impl From<IfxI2cError> for OptigaError {
    fn from(err: IfxI2cError) -> Self {
        Self::Comms(err)
    }
}

impl From<DeviceError> for OptigaError {
    fn from(err: DeviceError) -> Self {
        Self::Device(err)
    }
}

impl fmt::Display for OptigaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Comms(e) => write!(f, "Communication error: {}", e),
            Self::InvalidInput => write!(f, "Invalid input"),
            Self::MemoryInsufficient => write!(f, "Memory insufficient"),
            Self::InstanceInUse => write!(f, "Instance or session already in use"),
            Self::CommandError => write!(f, "Command execution error"),
            Self::Device(d) => write!(f, "OPTIGA device error: {}", d),
            Self::DatastoreError => write!(f, "Datastore access error"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_device_error_roundtrip() {
        assert_eq!(DeviceError::from(0x01), DeviceError::InvalidOid);
        assert_eq!(DeviceError::from(0x01).code(), 0x01);
        assert_eq!(DeviceError::from(0x2E), DeviceError::DecryptionFailure);
        assert_eq!(DeviceError::from(0x2E).code(), 0x2E);
        assert_eq!(DeviceError::from(0xFF), DeviceError::GeneralError);
        assert_eq!(DeviceError::from(0xFF).code(), 0xFF);
        assert_eq!(DeviceError::from(0x77), DeviceError::Unknown(0x77));
        assert_eq!(DeviceError::from(0x77).code(), 0x77);
    }

    #[test]
    fn test_error_conversions() {
        let comms_err: OptigaError = IfxI2cError::FatalError.into();
        assert_eq!(comms_err, OptigaError::Comms(IfxI2cError::FatalError));

        let dev_err: OptigaError = DeviceError::InvalidTrustAnchor.into();
        assert_eq!(dev_err, OptigaError::Device(DeviceError::InvalidTrustAnchor));
    }
}

