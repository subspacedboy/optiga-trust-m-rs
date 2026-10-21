//! Strongly typed OIDs, Curve IDs, Algorithm IDs, and SessionSlot handles.

/// Well-known Object Identifiers (OIDs) on OPTIGA Trust M.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum Oid {
    /// Device global error code register (`0xF1C2`).
    ErrorCode = 0xF1C2,
    /// Coprocessor UID (`0xE0C2`).
    CoprUid = 0xE0C2,
    /// Global Life Cycle State (`0xE0C0`).
    GlobalLifecycleState = 0xE0C0,
    /// Global Security Status (`0xE0C1`).
    GlobalSecurityStatus = 0xE0C1,

    // Arbitrary data objects (e.g. certificates)
    Data0 = 0xE0E0,
    Data1 = 0xE0E1,
    Data2 = 0xE0E2,
    Data3 = 0xE0E3,

    // Monotonic counters
    MonotonicCounter0 = 0xE120,
    MonotonicCounter1 = 0xE121,
    MonotonicCounter2 = 0xE122,
    MonotonicCounter3 = 0xE123,

    // Non-volatile ECC private keys
    DevicePrivateKey0 = 0xE0F0,
    DevicePrivateKey1 = 0xE0F1,
    DevicePrivateKey2 = 0xE0F2,
    DevicePrivateKey3 = 0xE0F3,

    // Volatile session contexts
    SessionContext0 = 0xE100,
    SessionContext1 = 0xE101,
    SessionContext2 = 0xE102,
    SessionContext3 = 0xE103,

    // Arbitrary custom OID
    Custom(u16),
}

impl Oid {
    #[inline]
    pub const fn as_u16(&self) -> u16 {
        match self {
            Self::ErrorCode => 0xF1C2,
            Self::CoprUid => 0xE0C2,
            Self::GlobalLifecycleState => 0xE0C0,
            Self::GlobalSecurityStatus => 0xE0C1,
            Self::Data0 => 0xE0E0,
            Self::Data1 => 0xE0E1,
            Self::Data2 => 0xE0E2,
            Self::Data3 => 0xE0E3,
            Self::MonotonicCounter0 => 0xE120,
            Self::MonotonicCounter1 => 0xE121,
            Self::MonotonicCounter2 => 0xE122,
            Self::MonotonicCounter3 => 0xE123,
            Self::DevicePrivateKey0 => 0xE0F0,
            Self::DevicePrivateKey1 => 0xE0F1,
            Self::DevicePrivateKey2 => 0xE0F2,
            Self::DevicePrivateKey3 => 0xE0F3,
            Self::SessionContext0 => 0xE100,
            Self::SessionContext1 => 0xE101,
            Self::SessionContext2 => 0xE102,
            Self::SessionContext3 => 0xE103,
            Self::Custom(val) => *val,
        }
    }
}

impl From<u16> for Oid {
    fn from(val: u16) -> Self {
        match val {
            0xF1C2 => Self::ErrorCode,
            0xE0C2 => Self::CoprUid,
            0xE0C0 => Self::GlobalLifecycleState,
            0xE0C1 => Self::GlobalSecurityStatus,
            0xE0E0 => Self::Data0,
            0xE0E1 => Self::Data1,
            0xE0E2 => Self::Data2,
            0xE0E3 => Self::Data3,
            0xE120 => Self::MonotonicCounter0,
            0xE121 => Self::MonotonicCounter1,
            0xE122 => Self::MonotonicCounter2,
            0xE123 => Self::MonotonicCounter3,
            0xE0F0 => Self::DevicePrivateKey0,
            0xE0F1 => Self::DevicePrivateKey1,
            0xE0F2 => Self::DevicePrivateKey2,
            0xE0F3 => Self::DevicePrivateKey3,
            0xE100 => Self::SessionContext0,
            0xE101 => Self::SessionContext1,
            0xE102 => Self::SessionContext2,
            0xE103 => Self::SessionContext3,
            other => Self::Custom(other),
        }
    }
}

/// Elliptic curve identifiers supported by OPTIGA Trust M.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EccCurve {
    NistP256 = 0x03,
    NistP384 = 0x04,
    NistP521 = 0x05,
    BrainpoolP256r1 = 0x13,
    BrainpoolP384r1 = 0x15,
    BrainpoolP512r1 = 0x16,
}

impl EccCurve {
    /// Returns the expected shared secret length in bytes for ECDH on this curve.
    #[inline]
    pub const fn shared_secret_len(&self) -> usize {
        match self {
            Self::NistP256 | Self::BrainpoolP256r1 => 32,
            Self::NistP384 | Self::BrainpoolP384r1 => 48,
            Self::BrainpoolP512r1 => 64,
            Self::NistP521 => 66,
        }
    }

    /// Returns the exported private key length in bytes for `GenKeyPair` on this curve.
    #[inline]
    pub const fn private_key_len(&self) -> usize {
        match self {
            Self::NistP256 | Self::BrainpoolP256r1 => 0x22,
            Self::NistP384 | Self::BrainpoolP384r1 => 0x32,
            Self::BrainpoolP512r1 => 0x42,
            Self::NistP521 => 0x44,
        }
    }
}

/// Random number generator modes supported by `GetRandom` (`0x0C`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RngType {
    /// True Random Number Generator (`0x00`).
    Trng = 0x00,
    /// Deterministic Random Number Generator (`0x01`).
    Drng = 0x01,
}

/// Key derivation function algorithms supported by `DeriveKey` (`0x34`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum KdfAlg {
    TlsPrfSha256 = 0x01,
    TlsPrfSha384 = 0x02,
    TlsPrfSha512 = 0x03,
    HkdfSha256 = 0x08,
    HkdfSha384 = 0x09,
    HkdfSha512 = 0x0A,
}

/// Key usage flags for generated keypairs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyUsage(pub u8);

impl KeyUsage {
    pub const AUTH: u8 = 0x01;
    pub const SIGN: u8 = 0x02;
    pub const KEY_AGREEMENT: u8 = 0x04;
    pub const ENCRYPT: u8 = 0x08;

    pub const fn auth_and_sign() -> Self {
        Self(Self::AUTH | Self::SIGN)
    }

    pub const fn key_agreement() -> Self {
        Self(Self::KEY_AGREEMENT)
    }
}

/// Move-only handle to one of the 4 volatile session slots (`0xE100..=0xE103`).
///
/// This type intentionally does not implement `Copy` or `Clone` so that releasing a
/// session slot via `release_session_slot(slot)` consumes the handle and prevents
/// use-after-release bugs at compile time.
#[derive(Debug, PartialEq, Eq)]
pub struct SessionSlot {
    index: u8, // 0..=3
}

impl SessionSlot {
    pub fn new(index: u8) -> Option<Self> {
        if index < 4 {
            Some(Self { index })
        } else {
            None
        }
    }

    #[inline]
    pub const fn index(&self) -> u8 {
        self.index
    }

    #[inline]
    pub const fn oid(&self) -> Oid {
        match self.index {
            0 => Oid::SessionContext0,
            1 => Oid::SessionContext1,
            2 => Oid::SessionContext2,
            _ => Oid::SessionContext3,
        }
    }
}
