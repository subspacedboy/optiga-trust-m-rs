//! Integration tests for WP5: Command Layer, APDU auto-0xF1C2 error fetch, Util & Crypt APIs.

use optiga_sim::clock::{MockPin, SimulatedClock};
use optiga_sim::datastore::InMemoryDatastore;
use optiga_sim::fault_bus::FaultInjectingI2cBus;
use optiga_sim::virtual_chip::VirtualOptiga;
use optiga_trust_m_rs::cmd::types::{EccCurve, KdfAlg, KeyUsage, Oid, RngType};
use optiga_trust_m_rs::error::{DeviceError, OptigaError};
use optiga_trust_m_rs::ifx_i2c::headers::ResetType;
use optiga_trust_m_rs::pal::rust_crypto::RustCryptoBackend;
use optiga_trust_m_rs::{OptigaFor, OptigaPlatform, OptigaTrustM};
use std::cell::RefCell;
use std::rc::Rc;

struct SimPlatform;

impl OptigaPlatform for SimPlatform {
    type I2c = FaultInjectingI2cBus;
    type Timer = SimulatedClock;
    type VddPin = MockPin;
    type RstPin = MockPin;
    type Crypto = RustCryptoBackend;
    type Datastore = InMemoryDatastore;
}

type TrustMRig = (
    SimulatedClock,
    Rc<RefCell<VirtualOptiga>>,
    OptigaFor<SimPlatform>,
);

fn setup_trust_m() -> TrustMRig {
    let clock = SimulatedClock::new();
    let mut chip = VirtualOptiga::new(clock.clone());
    chip.registers.strict_guard_time = true;
    let shared_chip = Rc::new(RefCell::new(chip));
    let bus = FaultInjectingI2cBus::with_shared_chip(shared_chip.clone());

    let vdd = MockPin::new(clock.clone(), embedded_hal::digital::PinState::High);
    let rst = MockPin::new(clock.clone(), embedded_hal::digital::PinState::High);

    let ds = InMemoryDatastore::new();

    let optiga = OptigaTrustM::builder(bus, clock.clone())
        .with_pins(vdd, rst)
        .with_datastore(ds)
        .build();
    (clock, shared_chip, optiga)
}

#[test]
fn test_cmd_auto_f1c2_device_error_retrieval() {
    let (_clock, chip, mut optiga) = setup_trust_m();
    optiga.open(ResetType::Warm, 277, 400).expect("open succeeds");

    // Force chip to fail next command with error 0x07 (AccessConditionNotSatisfied)
    chip.borrow_mut().apdu.force_next_command_failure = true;

    let mut buf = [0u8; 10];
    let res = optiga.util().read_data(Oid::Data0, 0, &mut buf);

    assert_eq!(
        res,
        Err(OptigaError::Device(DeviceError::AccessConditionNotSatisfied))
    );
}

#[test]
fn test_util_lifecycle_and_data_access() {
    let (_clock, _chip, mut optiga) = setup_trust_m();
    optiga.open(ResetType::Warm, 277, 400).expect("open succeeds");

    let mut util = optiga.util();

    // Open Application
    assert!(util.open_application(false).is_ok());

    // Write Data
    let test_data = [0xAA, 0xBB, 0xCC, 0xDD];
    assert!(util.write_data(Oid::Data0, 0, &test_data, false).is_ok());

    // Read Data
    let mut read_buf = [0u8; 4];
    let len = util.read_data(Oid::Data0, 0, &mut read_buf).expect("read succeeds");
    assert_eq!(len, 4);

    // Read Metadata
    let mut meta_buf = [0u8; 4];
    assert!(util.read_metadata(Oid::Data0, &mut meta_buf).is_ok());

    // Write Metadata
    assert!(util.write_metadata(Oid::Data0, &[0x20, 0x03, 0xD0, 0x01, 0x00]).is_ok());

    // Protected Update (Start -> Continue -> Final)
    let manifest = [0x01, 0x02, 0x03, 0x04];
    let frag1 = [0x10, 0x20];
    let frag2 = [0x30, 0x40];
    assert!(util.protected_update(0x01, &manifest, &[&frag1, &frag2]).is_ok());

    // Increment Monotonic Counter
    assert!(util.increment_monotonic_counter(Oid::MonotonicCounter0, 1).is_ok());

    // Hibernate Close & Restore Open roundtrip
    assert!(util.close_application(true).is_ok());
    assert!(util.open_application(true).is_ok());

    // Second restore without a new hibernate close must fail because handle was cleared!
    assert_eq!(util.open_application(true), Err(OptigaError::CommandError));

    // Close Application normally
    assert!(util.close_application(false).is_ok());
}

#[test]
fn test_crypt_trng_and_keypair_generation() {
    let (_clock, chip, mut optiga) = setup_trust_m();
    optiga.open(ResetType::Warm, 277, 400).expect("open succeeds");

    let mut crypt = optiga.crypt();

    // TRNG & DRNG
    let mut rnd = [0u8; 16];
    assert!(crypt.get_random(&mut rnd).is_ok());
    assert_ne!(rnd, [0u8; 16]);
    assert!(crypt.get_random_with_type(RngType::Drng, &mut rnd).is_ok());

    // Keypair generation in session slot
    let mut pubkey = [0u8; 65];
    let slot = crypt
        .generate_keypair_in_session(EccCurve::NistP256, KeyUsage::auth_and_sign(), &mut pubkey)
        .expect("keypair gen succeeds");

    assert_eq!(slot.index(), 0);
    assert_eq!(slot.oid(), Oid::SessionContext0);
    assert_eq!(pubkey[0], 0x04); // Uncompressed format prefix
    crypt.cmd.release_session_slot(slot);

    // Verify session slot is not leaked if GenKeyPair fails on device
    chip.borrow_mut().apdu.force_next_command_failure = true;
    assert!(crypt
        .generate_keypair_in_session(EccCurve::NistP256, KeyUsage::auth_and_sign(), &mut pubkey)
        .is_err());
    let slot_after_err = crypt
        .generate_keypair_in_session(EccCurve::NistP256, KeyUsage::auth_and_sign(), &mut pubkey)
        .expect("slot 0 was properly released on error");
    assert_eq!(slot_after_err.index(), 0);
    crypt.cmd.release_session_slot(slot_after_err);

    // Persistent OID keypair generation & export keypair generation
    let pub_len = crypt
        .ecc_generate_keypair(
            EccCurve::NistP256,
            Oid::DevicePrivateKey0,
            KeyUsage::auth_and_sign(),
            &mut pubkey,
        )
        .expect("persistent keypair gen succeeds");
    assert_eq!(pub_len, 65);

    let mut privkey = [0u8; 0x22];
    let (priv_len, pub_len2) = crypt
        .ecc_generate_keypair_export(EccCurve::NistP256, &mut privkey, &mut pubkey)
        .expect("export keypair gen succeeds");
    assert_eq!(priv_len, 0x22);
    assert_eq!(pub_len2, 65);
}

#[test]
fn test_crypt_ecdsa_sign_verify_ecdh_hash_and_kdf() {
    let (_clock, _chip, mut optiga) = setup_trust_m();
    optiga.open(ResetType::Warm, 277, 400).expect("open succeeds");

    let mut crypt = optiga.crypt();

    // SHA-256 Hash (host data and OID data)
    let mut digest = [0u8; 32];
    crypt
        .hash_sha256(b"hello optiga", &mut digest)
        .expect("hash_sha256 succeeds");
    let mut oid_digest = [0u8; 32];
    crypt
        .hash_oid_sha256(Oid::Data0, 0, 4, &mut oid_digest)
        .expect("hash_oid_sha256 succeeds");
    assert_ne!(digest, oid_digest);

    // ECDSA Sign (returns 68-byte ASN.1 DER (r, s) INTEGER pair)
    let mut signature = [0u8; 72];
    let sig_len = crypt
        .ecdsa_sign(&digest, Oid::DevicePrivateKey0, &mut signature)
        .expect("sign succeeds");
    assert_eq!(sig_len, 68);
    assert_eq!(signature[0], 0x02);
    assert_eq!(signature[1], 0x20);

    // ECDSA Verify (host pubkey and OID)
    let pubkey = [0x04u8; 65];
    let valid = crypt
        .ecdsa_verify(&digest, &signature[..sig_len], &pubkey, EccCurve::NistP256)
        .expect("verify succeeds");
    assert!(valid);
    let valid_oid = crypt
        .ecdsa_verify_with_oid(&digest, &signature[..sig_len], Oid::Data0)
        .expect("verify with oid succeeds");
    assert!(valid_oid);

    // ECDH Key Agreement (export to host)
    let mut shared_secret = [0u8; 32];
    let ssec_len = crypt
        .ecdh(
            Oid::DevicePrivateKey0,
            &pubkey,
            EccCurve::NistP256,
            &mut shared_secret,
        )
        .expect("ecdh succeeds");
    assert_eq!(ssec_len, 32);
    assert_eq!(shared_secret, [0x33u8; 32]);

    // ECDH to Session Slot + DeriveKey (TLS-PRF and HKDF)
    let ssec_slot = crypt
        .ecdh_to_session(Oid::DevicePrivateKey0, &pubkey, EccCurve::NistP256)
        .expect("ecdh_to_session succeeds");
    let mut derived_key = [0u8; 32];
    crypt
        .derive_key_to_host(
            KdfAlg::HkdfSha256,
            ssec_slot.oid(),
            b"label",
            b"salt",
            Some(b"info"),
            &mut derived_key,
        )
        .expect("derive_key_to_host succeeds");
    assert_eq!(derived_key[0], 0xA0);

    let target_slot = crypt.cmd.acquire_session_slot().unwrap();
    crypt
        .derive_key_to_session(
            KdfAlg::TlsPrfSha256,
            ssec_slot.oid(),
            b"master secret",
            b"seed",
            None,
            32,
            &target_slot,
        )
        .expect("derive_key_to_session succeeds");

    crypt.cmd.release_session_slot(target_slot);
    crypt.cmd.release_session_slot(ssec_slot);
}

#[test]
fn test_session_slot_allocation_exhaustion() {
    let (_clock, _chip, mut optiga) = setup_trust_m();
    optiga.open(ResetType::Warm, 277, 400).expect("open succeeds");

    // Acquire 4 session slots
    let s0 = optiga.cmd.acquire_session_slot().unwrap();
    let s1 = optiga.cmd.acquire_session_slot().unwrap();
    let s2 = optiga.cmd.acquire_session_slot().unwrap();
    let s3 = optiga.cmd.acquire_session_slot().unwrap();

    assert_eq!(s0.index(), 0);
    assert_eq!(s1.index(), 1);
    assert_eq!(s2.index(), 2);
    assert_eq!(s3.index(), 3);

    // 5th attempt exhausts slots
    assert_eq!(optiga.cmd.acquire_session_slot(), Err(OptigaError::InstanceInUse));

    // Release slot 1
    optiga.cmd.release_session_slot(s1);

    // Now acquiring succeeds and reuses slot 1
    let reused = optiga.cmd.acquire_session_slot().unwrap();
    assert_eq!(reused.index(), 1);
}
