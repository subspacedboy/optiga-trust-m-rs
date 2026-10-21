//! Integration tests for WP5: Command Layer, APDU auto-0xF1C2 error fetch, Util & Crypt APIs.

use optiga_sim::clock::{MockPin, SimulatedClock};
use optiga_sim::datastore::InMemoryDatastore;
use optiga_sim::fault_bus::FaultInjectingI2cBus;
use optiga_sim::virtual_chip::VirtualOptiga;
use optiga_trust_m_rs::cmd::types::{EccCurve, KeyUsage, Oid};
use optiga_trust_m_rs::error::{DeviceError, OptigaError};
use optiga_trust_m_rs::ifx_i2c::headers::ResetType;
use optiga_trust_m_rs::pal::rust_crypto::RustCryptoBackend;
use optiga_trust_m_rs::OptigaTrustM;
use std::cell::RefCell;
use std::rc::Rc;

type TrustMRig = (
    SimulatedClock,
    Rc<RefCell<VirtualOptiga>>,
    OptigaTrustM<
        FaultInjectingI2cBus,
        SimulatedClock,
        MockPin,
        MockPin,
        SimulatedClock,
        RustCryptoBackend,
        InMemoryDatastore,
    >,
);

fn setup_trust_m() -> TrustMRig {
    let clock = SimulatedClock::new();
    let mut chip = VirtualOptiga::new(clock.clone());
    chip.registers.strict_guard_time = true;
    let shared_chip = Rc::new(RefCell::new(chip));
    let bus = FaultInjectingI2cBus::with_shared_chip(shared_chip.clone());

    let vdd = MockPin::new(clock.clone(), embedded_hal::digital::PinState::High);
    let rst = MockPin::new(clock.clone(), embedded_hal::digital::PinState::High);

    let crypto = RustCryptoBackend;
    let ds = InMemoryDatastore::new();

    let optiga = OptigaTrustM::new(bus, clock.clone(), vdd, rst, clock.clone(), crypto, ds);
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

    // Increment Monotonic Counter
    assert!(util.increment_monotonic_counter(Oid::MonotonicCounter0, 1).is_ok());

    // Close Application
    assert!(util.close_application(false).is_ok());
}

#[test]
fn test_crypt_trng_and_keypair_generation() {
    let (_clock, _chip, mut optiga) = setup_trust_m();
    optiga.open(ResetType::Warm, 277, 400).expect("open succeeds");

    let mut crypt = optiga.crypt();

    // TRNG
    let mut rnd = [0u8; 16];
    assert!(crypt.get_random(&mut rnd).is_ok());
    assert_ne!(rnd, [0u8; 16]);

    // Keypair generation in session slot
    let mut pubkey = [0u8; 65];
    let slot = crypt
        .generate_keypair_in_session(EccCurve::NistP256, KeyUsage::auth_and_sign(), &mut pubkey)
        .expect("keypair gen succeeds");

    assert_eq!(slot.index(), 0);
    assert_eq!(slot.oid(), Oid::SessionContext0);
    assert_eq!(pubkey[0], 0x04); // Uncompressed format prefix
}

#[test]
fn test_crypt_ecdsa_sign_verify_and_ecdh() {
    let (_clock, _chip, mut optiga) = setup_trust_m();
    optiga.open(ResetType::Warm, 277, 400).expect("open succeeds");

    let mut crypt = optiga.crypt();

    // ECDSA Sign
    let digest = [0x11u8; 32];
    let mut signature = [0u8; 64];
    let sig_len = crypt
        .ecdsa_sign(&digest, Oid::DevicePrivateKey0, &mut signature)
        .expect("sign succeeds");
    assert_eq!(sig_len, 64);

    // ECDSA Verify
    let pubkey = [0x04u8; 65];
    let valid = crypt
        .ecdsa_verify(&digest, &signature, &pubkey, EccCurve::NistP256)
        .expect("verify succeeds");
    assert!(valid);

    // ECDH Key Agreement
    let mut shared_secret = [0u8; 32];
    let ssec_len = crypt
        .ecdh(Oid::DevicePrivateKey0, &pubkey, EccCurve::NistP256, &mut shared_secret)
        .expect("ecdh succeeds");
    assert_eq!(ssec_len, 32);
    assert_eq!(shared_secret, [0x33u8; 32]);
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
