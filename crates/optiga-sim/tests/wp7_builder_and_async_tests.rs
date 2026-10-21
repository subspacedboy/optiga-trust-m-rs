//! Integration tests for Proposal A (`OptigaTimer`, `OptigaBuilder`, `OptigaPlatform` / `OptigaFor<P>`)
//! and Proposal C (native `embedded-hal-async` driver in `optiga_trust_m_rs::asynch`).

use core::future::Future;
use core::pin::pin;
use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
use optiga_sim::clock::{MockPin, SimulatedClock};
use optiga_sim::datastore::InMemoryDatastore;
use optiga_sim::fault_bus::{FaultInjectingI2cBus, FaultRule};
use optiga_sim::virtual_chip::VirtualOptiga;
use optiga_trust_m_rs::asynch;
use optiga_trust_m_rs::cmd::types::{EccCurve, KdfAlg, KeyUsage, Oid, RngType};
use optiga_trust_m_rs::error::{DeviceError, OptigaError};
use optiga_trust_m_rs::ifx_i2c::headers::{ProtectionConfig, ProtectionLevel, ResetType};
use optiga_trust_m_rs::pal::rust_crypto::RustCryptoBackend;
use optiga_trust_m_rs::{OptigaFor, OptigaPlatform, OptigaTrustM};
use std::cell::RefCell;
use std::rc::Rc;

/// Zero-dependency single-threaded `block_on` executor for testing `embedded-hal-async` futures.
fn block_on<F: Future>(fut: F) -> F::Output {
    const VTABLE: RawWakerVTable = RawWakerVTable::new(
        |p| RawWaker::new(p, &VTABLE),
        |_| {},
        |_| {},
        |_| {},
    );
    let waker = unsafe { Waker::from_raw(RawWaker::new(core::ptr::null(), &VTABLE)) };
    let mut cx = Context::from_waker(&waker);
    let mut pinned = pin!(fut);
    loop {
        if let Poll::Ready(val) = pinned.as_mut().poll(&mut cx) {
            return val;
        }
    }
}

struct MinimalSyncBoard;

impl OptigaPlatform for MinimalSyncBoard {
    type I2c = FaultInjectingI2cBus;
    type Timer = SimulatedClock;
    type VddPin = optiga_trust_m_rs::NoPin;
    type RstPin = optiga_trust_m_rs::NoPin;
    type Crypto = RustCryptoBackend;
    type Datastore = optiga_trust_m_rs::NoDatastore;
}

struct FullAsyncBoard;

impl asynch::OptigaPlatform for FullAsyncBoard {
    type I2c = FaultInjectingI2cBus;
    type Timer = SimulatedClock;
    type VddPin = MockPin;
    type RstPin = MockPin;
    type Crypto = RustCryptoBackend;
    type Datastore = InMemoryDatastore;
}

#[test]
fn test_proposal_a_minimal_builder_and_platform_alias() {
    let clock = SimulatedClock::new();
    let mut chip = VirtualOptiga::new(clock.clone());
    chip.registers.strict_guard_time = true;
    let shared_chip = Rc::new(RefCell::new(chip));
    let bus = FaultInjectingI2cBus::with_shared_chip(shared_chip.clone());

    // Proposal A: Minimal 2-parameter builder using Soft Reset and NoPin/NoDatastore defaults
    let mut optiga: OptigaFor<MinimalSyncBoard> = OptigaTrustM::builder(bus, clock).build();

    optiga
        .open(ResetType::Soft, 277, 400)
        .expect("soft reset open succeeds");
    optiga
        .util()
        .open_application(false)
        .expect("open_application succeeds");

    let mut rnd = [0u8; 16];
    optiga
        .crypt()
        .get_random(&mut rnd)
        .expect("get_random succeeds");
    assert_ne!(rnd, [0u8; 16]);
    assert_eq!(shared_chip.borrow().registers.guard_time_violations, 0);
}

#[test]
fn test_proposal_c_async_full_lifecycle_shielded_and_crypto() {
    block_on(async {
        let clock = SimulatedClock::new();
        let mut chip = VirtualOptiga::new(clock.clone());
        chip.registers.strict_guard_time = true;
        let shared_chip = Rc::new(RefCell::new(chip));
        let bus = FaultInjectingI2cBus::with_shared_chip(shared_chip.clone());

        let vdd = MockPin::new(clock.clone(), embedded_hal::digital::PinState::High);
        let rst = MockPin::new(clock.clone(), embedded_hal::digital::PinState::High);
        let ds = InMemoryDatastore::new();

        // Construct async driver via fluent builder + OptigaFor<FullAsyncBoard>
        let mut optiga: asynch::OptigaFor<FullAsyncBoard> =
            asynch::OptigaTrustM::builder(bus.clone(), clock.clone())
                .with_vdd_pin(vdd)
                .with_reset_pin(rst)
                .with_datastore(ds)
                .build();

        // 1. Async Open (Warm Reset + Negotiate 277B @ 400kHz)
        optiga
            .open(ResetType::Warm, 277, 400)
            .await
            .expect("async open succeeds");

        // 2. Async Utility operations under Full Shielded Connection
        {
            let mut util = optiga.util();
            util.set_protection(ProtectionConfig {
                level: ProtectionLevel::Full,
                force_reestablish: false,
            });

            util.open_application(false)
                .await
                .expect("async open_application under Full protection succeeds");

            util.write_data(Oid::Data0, 0, &[0xDE, 0xAD, 0xBE, 0xEF], true)
                .await
                .expect("async write_data succeeds");

            let mut read_buf = [0u8; 4];
            let len = util
                .read_data(Oid::Data0, 0, &mut read_buf)
                .await
                .expect("async read_data succeeds");
            assert_eq!(len, 4);

            util.write_metadata(Oid::Data0, &[0x20, 0x03, 0xD0, 0x01, 0x00])
                .await
                .expect("async write_metadata succeeds");

            let mut meta_buf = [0u8; 4];
            util.read_metadata(Oid::Data0, &mut meta_buf)
                .await
                .expect("async read_metadata succeeds");

            util.increment_monotonic_counter(Oid::MonotonicCounter0, 2)
                .await
                .expect("async increment_monotonic_counter succeeds");

            util.protected_update(0x01, &[0x01, 0x02], &[&[0xAA, 0xBB], &[0xCC, 0xDD]])
                .await
                .expect("async protected_update succeeds");

            // Hibernate close & restore open roundtrip
            util.close_application(true)
                .await
                .expect("async close_application(true) succeeds");
            util.open_application(true)
                .await
                .expect("async open_application(true) succeeds");
        }

        // 3. Async Session Context Save & Restore across Warm Reset
        optiga
            .cmd
            .stack
            .close(true)
            .await
            .expect("async stack close(true) saves context");
        optiga
            .cmd
            .stack
            .reset(ResetType::Warm)
            .await
            .expect("async warm reset succeeds");
        optiga
            .cmd
            .stack
            .restore_context()
            .await
            .expect("async restore_context succeeds");

        // 4. Async Cryptographic suite + Fault Recovery
        {
            let mut crypt = optiga.crypt();
            crypt.set_protection(ProtectionConfig {
                level: ProtectionLevel::Full,
                force_reestablish: false,
            });

            // Inject 5 NACKs to verify async NACK retry loop
            bus.add_rule(FaultRule::NackNextWrites(5));

            let mut rnd = [0u8; 16];
            crypt
                .get_random(&mut rnd)
                .await
                .expect("async get_random recovers from NACKs");
            assert_ne!(rnd, [0u8; 16]);
            crypt
                .get_random_with_type(RngType::Drng, &mut rnd)
                .await
                .expect("async DRNG succeeds");

            // SHA-256 Hash
            let mut digest = [0u8; 32];
            crypt
                .hash_sha256(b"async optiga", &mut digest)
                .await
                .expect("async hash_sha256 succeeds");

            // Ephemeral Session Keypair + ECDSA Sign + Verify
            let mut pubkey = [0u8; 65];
            let slot = crypt
                .generate_keypair_in_session(
                    EccCurve::NistP256,
                    KeyUsage::auth_and_sign(),
                    &mut pubkey,
                )
                .await
                .expect("async generate_keypair_in_session succeeds");

            let mut sig = [0u8; 72];
            let sig_len = crypt
                .ecdsa_sign_with_session(&digest, &slot, &mut sig)
                .await
                .expect("async ecdsa_sign_with_session succeeds");
            assert_eq!(sig_len, 68);

            let valid = crypt
                .ecdsa_verify(&digest, &sig[..sig_len], &pubkey, EccCurve::NistP256)
                .await
                .expect("async ecdsa_verify succeeds");
            assert!(valid);

            // ECDH to session + HKDF DeriveKey
            let ssec_slot = crypt
                .ecdh_to_session(Oid::DevicePrivateKey0, &pubkey, EccCurve::NistP256)
                .await
                .expect("async ecdh_to_session succeeds");

            let mut derived = [0u8; 32];
            crypt
                .derive_key_to_host(
                    KdfAlg::HkdfSha256,
                    ssec_slot.oid(),
                    b"label",
                    b"salt",
                    Some(b"info"),
                    &mut derived,
                )
                .await
                .expect("async derive_key_to_host succeeds");
            assert_eq!(derived[0], 0xA0);

            crypt.cmd.release_session_slot(ssec_slot);
            crypt.cmd.release_session_slot(slot);
        }

        // 5. Async automatic 0xF1C2 device error retrieval
        shared_chip.borrow_mut().apdu.force_next_command_failure = true;
        let mut buf = [0u8; 4];
        let err = optiga.util().read_data(Oid::Data0, 0, &mut buf).await;
        assert_eq!(
            err,
            Err(OptigaError::Device(DeviceError::AccessConditionNotSatisfied))
        );

        assert_eq!(shared_chip.borrow().registers.guard_time_violations, 0);
    });
}
