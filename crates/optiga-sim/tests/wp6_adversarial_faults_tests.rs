//! Integration tests for WP6: Tier 3 Adversarial Fault Suite & End-to-End Stress Validation.

use optiga_sim::clock::{MockPin, SimulatedClock};
use optiga_sim::datastore::InMemoryDatastore;
use optiga_sim::fault_bus::{FaultInjectingI2cBus, FaultRule};
use optiga_sim::virtual_chip::VirtualOptiga;
use optiga_trust_m_rs::cmd::types::Oid;
use optiga_trust_m_rs::error::IfxI2cError;
use optiga_trust_m_rs::ifx_i2c::headers::{PlRegister, ProtectionConfig, ProtectionLevel, ResetType};
use optiga_trust_m_rs::pal::rust_crypto::RustCryptoBackend;
use optiga_trust_m_rs::{OptigaFor, OptigaPlatform, OptigaTrustM};
use std::cell::RefCell;
use std::rc::Rc;

struct AdvPlatform;

impl OptigaPlatform for AdvPlatform {
    type I2c = FaultInjectingI2cBus;
    type Timer = SimulatedClock;
    type VddPin = MockPin;
    type RstPin = MockPin;
    type Crypto = RustCryptoBackend;
    type Datastore = InMemoryDatastore;
}

type AdvRig = (
    SimulatedClock,
    Rc<RefCell<VirtualOptiga>>,
    FaultInjectingI2cBus,
    OptigaFor<AdvPlatform>,
);

fn setup_adv_rig() -> AdvRig {
    let clock = SimulatedClock::new();
    let mut chip = VirtualOptiga::new(clock.clone());
    chip.registers.strict_guard_time = true;
    let shared_chip = Rc::new(RefCell::new(chip));
    let bus = FaultInjectingI2cBus::with_shared_chip(shared_chip.clone());

    let vdd = MockPin::new(clock.clone(), embedded_hal::digital::PinState::High);
    let rst = MockPin::new(clock.clone(), embedded_hal::digital::PinState::High);

    let ds = InMemoryDatastore::new();

    let optiga = OptigaTrustM::builder(bus.clone(), clock.clone())
        .with_pins(vdd, rst)
        .with_datastore(ds)
        .build();
    (clock, shared_chip, bus, optiga)
}

#[test]
fn test_adv_pl_sleep_nack_recovery() {
    let (_clock, _chip, bus, mut optiga) = setup_adv_rig();

    // Slave in deep sleep: NACKs first 25 I2C writes
    bus.add_rule(FaultRule::NackNextWrites(25));

    // Driver polls every 1 ms and succeeds on attempt 26
    let res = optiga.cmd.stack.pl.write_register(PlRegister::DataRegLen, &[0x01, 0x15]);
    assert!(res.is_ok());
}

#[test]
fn test_adv_pl_nack_exhaustion() {
    let (_clock, _chip, bus, mut optiga) = setup_adv_rig();

    // Slave NACKs 201 consecutive I2C writes (exceeding max retry count 200)
    bus.add_rule(FaultRule::NackNextWrites(201));

    let res = optiga.cmd.stack.pl.write_register(PlRegister::DataRegLen, &[0x01, 0x15]);
    assert_eq!(res, Err(IfxI2cError::FatalError));
}

#[test]
fn test_adv_dl_rx_crc_corruption_nack_recovery() {
    let (_clock, _chip, bus, mut optiga) = setup_adv_rig();
    optiga.open(ResetType::Warm, 277, 400).expect("open succeeds");

    // Corrupt 1 byte in the first response from slave
    bus.add_rule(FaultRule::CorruptNextReadByte { offset: 4, mask: 0x02 });

    let mut buf = [0u8; 10];
    let res = optiga.util().read_data(Oid::Data0, 0, &mut buf);
    assert!(res.is_ok(), "Master NACKs corrupted frame, slave retransmits, and succeeds");
}

#[test]
fn test_adv_dl_tx_nack_retransmit_and_resync() {
    let (_clock, _chip, bus, mut optiga) = setup_adv_rig();
    optiga.open(ResetType::Warm, 277, 400).expect("open succeeds");

    // Force 2 consecutive read NACKs
    bus.add_rule(FaultRule::NackNextReads(2));

    let mut buf = [0u8; 10];
    let res = optiga.util().read_data(Oid::Data0, 0, &mut buf);
    assert!(res.is_ok());
}

#[test]
fn test_adv_tl_rx_buffer_overflow_drains_chain() {
    let (_clock, _chip, _bus, mut optiga) = setup_adv_rig();
    optiga.open(ResetType::Warm, 277, 400).expect("open succeeds");

    // Request data into a 2-byte buffer (chip returns 4 bytes)
    let mut small_buf = [0u8; 2];
    let res = optiga.util().read_data(Oid::Data0, 0, &mut small_buf);
    assert_eq!(res, Err(optiga_trust_m_rs::error::OptigaError::MemoryInsufficient));
}

#[test]
fn test_adv_prl_slave_mac_corruption_alert_retry() {
    let (_clock, _chip, bus, mut optiga) = setup_adv_rig();
    optiga.open(ResetType::Warm, 277, 400).expect("open succeeds");

    let mut buf = [0u8; 16];

    // Establish full shielded session first
    optiga
        .crypt()
        .get_random(&mut buf)
        .expect("initial handshake succeeds");

    let mut util = optiga.util();
    util.set_protection(ProtectionConfig {
        level: ProtectionLevel::Full,
        force_reestablish: false,
    });

    // Corrupt MAC tag byte of next encrypted response record from slave
    // Response frame has header(3B) + PCTR(1B) + SCTR(1B) + Seq(4B) + Data(4B) + Tag(8B) + CRC(2B)
    bus.add_rule(FaultRule::CorruptNextReadByte { offset: 15, mask: 0x80 });

    let mut read_buf = [0u8; 4];
    let res = util.read_data(Oid::Data0, 0, &mut read_buf);
    assert!(
        res.is_ok(),
        "Master detects MAC tag failure, sends IntegrityViolated alert [0x44], slave re-encrypts and succeeds!"
    );
}

#[test]
fn test_adv_prl_sequence_threshold_renegotiation() {
    let (_clock, _chip, _bus, mut optiga) = setup_adv_rig();
    optiga.open(ResetType::Warm, 277, 400).expect("open succeeds");

    let mut buf = [0u8; 16];
    optiga.crypt().get_random(&mut buf).expect("handshake succeeds");

    // Push master sequence number to 0xFFFFFFF0
    optiga.cmd.stack.prl.master_sequence_number = 0xFFFF_FFF0;

    let mut util = optiga.util();
    util.set_protection(ProtectionConfig {
        level: ProtectionLevel::Full,
        force_reestablish: false,
    });

    let mut read_buf = [0u8; 4];
    let res = util.read_data(Oid::Data0, 0, &mut read_buf);
    assert!(res.is_ok());

    // Sequence number was renegotiated and reset to small value
    assert!(optiga.cmd.stack.prl.master_sequence_number < 10);
}

#[test]
fn test_adv_full_stack_stress_transceive() {
    let (_clock, chip, _bus, mut optiga) = setup_adv_rig();
    optiga.open(ResetType::Warm, 277, 400).expect("open succeeds");

    optiga.util().set_protection(ProtectionConfig {
        level: ProtectionLevel::Full,
        force_reestablish: false,
    });

    // Execute 20 consecutive protected transactions
    for i in 0..20 {
        let mut buf = [0u8; 4];
        let res = optiga.util().read_data(Oid::Data0, i as u16, &mut buf);
        assert!(res.is_ok());
    }

    // Verify 0 guard time violations across all 20 protected roundtrips!
    assert_eq!(chip.borrow().registers.guard_time_violations, 0);
}
