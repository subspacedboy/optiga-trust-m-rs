//! Integration tests for WP3: Physical Layer & Data Link Layer against VirtualOptiga.

use optiga_sim::clock::{MockPin, SimulatedClock};
use optiga_sim::fault_bus::{FaultInjectingI2cBus, FaultRule};
use optiga_sim::virtual_chip::VirtualOptiga;
use optiga_trust_m_rs::config::*;
use optiga_trust_m_rs::error::IfxI2cError;
use optiga_trust_m_rs::ifx_i2c::datalink::{DataLinkLayer, DlEvent};
use optiga_trust_m_rs::ifx_i2c::headers::{PlRegister, ResetType};
use optiga_trust_m_rs::ifx_i2c::physical::PhysicalLayer;
use std::cell::RefCell;
use std::rc::Rc;

type TestRig = (
    SimulatedClock,
    Rc<RefCell<VirtualOptiga>>,
    FaultInjectingI2cBus,
    PhysicalLayer<FaultInjectingI2cBus, SimulatedClock, MockPin, MockPin>,
);

fn setup_test_rig() -> TestRig {
    let clock = SimulatedClock::new();
    let mut chip = VirtualOptiga::new(clock.clone());
    chip.registers.strict_guard_time = true; // Strict 50 µs guard time invariant enforcement
    let shared_chip = Rc::new(RefCell::new(chip));
    let bus = FaultInjectingI2cBus::with_shared_chip(shared_chip.clone());

    let vdd_pin = MockPin::new(clock.clone(), embedded_hal::digital::PinState::High);
    let rst_pin = MockPin::new(clock.clone(), embedded_hal::digital::PinState::High);

    let pl = PhysicalLayer::new(bus.clone(), clock.clone(), vdd_pin, rst_pin);
    (clock, shared_chip, bus, pl)
}

#[test]
fn test_pl_resets_and_guard_time_compliance() {
    let (clock, chip, _bus, mut pl) = setup_test_rig();

    // 1. Cold Reset
    assert!(pl.reset(ResetType::Cold).is_ok());
    assert_eq!(pl.rst_pin.last_low_duration_us(), Some(RESET_LOW_TIME_US as u64));
    assert_eq!(chip.borrow().registers.guard_time_violations, 0);

    // 2. Warm Reset
    clock.advance_us(100);
    assert!(pl.reset(ResetType::Warm).is_ok());
    assert_eq!(pl.rst_pin.last_low_duration_us(), Some(RESET_LOW_TIME_US as u64));
    assert_eq!(chip.borrow().registers.guard_time_violations, 0);

    // 3. Soft Reset
    clock.advance_us(100);
    assert!(pl.reset(ResetType::Soft).is_ok());
    assert_eq!(chip.borrow().registers.guard_time_violations, 0);
}

#[test]
fn test_pl_negotiate_sm_fm_and_fm_plus() {
    let (_clock, chip, _bus, mut pl) = setup_test_rig();

    // Reset chip first
    assert!(pl.reset(ResetType::Warm).is_ok());

    // Negotiate SM/FM (400 kHz) and frame size 277
    assert!(pl.negotiate(277, 400).is_ok());
    assert_eq!(pl.negotiated_frequency_khz, 400);
    assert_eq!(pl.negotiated_frame_size, 277);
    assert_eq!(chip.borrow().registers.guard_time_violations, 0);

    // Negotiate FM+ (1000 kHz) and down-negotiated frame size 64
    assert!(pl.negotiate(64, 1000).is_ok());
    assert_eq!(pl.negotiated_frequency_khz, 1000);
    assert_eq!(pl.negotiated_frame_size, 64);
    assert_eq!(chip.borrow().registers.guard_time_violations, 0);
}

#[test]
fn test_pl_sleep_nack_wakeup_recovery() {
    let (_clock, _chip, bus, mut pl) = setup_test_rig();

    // Injects 25 consecutive NACKs simulating chip in sleep state
    bus.add_rule(FaultRule::NackNextWrites(25));

    // write_register should retry 25 times and succeed on attempt 26
    let res = pl.write_register(PlRegister::DataRegLen, &[0x01, 0x15]);
    assert!(res.is_ok());
}

#[test]
fn test_pl_nack_exhaustion_fatal_error() {
    let (_clock, _chip, bus, mut pl) = setup_test_rig();

    // Inject 201 consecutive NACKs (exceeding PL_POLLING_MAX_CNT = 200)
    bus.add_rule(FaultRule::NackNextWrites(201));

    let res = pl.write_register(PlRegister::DataRegLen, &[0x01, 0x15]);
    assert_eq!(res, Err(IfxI2cError::FatalError));
}

#[test]
fn test_dl_sequence_rollover_roundtrip() {
    let (_clock, _chip, _bus, mut pl) = setup_test_rig();
    assert!(pl.reset(ResetType::Warm).is_ok());
    assert!(pl.negotiate(277, 400).is_ok());

    let mut dl = DataLinkLayer::new();
    let mut rx_buf = [0u8; 300];

    // Send 8 consecutive frames, verifying sequence numbers roll over: 0, 1, 2, 3, 0, 1, 2, 3
    for i in 0..8 {
        let payload = [0xA0, i as u8, 0x01, 0x02];
        let event = dl.send_frame(&mut pl, &payload, &mut rx_buf).expect("send frame succeeds");
        assert!(matches!(event, DlEvent::TxSuccess | DlEvent::TxAndRxSuccess(_)));
        assert_eq!(dl.tx_seq_nr, (i as u8) & 0x03);
    }
}

#[test]
fn test_dl_corrupted_response_crc_triggers_retransmit() {
    let (_clock, _chip, bus, mut pl) = setup_test_rig();
    assert!(pl.reset(ResetType::Warm).is_ok());
    assert!(pl.negotiate(277, 400).is_ok());

    let mut dl = DataLinkLayer::new();
    let mut rx_buf = [0u8; 300];

    // Corrupt the CRC of the first response from slave
    // Response frame is 5 bytes: byte 4 is CRC LSB
    bus.add_rule(FaultRule::CorruptNextReadByte { offset: 4, mask: 0x01 });

    let payload = [0x55, 0xAA];
    // Master should detect the CRC corruption, retransmit, and succeed on retry
    let event = dl.send_frame(&mut pl, &payload, &mut rx_buf).expect("retransmits and succeeds");
    assert_eq!(event, DlEvent::TxSuccess);
}

#[test]
fn test_dl_three_retries_resync_recovery() {
    let (_clock, chip, bus, mut pl) = setup_test_rig();
    assert!(pl.reset(ResetType::Warm).is_ok());
    assert!(pl.negotiate(277, 400).is_ok());

    let mut dl = DataLinkLayer::new();
    let mut rx_buf = [0u8; 300];

    // Force 2 failures on read, triggering retransmits
    bus.add_rule(FaultRule::NackNextReads(2));

    let payload = [0x11, 0x22, 0x33];
    let event = dl.send_frame(&mut pl, &payload, &mut rx_buf).expect("send succeeds after retries");
    assert_eq!(event, DlEvent::TxSuccess);

    // Verify 0 guard time violations occurred throughout all retries
    assert_eq!(chip.borrow().registers.guard_time_violations, 0);
}

#[test]
fn test_dl_resync_when_seq_nonzero_updates_fctr_and_crc() {
    let (_clock, _chip, bus, mut pl) = setup_test_rig();
    assert!(pl.reset(ResetType::Warm).is_ok());
    assert!(pl.negotiate(277, 400).is_ok());

    let mut dl = DataLinkLayer::new();
    let mut rx_buf = [0u8; 300];

    // Send 2 frames so tx_seq_nr advances from 3 -> 0 -> 1
    let _ = dl.send_frame(&mut pl, &[0x55, 0xAA], &mut rx_buf).unwrap();
    let _ = dl.send_frame(&mut pl, &[0x55, 0xAA], &mut rx_buf).unwrap();
    assert_eq!(dl.tx_seq_nr, 1);

    // Corrupt the 5-byte Control Frame ACK 3 times in a row so the 3rd frame (initially FRNR = 2)
    // exhausts DL_TRANS_REPEAT (3) and triggers perform_resync!
    // After perform_resync, master and slave reset to 3 and master must re-encode the frame with FRNR = 0!
    bus.add_rule(FaultRule::CorruptNextReadByte { offset: 4, mask: 0x01 });
    bus.add_rule(FaultRule::CorruptNextReadByte { offset: 4, mask: 0x01 });
    bus.add_rule(FaultRule::CorruptNextReadByte { offset: 4, mask: 0x01 });

    let event = dl
        .send_frame(&mut pl, &[0x55, 0xAA], &mut rx_buf)
        .expect("resync updates FRNR to 0 and succeeds");
    assert_eq!(event, DlEvent::TxSuccess);
    assert_eq!(dl.tx_seq_nr, 0);
}

#[test]
fn test_pl_volatile_and_persistent_slave_address_reset() {
    let (_clock, _chip, _bus, mut pl) = setup_test_rig();
    assert!(pl.reset(ResetType::Warm).is_ok());

    // Change slave address to 0x32 in VOLATILE mode (persistent = false)
    assert!(pl.write_slave_address(0x32, false).is_ok());
    assert_eq!(pl.slave_address, 0x32);
    assert_eq!(pl.configured_base_address, 0x30);

    // Soft reset should revert both chip and PL active slave_address back to 0x30
    assert!(pl.reset(ResetType::Soft).is_ok());
    assert_eq!(pl.slave_address, 0x30);
    assert!(pl.negotiate(277, 400).is_ok());
}
