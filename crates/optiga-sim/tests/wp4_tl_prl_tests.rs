//! Integration tests for WP4: Transport Layer & Presentation Layer against VirtualOptiga.

use optiga_sim::clock::{MockPin, SimulatedClock};
use optiga_sim::datastore::InMemoryDatastore;
use optiga_sim::fault_bus::FaultInjectingI2cBus;
use optiga_sim::virtual_chip::VirtualOptiga;
use optiga_trust_m_rs::error::IfxI2cError;
use optiga_trust_m_rs::ifx_i2c::headers::{ProtectionConfig, ProtectionLevel, ResetType};
use optiga_trust_m_rs::ifx_i2c::IfxI2cStack;
use optiga_trust_m_rs::pal::rust_crypto::RustCryptoBackend;
use std::cell::RefCell;
use std::rc::Rc;

type StackRig = (
    SimulatedClock,
    Rc<RefCell<VirtualOptiga>>,
    IfxI2cStack<
        FaultInjectingI2cBus,
        SimulatedClock,
        MockPin,
        MockPin,
        RustCryptoBackend,
        InMemoryDatastore,
    >,
);

fn setup_stack() -> StackRig {
    let clock = SimulatedClock::new();
    let mut chip = VirtualOptiga::new(clock.clone());
    chip.registers.strict_guard_time = true;
    let shared_chip = Rc::new(RefCell::new(chip));
    let bus = FaultInjectingI2cBus::with_shared_chip(shared_chip.clone());

    let vdd = MockPin::new(clock.clone(), embedded_hal::digital::PinState::High);
    let rst = MockPin::new(clock.clone(), embedded_hal::digital::PinState::High);

    let crypto = RustCryptoBackend;
    let ds = InMemoryDatastore::new();

    let stack = IfxI2cStack::new(bus, clock.clone(), vdd, rst, crypto, ds);
    (clock, shared_chip, stack)
}

#[test]
fn test_tl_multi_fragment_tx() {
    let (_clock, _chip, mut stack) = setup_stack();

    // Negotiate 64-byte frame size (max TL fragment payload = 58 bytes)
    stack
        .open(ResetType::Warm, 64, 400)
        .expect("stack open succeeds");

    // Send OpenApplication APDU (16 bytes payload)
    // [Cmd=0x70, Param=0x00, Len=0x0000]
    let apdu_tx = [0x70, 0x00, 0x00, 0x00];
    let mut apdu_rx = [0u8; 100];

    let len = stack
        .transceive(&apdu_tx, &mut apdu_rx, ProtectionConfig::default())
        .expect("transceive succeeds");

    assert_eq!(len, 4);
    assert_eq!(&apdu_rx[..4], &[0x00, 0x00, 0x00, 0x00]); // APDU success
}

#[test]
fn test_tl_rx_buffer_overflow_draining() {
    let (_clock, _chip, mut stack) = setup_stack();
    stack.open(ResetType::Warm, 277, 400).expect("open succeeds");

    // Request GetRandom of 30 bytes
    // [Cmd=0x0C, Param=0x00, Len=0x0002, 0x00, 0x1E]
    let apdu_tx = [0x0C, 0x00, 0x00, 0x02, 0x00, 0x1E];
    // Provide tiny 2-byte buffer (response is 4 + 30 = 34 bytes)
    let mut small_rx = [0u8; 2];

    let res = stack.transceive(&apdu_tx, &mut small_rx, ProtectionConfig::default());
    assert_eq!(res, Err(IfxI2cError::MemoryInsufficient));
}

#[test]
fn test_prl_shielded_connection_all_protection_levels() {
    let (_clock, _chip, mut stack) = setup_stack();
    stack
        .open(ResetType::Warm, 277, 400)
        .expect("stack open succeeds");

    let mut apdu_rx = [0u8; 100];

    // 1. None Protection
    let open_app = [0x70, 0x00, 0x00, 0x00];
    let len = stack
        .transceive(
            &open_app,
            &mut apdu_rx,
            ProtectionConfig {
                level: ProtectionLevel::None,
                force_reestablish: false,
            },
        )
        .expect("None protection succeeds");
    assert_eq!(&apdu_rx[..len], &[0x00, 0x00, 0x00, 0x00]);

    // 2. Master Protection (triggers initial Handshake)
    let get_random = [0x0C, 0x00, 0x00, 0x02, 0x00, 0x08];
    let len = stack
        .transceive(
            &get_random,
            &mut apdu_rx,
            ProtectionConfig {
                level: ProtectionLevel::Master,
                force_reestablish: false,
            },
        )
        .expect("Master protection succeeds");
    assert_eq!(len, 12); // 4B APDU header + 8B random

    // 3. Slave Protection
    let len = stack
        .transceive(
            &get_random,
            &mut apdu_rx,
            ProtectionConfig {
                level: ProtectionLevel::Slave,
                force_reestablish: false,
            },
        )
        .expect("Slave protection succeeds");
    assert_eq!(len, 12);

    // 4. Full Protection
    let len = stack
        .transceive(
            &get_random,
            &mut apdu_rx,
            ProtectionConfig {
                level: ProtectionLevel::Full,
                force_reestablish: false,
            },
        )
        .expect("Full protection succeeds");
    assert_eq!(len, 12);
}

#[test]
fn test_prl_save_and_restore_context() {
    let (_clock, _chip, mut stack) = setup_stack();
    stack
        .open(ResetType::Warm, 277, 400)
        .expect("stack open succeeds");

    let mut apdu_rx = [0u8; 100];
    let get_random = [0x0C, 0x00, 0x00, 0x02, 0x00, 0x08];

    // Establish full shielded session
    stack
        .transceive(
            &get_random,
            &mut apdu_rx,
            ProtectionConfig {
                level: ProtectionLevel::Full,
                force_reestablish: false,
            },
        )
        .expect("full protection handshake succeeds");

    let master_seq_before = stack.prl.master_sequence_number;
    let slave_seq_before = stack.prl.save_slave_sequence_number;

    // Save session context and close
    assert!(stack.close(true).is_ok());
    assert!(!stack.prl.negotiation_state); // Session marked inactive on master

    // Warm reset (simulating wake from hibernate)
    assert!(stack.reset(ResetType::Warm).is_ok());

    // Restore context
    assert!(stack.restore_context().is_ok());
    assert!(stack.prl.negotiation_state);
    assert_eq!(stack.prl.master_sequence_number, master_seq_before);
    assert_eq!(stack.prl.save_slave_sequence_number, slave_seq_before);

    // Transceive again under Full protection without fresh handshake
    let len = stack
        .transceive(
            &get_random,
            &mut apdu_rx,
            ProtectionConfig {
                level: ProtectionLevel::Full,
                force_reestablish: false,
            },
        )
        .expect("transceive after restore succeeds");
    assert_eq!(len, 12);
}

#[test]
fn test_prl_sequence_rollover_renegotiates() {
    let (_clock, _chip, mut stack) = setup_stack();
    stack
        .open(ResetType::Warm, 277, 400)
        .expect("stack open succeeds");

    let mut apdu_rx = [0u8; 100];
    let get_random = [0x0C, 0x00, 0x00, 0x02, 0x00, 0x08];

    // Establish initial session
    stack
        .transceive(
            &get_random,
            &mut apdu_rx,
            ProtectionConfig {
                level: ProtectionLevel::Full,
                force_reestablish: false,
            },
        )
        .expect("initial handshake succeeds");

    // Manually push master sequence number to threshold (0xFFFFFFF0)
    stack.prl.master_sequence_number = 0xFFFF_FFF0;

    // Next transaction should trigger automatic re-handshake
    let len = stack
        .transceive(
            &get_random,
            &mut apdu_rx,
            ProtectionConfig {
                level: ProtectionLevel::Full,
                force_reestablish: false,
            },
        )
        .expect("transceive with re-handshake succeeds");

    assert_eq!(len, 12);
    // Master sequence should have reset to low value
    assert!(stack.prl.master_sequence_number < 10);
}
