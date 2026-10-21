//! `optiga-sim`: Host-side Virtual OPTIGA™ Trust M chip emulator and fault-injecting test harness.

pub mod clock;
pub mod datastore;
pub mod fault_bus;
pub mod virtual_chip;

pub use clock::{MockPin, PinTransition, SimulatedClock};
pub use datastore::{InMemoryDatastore, DEFAULT_PLATFORM_BINDING_SECRET};
pub use fault_bus::{BusError, FaultInjectingI2cBus, FaultRule};
pub use virtual_chip::{VirtualChipError, VirtualOptiga};
