//! Simulated monotonic clock, delay provider, and mock GPIO pins for host testing.

use embedded_hal::delay::DelayNs;
use embedded_hal::digital::{ErrorType, OutputPin, PinState};
use optiga_trust_m_rs::pal::MonotonicClock;
use std::cell::RefCell;
use std::convert::Infallible;
use std::rc::Rc;

/// Internal state of the simulated clock.
#[derive(Debug, Clone, Default)]
struct ClockState {
    time_us: u64,
}

/// Simulated clock and delay provider implementing `MonotonicClock` and `DelayNs`.
#[derive(Debug, Clone, Default)]
pub struct SimulatedClock {
    state: Rc<RefCell<ClockState>>,
}

impl SimulatedClock {
    pub fn new() -> Self {
        Self {
            state: Rc::new(RefCell::new(ClockState { time_us: 0 })),
        }
    }

    /// Sets the current time in microseconds.
    pub fn set_time_us(&self, us: u64) {
        self.state.borrow_mut().time_us = us;
    }

    /// Returns current simulated time in microseconds.
    pub fn now_us(&self) -> u64 {
        self.state.borrow().time_us
    }

    /// Advances the clock by the given number of microseconds.
    pub fn advance_us(&self, us: u64) {
        self.state.borrow_mut().time_us += us;
    }

    /// Advances the clock by the given number of milliseconds.
    pub fn advance_ms(&self, ms: u32) {
        self.advance_us(ms as u64 * 1_000);
    }
}

impl MonotonicClock for SimulatedClock {
    fn now_ms(&self) -> u32 {
        (self.state.borrow().time_us / 1_000) as u32
    }
}

impl DelayNs for SimulatedClock {
    fn delay_ns(&mut self, ns: u32) {
        // Round up to nearest microsecond for realistic timing
        let us = (ns as u64).div_ceil(1000);
        self.advance_us(us);
    }

    fn delay_us(&mut self, us: u32) {
        self.advance_us(us as u64);
    }

    fn delay_ms(&mut self, ms: u32) {
        self.advance_ms(ms);
    }
}

impl embedded_hal_async::delay::DelayNs for SimulatedClock {
    async fn delay_ns(&mut self, ns: u32) {
        DelayNs::delay_ns(self, ns);
    }

    async fn delay_us(&mut self, us: u32) {
        DelayNs::delay_us(self, us);
    }

    async fn delay_ms(&mut self, ms: u32) {
        DelayNs::delay_ms(self, ms);
    }
}

/// Record of a GPIO pin transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PinTransition {
    pub timestamp_us: u64,
    pub state: PinState,
}

/// Mock GPIO output pin recording timestamps of state transitions.
#[derive(Debug, Clone)]
pub struct MockPin {
    clock: SimulatedClock,
    current_state: PinState,
    history: Rc<RefCell<Vec<PinTransition>>>,
}

impl MockPin {
    pub fn new(clock: SimulatedClock, initial: PinState) -> Self {
        let history = Rc::new(RefCell::new(vec![PinTransition {
            timestamp_us: clock.now_us(),
            state: initial,
        }]));
        Self {
            clock,
            current_state: initial,
            history,
        }
    }

    pub fn state(&self) -> PinState {
        self.current_state
    }

    pub fn is_high(&self) -> bool {
        self.current_state == PinState::High
    }

    pub fn is_low(&self) -> bool {
        self.current_state == PinState::Low
    }

    pub fn transitions(&self) -> Vec<PinTransition> {
        self.history.borrow().clone()
    }

    /// Returns the total duration in microseconds that the pin spent in `Low` state during the last pulse.
    pub fn last_low_duration_us(&self) -> Option<u64> {
        let h = self.history.borrow();
        let mut low_start = None;
        let mut last_duration = None;

        for t in h.iter() {
            match t.state {
                PinState::Low if low_start.is_none() => {
                    low_start = Some(t.timestamp_us);
                }
                PinState::High if low_start.is_some() => {
                    let start = low_start.take().unwrap();
                    last_duration = Some(t.timestamp_us.saturating_sub(start));
                }
                _ => {}
            }
        }
        last_duration
    }
}

impl ErrorType for MockPin {
    type Error = Infallible;
}

impl OutputPin for MockPin {
    fn set_low(&mut self) -> Result<(), Self::Error> {
        self.current_state = PinState::Low;
        self.history.borrow_mut().push(PinTransition {
            timestamp_us: self.clock.now_us(),
            state: PinState::Low,
        });
        Ok(())
    }

    fn set_high(&mut self) -> Result<(), Self::Error> {
        self.current_state = PinState::High;
        self.history.borrow_mut().push(PinTransition {
            timestamp_us: self.clock.now_us(),
            state: PinState::High,
        });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clock_delay_and_monotonic() {
        let mut clock = SimulatedClock::new();
        assert_eq!(clock.now_us(), 0);
        assert_eq!(clock.now_ms(), 0);

        clock.delay_us(50);
        assert_eq!(clock.now_us(), 50);
        assert_eq!(clock.now_ms(), 0);

        clock.delay_ms(2);
        assert_eq!(clock.now_us(), 2050);
        assert_eq!(clock.now_ms(), 2);
    }

    #[test]
    fn test_mock_pin_pulse_duration() {
        let mut clock = SimulatedClock::new();
        let mut pin = MockPin::new(clock.clone(), PinState::High);

        clock.delay_ms(5);
        pin.set_low().unwrap();
        clock.delay_us(2000); // 2000 µs low pulse (RESET_LOW_TIME_US)
        pin.set_high().unwrap();

        assert_eq!(pin.last_low_duration_us(), Some(2000));
    }
}
