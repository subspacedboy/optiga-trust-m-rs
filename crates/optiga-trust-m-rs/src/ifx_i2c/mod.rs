//! Infineon I2C Protocol v2.03 stack implementation (`ifx_i2c`).

pub mod datalink;
pub mod headers;
pub mod physical;
pub mod presentation;
pub mod transport;

pub use datalink::{DataLinkLayer, DlEvent};
pub use headers::{
    crc16_ccitt, crc16_ccitt_byte, ChainState, Fctr, FrameType, I2cStateStatus, Pctr, PlRegister,
    ProtectionConfig, ProtectionLevel, ProtocolType, ResetType, Sctr, SeqCtrl,
};
pub use physical::PhysicalLayer;
pub use presentation::PresentationLayer;
pub use transport::TransportLayer;

use crate::error::IfxI2cError;
use crate::pal::{Datastore, HostCrypto, MonotonicClock, OptigaI2cBus};
use embedded_hal::delay::DelayNs;
use embedded_hal::digital::OutputPin;

/// Top-level coordinator of the 4-layer `ifx_i2c` protocol stack.
pub struct IfxI2cStack<I2C, D, VDD, RST, CLK, CRYPTO, DS> {
    pub pl: PhysicalLayer<I2C, D, VDD, RST>,
    pub dl: DataLinkLayer,
    pub tl: TransportLayer,
    pub prl: PresentationLayer<CRYPTO, DS>,
    pub clock: CLK,
}

impl<I2C, D, VDD, RST, CLK, CRYPTO, DS> IfxI2cStack<I2C, D, VDD, RST, CLK, CRYPTO, DS>
where
    I2C: OptigaI2cBus,
    D: DelayNs,
    VDD: OutputPin,
    RST: OutputPin,
    CLK: MonotonicClock,
    CRYPTO: HostCrypto,
    DS: Datastore,
{
    /// Creates a new `IfxI2cStack` with the given hardware peripherals, clock, and crypto/storage providers.
    pub fn new(
        i2c: I2C,
        delay: D,
        vdd_pin: VDD,
        rst_pin: RST,
        clock: CLK,
        crypto: CRYPTO,
        datastore: DS,
    ) -> Self {
        Self {
            pl: PhysicalLayer::new(i2c, delay, vdd_pin, rst_pin),
            dl: DataLinkLayer::new(),
            tl: TransportLayer::new(),
            prl: PresentationLayer::new(crypto, datastore),
            clock,
        }
    }

    /// Initializes and negotiates the stack: performs reset and negotiates frame size and bus speed.
    pub fn open(
        &mut self,
        reset_type: ResetType,
        frame_size: u16,
        freq_khz: u16,
    ) -> Result<(), IfxI2cError> {
        self.pl.reset(reset_type)?;
        self.pl.negotiate(frame_size, freq_khz)?;
        self.dl.reset();
        self.prl.reset();
        Ok(())
    }

    /// Executes a stack reset (Cold, Warm, or Soft) and clears protocol state.
    pub fn reset(&mut self, reset_type: ResetType) -> Result<(), IfxI2cError> {
        self.pl.reset(reset_type)?;
        self.dl.reset();
        self.prl.reset();
        Ok(())
    }

    /// Transceives an APDU command payload over the stack using the specified protection level.
    pub fn transceive(
        &mut self,
        tx: &[u8],
        rx: &mut [u8],
        protection: ProtectionConfig,
    ) -> Result<usize, IfxI2cError> {
        self.prl.transceive(
            &mut self.pl,
            &mut self.dl,
            &mut self.tl,
            &self.clock,
            tx,
            rx,
            protection,
        )
    }

    /// Saves session context and closes the active connection.
    pub fn close(&mut self, save_context: bool) -> Result<(), IfxI2cError> {
        if save_context {
            self.prl
                .save_context(&mut self.pl, &mut self.dl, &mut self.tl, &self.clock)?;
        } else {
            self.prl.reset();
        }
        Ok(())
    }

    /// Restores a previously saved session context across hibernate cycles.
    pub fn restore_context(&mut self) -> Result<(), IfxI2cError> {
        self.prl
            .restore_context(&mut self.pl, &mut self.dl, &mut self.tl, &self.clock)
    }

    /// Configures a new 7-bit I2C slave address.
    pub fn set_slave_address(&mut self, addr: u8, persistent: bool) -> Result<(), IfxI2cError> {
        self.pl.write_slave_address(addr, persistent)
    }
}
