# OPTIGA™ Trust M — Rust `#![no_std]` Architecture & Agent Blueprint

Welcome to the specification and implementation reference for the Rust-first, `#![no_std]` port of the Infineon OPTIGA™ Trust M host library and its `ifx_i2c` (Infineon I2C Protocol v2.03) communication stack.

This directory serves as the **authoritative engineering blueprint** for autonomous coding agents and developers implementing, testing, and verifying individual layers of the stack.

---

## 📚 Document Index

| Document | Scope & Purpose | Primary C Reference Files |
| :--- | :--- | :--- |
| [**`00_MASTER_ARCHITECTURE.md`**](file:///Users/chris/Development/optiga/docs/architecture/00_MASTER_ARCHITECTURE.md) | Workspace structure, `#![no_std]` coding rules, zero-cost error hierarchy (`OptigaError`, `IfxI2cError`, `DeviceError`), PAL traits (`OptigaI2cBus`, `HostCrypto`, `Datastore`, `MonotonicClock`), and eliminating C anti-patterns. | [`ifx_i2c_config.h`](file:///Users/chris/Development/optiga/optiga-trust-m/include/ifx_i2c/ifx_i2c_config.h), [`optiga_lib_return_codes.h`](file:///Users/chris/Development/optiga/optiga-trust-m/include/common/optiga_lib_return_codes.h), [`include/pal/`](file:///Users/chris/Development/optiga/optiga-trust-m/include/pal) |
| [**`01_PHYSICAL_LAYER_PL.md`**](file:///Users/chris/Development/optiga/docs/architecture/01_PHYSICAL_LAYER_PL.md) | Layer 1 (`ifx_i2c::physical`): Virtual register map (`0x80`–`0x89`), $50\ \mu\text{s}$ guard time invariant, NACK wakeup polling ($200 \times 1\text{ ms}$), Cold/Warm/Soft reset timings, and frequency/frame-size negotiation state machines. | [`ifx_i2c_physical_layer.c`](file:///Users/chris/Development/optiga/optiga-trust-m/src/comms/ifx_i2c/ifx_i2c_physical_layer.c), [`ifx_i2c.c`](file:///Users/chris/Development/optiga/optiga-trust-m/src/comms/ifx_i2c/ifx_i2c.c) |
| [**`02_DATA_LINK_LAYER_DL.md`**](file:///Users/chris/Development/optiga/docs/architecture/02_DATA_LINK_LAYER_DL.md) | Layer 2 (`ifx_i2c::datalink`): 5-byte frame layout, `FCTR` bitfields (`FTYPE`, `SEQCTR`, `FRNR`, `ACKNR`), reflected CRC-16/CCITT (`0x1021`), 2-bit modulo-4 sequence tracking, ACK/NACK/RESYNC ARQ state machine. | [`ifx_i2c_data_link_layer.c`](file:///Users/chris/Development/optiga/optiga-trust-m/src/comms/ifx_i2c/ifx_i2c_data_link_layer.c), [`ifx_i2c_data_link_layer.h`](file:///Users/chris/Development/optiga/optiga-trust-m/include/ifx_i2c/ifx_i2c_data_link_layer.h) |
| [**`03_TRANSPORT_LAYER_TL.md`**](file:///Users/chris/Development/optiga/docs/architecture/03_TRANSPORT_LAYER_TL.md) | Layer 3 (`ifx_i2c::transport`): `PCTR` chaining header (`NO`, `FIRST`, `INTERMEDIATE`, `LAST`, `ERROR`) + Presentation Layer presence bit (`0x08`), transition matrix validation, fragmentation, and reassembly. | [`ifx_i2c_transport_layer.c`](file:///Users/chris/Development/optiga/optiga-trust-m/src/comms/ifx_i2c/ifx_i2c_transport_layer.c), [`ifx_i2c_transport_layer.h`](file:///Users/chris/Development/optiga/optiga-trust-m/include/ifx_i2c/ifx_i2c_transport_layer.c) |
| [**`04_PRESENTATION_LAYER_PRL.md`**](file:///Users/chris/Development/optiga/docs/architecture/04_PRESENTATION_LAYER_PRL.md) | Layer 4 (`ifx_i2c::presentation`): OPTIGA Shielded Connection (`SCTR`), `MasterHello`/`SlaveHello`/`MasterFinished`/`SlaveFinished` handshake, `TLS-1.2 PRF SHA-256` key schedule, `AES-128-CCM-8` record encryption, sequence rollover (`0xFFFFFFF0`), alerts (`0x40`/`0x44`), and context save/restore (`0x60`–`0x6C`). | [`ifx_i2c_presentation_layer.c`](file:///Users/chris/Development/optiga/optiga-trust-m/src/comms/ifx_i2c/ifx_i2c_presentation_layer.c), [`pal_crypt_psa.c`](file:///Users/chris/Development/optiga/optiga-trust-m/extras/pal/pal_crypt_psa.c) |
| [**`05_COMMAND_AND_SERVICES.md`**](file:///Users/chris/Development/optiga/docs/architecture/05_COMMAND_AND_SERVICES.md) | Layer 5 (`cmd`, `util`, `crypt`): APDU command/response framing, TLV encoding, automatic `0xF1C2` device error code retrieval on `Sta == 0xFF`, RAII session OID management (`0xE100`–`0xE103`), and high-level `Util` & `Crypt` APIs. | [`optiga_cmd.c`](file:///Users/chris/Development/optiga/optiga-trust-m/src/cmd/optiga_cmd.c), [`optiga_util.c`](file:///Users/chris/Development/optiga/optiga-trust-m/src/util/optiga_util.c), [`optiga_crypt.c`](file:///Users/chris/Development/optiga/optiga-trust-m/src/crypt/optiga_crypt.c) |
| [**`06_TESTING_AND_SIMULATION.md`**](file:///Users/chris/Development/optiga/docs/architecture/06_TESTING_AND_SIMULATION.md) | Host-first verification (`optiga-sim`): Stateful `VirtualOptiga` I2C slave emulator, `FaultInjectingI2cBus` (NACKs, CRC bitflips, dropped frames, MAC tampering), property tests, and C-to-Rust FFI differential harness. | [`tests/`](file:///Users/chris/Development/optiga/optiga-trust-m/tests), [`extras/pal/test_pal/`](file:///Users/chris/Development/optiga/optiga-trust-m/extras/pal/test_pal) |
| [**`07_PHASED_TASK_BREAKDOWN.md`**](file:///Users/chris/Development/optiga/docs/architecture/07_PHASED_TASK_BREAKDOWN.md) | Actionable work packages, dependency graph, module contracts, and acceptance criteria for delegating implementation tasks across agents. | All |

---

## 🛠️ Core Mandates for All Implementing Agents

1. **Strictly `#![no_std]` & Zero Heap Allocation in Core**:
   - `crates/optiga-trust-m` must compile with `#![no_std]` and `#![forbid(unsafe_code)]` (unless explicitly justified for FFI in tests).
   - Never use `alloc::vec::Vec` or `Box` in `optiga-trust-m`; use fixed-capacity stack buffers parameterized by const generics (e.g., `const FRAME_SIZE: usize = 277`) or caller-provided slices (`&[u8]`, `&mut [u8]`).
2. **No C-Style Callback Inversion or In-Place Offset Hacks**:
   - The C library requires callers to pad buffers by 13 bytes (`IFX_I2C_PRL_OVERHEAD_SIZE`) and offset payloads by 5 bytes (`IFX_I2C_DATA_OFFSET`). **Do not replicate this in Rust.** Keep protocol framing and encryption scratch buffers encapsulated inside the stack layers.
   - Replace void-pointer event callbacks with direct synchronous (`embedded-hal`) and/or `async` (`embedded-hal-async`) state machine methods returning `Result<T, E>`.
3. **Verify Everything Against `optiga-sim` on the Host**:
   - Every layer implementation must include unit tests and stateful simulation tests against `optiga-sim` covering both the happy path and adversarial fault injection (NACKs, CRC errors, sequence desync, buffer overflows, and MAC failures).
