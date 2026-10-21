# 05 — Command (`cmd`) & Service Layers (`util`, `crypt`) Specification

**Primary C References:**
- [`optiga-trust-m/src/cmd/optiga_cmd.c`](file:///Users/chris/Development/optiga/optiga-trust-m/src/cmd/optiga_cmd.c)
- [`optiga-trust-m/include/cmd/optiga_cmd.h`](file:///Users/chris/Development/optiga/optiga-trust-m/include/cmd/optiga_cmd.h)
- [`optiga-trust-m/src/util/optiga_util.c`](file:///Users/chris/Development/optiga/optiga-trust-m/src/util/optiga_util.c)
- [`optiga-trust-m/src/crypt/optiga_crypt.c`](file:///Users/chris/Development/optiga/optiga-trust-m/src/crypt/optiga_crypt.c)

---

## 1. APDU Framing & Automatic Device Error Retrieval

All OPTIGA Trust M commands use a 4-byte Big-Endian APDU header (`OPTIGA_CMD_APDU_HEADER_SIZE = 4`):

### 1.1 Command APDU Layout
```text
+--------------------+--------------------+---------------------------------------+------------------------+
| Cmd (1B, | 0x80)   | Param (1B)         | InLength (2B u16 BE)                  | InData (0..1553 bytes) |
+--------------------+--------------------+---------------------------------------+------------------------+
```
- **Bit 7 (`0x80` = `OPTIGA_CMD_CLEAR_LAST_ERROR`)**: Set on all standard commands so the chip clears its error register (`0xF1C2`) prior to execution.
  - Exception: When `optiga_cmd` automatically issues `GetDataObject` to read `0xF1C2` after a command failure, Bit 7 is **not** set (`cmd = 0x01`, `OPTIGA_CMD_GET_DATA_OBJECT_NO_ERROR_CLEAR`).

### 1.2 Response APDU Layout & Auto-`0xF1C2` Error Fetch
```text
+--------------------+---------------------------------------+-------------------------+
| Sta (1B)           | OutLength (2B u16 BE)                 | OutData (0..1553 bytes) |
+--------------------+---------------------------------------+-------------------------+
```
- **Success (`Sta == 0x00` / `OPTIGA_CMD_APDU_SUCCESS`)**:
  - Verify `rx_len == 4 + u16::from_be_bytes([rx[2], rx[3]])` (note: byte `rx[1]` is unused/0 in response header; `OutLength` is at `rx[2..=3]`).
  - Parse `OutData` (`&rx[4..rx_len]`).
- **Device Failure (`Sta == 0xFF` / `OPTIGA_CMD_APDU_FAILURE`)**:
  - The Command Layer automatically constructs and executes an internal `GetDataObject` APDU for OID `0xF1C2` (`OPTIGA_CMD_LAST_ERROR_CODE`):
    - Request APDU: `[0x01, 0x00, 0x00, 0x06, 0xF1, 0xC2, 0x00, 0x00, 0x00, 0x01]` (Read Data, OID `0xF1C2`, Offset `0x0000`, Length `0x0001`), sent with `ProtectionLevel::None`.
    - Reads the 1-byte error code `err_byte` from `OutData[0]` and returns `Err(OptigaError::Device(DeviceError::from(err_byte)))`.

---

## 2. Command Opcode Catalog (`src/cmd/mod.rs`)

| Command Name | Base Opcode | With Clear Error (`\| 0x80`) | `Param` Values | Description |
| :--- | :---: | :---: | :--- | :--- |
| `OpenApplication` | `0x70` | `0xF0` | `0x00` = Clean init, `0x01` = Restore from hibernate | Initializes OPTIGA application (`g_optiga_unique_application_identifier` = `D27600000447656E417574684170706C`, 16B). |
| `CloseApplication` | `0x71` | `0xF1` | `0x00` = Clean close, `0x01` = Hibernate (returns 8B context handle) | Closes application and optionally saves 8B context handle to `DatastoreId::HibernateContext` (`0x33`). |
| `GetDataObject` | `0x01` | `0x81` (`0x01` for `0xF1C2`) | `0x00` = Read Data, `0x01` = Read Metadata | InData: `OID(2B) \|\| Offset(2B) \|\| Length(2B)`. Chained automatically if `bytes_to_read > OPTIGA_MAX_COMMS_BUFFER_SIZE`. |
| `SetDataObject` | `0x02` | `0x82` | `0x00` = Write data, `0x01` = Write metadata, `0x40` = Erase & Write, `0x02` = Count | InData: `OID(2B) \|\| Offset(2B) \|\| Data` (or `1B count`). |
| `SetObjectProtected` | `0x03` | `0x83` | `manifest_version` (`0x01`) for Start, `0x00` for Continue/Final | InData: `Tag(1B: 0x00=Start, 0x02=Continue, 0x01=Final) \|\| Len(2B) \|\| Fragment`. |
| `GetRandom` | `0x0C` | `0x8C` | `0x00` = TRNG, `0x01` = DRNG, `0x04` = Pre-master secret | InData: `Len(2B)` (`0x0008..=0x0100`), optional `0x41` TLV. |
| `EncryptSym` | `0x14` | `0x94` | `mode` (`0x08` ECB, `0x09` CBC, `0x0A` CBC-MAC, `0x0B` CMAC, `0x20..0x22` HMAC) | Symmetric encryption / MAC generation with Start/Continue/Final sequence. |
| `DecryptSym` | `0x15` | `0x95` | `mode` | Symmetric decryption / HMAC verification / Clear Auto State. |
| `EncryptAsym` | `0x1E` | `0x9E` | `0x11` (`OPTIGA_RSAES_PKCS1_V15`) | RSA PKCS#1 v1.5 encryption (message or session OID). |
| `DecryptAsym` | `0x1F` | `0x9F` | `0x11` (`OPTIGA_RSAES_PKCS1_V15`) | RSA PKCS#1 v1.5 decryption (export or store in session OID). |
| `CalcHash` | `0x30` | `0xB0` | `0xE2` (`SHA-256`) | Hash Start (`0x00`), Start+Final (`0x01`), Continue (`0x02`), Final (`0x03`), OID Hash (`0x10..0x13`). Context size = 209B. |
| `CalcSign` | `0x31` | `0xB1` | `0x11` (ECDSA FIPS 186-3), `0x01..0x03` (RSA PKCS#1 v1.5 SHA256/384/512) | TLV `0x01` (Digest) + TLV `0x03` (Private Key OID `2B`). Note: ECDSA response `R` and `S` DER integers are checked via `ecc_r_s_padding_check`. |
| `VerifySign` | `0x32` | `0xB2` | Signature scheme (`0x11` ECDSA, `0x01..0x03` RSA) | TLV `0x01` (Digest) + TLV `0x02` (Signature) + either TLV `0x04` (Cert OID) or TLV `0x05` (Algo/Curve ID) + TLV `0x06` (Public Key). |
| `CalcSSec` | `0x33` | `0xB3` | `0x01` (ECDH) | TLV `0x01` (PrivKey OID) + TLV `0x05` (Curve ID) + TLV `0x06` (Peer PubKey) + TLV `0x07` (Export) or TLV `0x08` (Session OID). |
| `DeriveKey` | `0x34` | `0xB4` | `0x01..0x03` (TLS PRF SHA256/384/512), `0x08..0x0A` (HKDF SHA256/384/512) | TLV `0x01` (Secret OID) + TLV `0x02` (Seed/Salt) + TLV `0x03` (Key Len) + optional TLV `0x04` (Info) + TLV `0x07`/`0x08` (Export/Store). |
| `GenKeyPair` | `0x38` | `0xB8` | Curve ID (`0x03..0x05`, `0x13..0x16`) or RSA (`0x41`, `0x42`) | TLV `0x01` (PrivKey OID) + TLV `0x02` (Key Usage) + optional TLV `0x07` (Export PrivKey). Returns TLV `0x02` (PubKey) and optional TLV `0x01` (PrivKey). |
| `GenSymKey` | `0x39` | `0xB9` | AES type (`0x81` = 128, `0x82` = 192, `0x83` = 256) | TLV `0x01` (Key OID `0xE200`) + TLV `0x02` (Key Usage) + optional TLV `0x07` (Export). |

---

## 3. TLV Encoding & Type-Safe Session Management

### 3.1 3-Byte TLV Helper (`src/cmd/tlv.rs`)
OPTIGA APDUs encode command parameters using 3-byte Tag-Length-Value headers (`Tag: u8`, `Length: u16 BE`, `Value: [u8; Length]`):
```rust
pub struct TlvWriter<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> TlvWriter<'a> {
    pub fn write_tlv(&mut self, tag: u8, value: &[u8]) -> Result<(), OptigaError> {
        let len = u16::try_from(value.len()).map_err(|_| OptigaError::MemoryInsufficient)?;
        if self.pos + 3 + value.len() > self.buf.len() {
            return Err(OptigaError::MemoryInsufficient);
        }
        self.buf[self.pos] = tag;
        self.buf[self.pos + 1..self.pos + 3].copy_from_slice(&len.to_be_bytes());
        self.buf[self.pos + 3..self.pos + 3 + value.len()].copy_from_slice(value);
        self.pos += 3 + value.len();
        Ok(())
    }
}
```

### 3.2 RAII Session Context Management (`0xE100..=0xE103`)
The OPTIGA chip has 4 volatile session contexts (`0xE100`, `0xE101`, `0xE102`, `0xE103`).
In C, session allocation is tracked via a global array `uint8_t sessions[4]` in `g_optiga`, and passing `OPTIGA_KEY_ID_SESSION_BASED` (`0x0000`) implicitly looks up `me->session_oid`.
In Rust, we provide a type-safe **`SessionSlot`** handle allocated from the driver's 4-bit session bitmap (`u8`), ensuring:
- A session slot (`0xE100..=0xE103`) is explicitly acquired when generating a session keypair or storing an ECDH shared secret/derived key in a session.
- Calling `ecdsa_sign` or `derive_key` with a session-based key requires passing `&SessionSlot`, turning C's runtime `OPTIGA_CMD_ERROR_INVALID_INPUT` session errors into compile-time type safety!
