# Secure SDLC Project Plan: IoT Sensor Pipeline (Arduino & Raspberry Pi, C++)

## Architecture Note
**Technical Alignment:** The system is a two-tier telemetry pipeline. An **Arduino sensor node (C++)** samples environmental data (temperature/humidity) and emits framed binary readings over a serial/UART link. A **Raspberry Pi gateway (C++17, CMake)** validates, aggregates, and republishes the readings (MQTT and/or local API). The gateway is the trust boundary: everything arriving from the wire is treated as untrusted input, exactly like network packets in a game server.

---

## Phase 1: Planning & Requirements (Inception)

### 1.1 Product Requirements Document (PRD)

#### Functional Requirements (FR)
*   **FR-1 (Sensor Sampling):** The Arduino node samples temperature and humidity every 5 seconds and transmits each reading as a fixed-size binary frame over serial (115200 baud).
*   **FR-2 (Frame Validation & Decoding):** The Pi gateway decodes incoming frames, verifies integrity (magic bytes + CRC), and rejects malformed or corrupted frames without crashing.
*   **FR-3 (Aggregation & Publishing):** The gateway keeps a rolling window of validated readings per node and publishes aggregates (min/max/avg) at a configurable interval.
*   **FR-4 (Multi-Node Support):** Frames carry a node ID; the gateway tracks at least 8 independent sensor nodes on one bus.

#### Non-Functional & Security Requirements (SR)
*   **SR-1 (Untrusted Wire):** The gateway must treat the serial link as hostile: strict frame-size checks, CRC verification, and range validation of decoded values (e.g., temperature in [-40, +85] °C) before any value enters application state.
*   **SR-2 (Replay & Ordering):** Frames carry a monotonically increasing sequence number per node; the gateway drops stale or replayed sequence numbers.
*   **SR-3 (Rate Limiting):** The gateway throttles per-node frame rates (a stuck or malicious node cannot starve the loop or flood downstream consumers).
*   **SR-4 (Fail-Safe Degradation):** Sensor faults (NaN, out-of-range, CRC storms) are quarantined per node; other nodes continue to be served.
*   **SR-5 (No Dynamic Allocation on Node):** The Arduino firmware uses only static buffers — no heap fragmentation on a device that runs for months.
*   **SR-6 (Frame Authenticity — stretch):** Every frame carries a SipHash-2-4 tag keyed with a 128-bit per-node pre-shared key; the gateway drops frames whose tag does not verify (constant-time compare) and counts them toward quarantine. A rogue device without the key cannot impersonate a node ID even with a valid CRC.

---

### 1.2 User Stories

#### **User Story 1: Trustworthy Readings**
*   **As an** operator,
*   **I want** the gateway to reject corrupted or implausible sensor frames,
*   **So that** downstream dashboards never display garbage data.
*   **Acceptance Criteria:**
    *   A frame with an invalid CRC is dropped and counted in a per-node error counter.
    *   A frame with out-of-range values (e.g., 300 °C) is dropped and logged as a security alert.
    *   A replayed sequence number is ignored (idempotent).

#### **User Story 2: Node Health Visibility**
*   **As an** operator,
*   **I want to** see per-node statistics (last reading, error counts, last-seen time),
*   **So that** I can detect a failing or tampered sensor before it corrupts aggregates.
*   **Acceptance Criteria:**
    *   The gateway exposes per-node counters: valid frames, CRC errors, range violations, replays.
    *   A node exceeding an error threshold within a window is quarantined and a single alert is emitted (no log storms).

---

## Phase 2: Architecture & Design (Secure Design)

### 2.1 Threat Modeling (STRIDE Matrix)

| Threat Category | Project Threat | Mitigation Strategy |
| :--- | :--- | :--- |
| **Spoofing** | A rogue device on the bus impersonating a legitimate node ID. | Per-node sequence tracking; (stretch, SR-6) per-node keyed SipHash-2-4 tag over the frame — see §2.3. |
| **Tampering** | Bit flips or injected bytes corrupting frames in transit. | Magic-byte framing + CRC-16 over the payload; resynchronization scan on framing errors. |
| **Information Disclosure** | Serial sniffing of telemetry. | Telemetry is low-sensitivity; document the boundary. (Stretch: encrypt gateway→cloud leg with TLS/MQTTs.) |
| **Denial of Service** | A stuck node streaming garbage at full baud rate. | Per-node rate limiting (SR-3) and quarantine (SR-4); bounded read loop budget per tick. |
| **Elevation of Privilege** | Malformed frame exploiting a gateway parsing bug (buffer overflow). | Fixed-size frame, explicit bounds checks, `-Werror -fanalyzer` SAST gate, fuzz test of the decoder. |

### 2.2 Wire Protocol (shared contract)
Fixed 24-byte frame, little-endian, no padding — mirrored byte-for-byte between the Arduino firmware and the gateway decoder (same discipline as a game-server input packet):

| Offset | Field | Type | Notes |
| :--- | :--- | :--- | :--- |
| 0 | magic | `uint16` | `0xA55A` frame delimiter |
| 2 | nodeId | `uint8` | 1–255 |
| 3 | flags | `uint8` | bit0: sensor fault self-report; bit1: firmware-version report (see below) |
| 4 | sequence | `uint32` | monotonic per node, wraps |
| 8 | temperatureCx100 | `int16` | °C × 100 (fixed-point, no floats on wire) |
| 10 | humidityPctX100 | `uint16` | %RH × 100 |
| 12 | reserved | `uint16` | must be 0 |
| 14 | crc16 | `uint16` | CRC-16/CCITT over bytes 0–13 |
| 16 | authTag | `uint64` | SipHash-2-4 over bytes 0–13, per-node 128-bit key (§2.3, SR-6) |

`static_assert(sizeof(SensorFrame) == 24)` on both sides is the tripwire.
Validation order at the gateway: size → CRC (cheap, catches EMI/bit rot) →
authTag (authenticity) → ranges → sequence. The sequence number sits inside
the MAC coverage, so replay protection and authenticity are bound together.

### 2.3 Frame Authentication & Key Management (SR-6, stretch)

*   **Algorithm:** SipHash-2-4 (Aumasson–Bernstein), 128-bit key, 64-bit tag —
    designed as a fast keyed PRF for short inputs on constrained hardware; a
    few hundred bytes of code and microseconds per frame on the ATmega328P,
    versus kilobytes of flash for HMAC-SHA256 with no security gain at this
    threat level (online-only forgery on a rate-limited, quarantining link).
*   **Coverage:** bytes 0–13 (same span as the CRC): magic, nodeId, flags,
    sequence, payload, reserved. The CRC itself is derived from the same bytes
    so including it would add nothing.
*   **Optional, switchable:** auth is off by default and the frame is always
    24 bytes (the tag field is always present, so the decoder never guesses
    the frame size).
    *   *Gateway:* auth is enforced iff `--keys <path>` is given — no key
        file means the tag is ignored (legacy/dev mode); with a key file
        every frame must verify.
    *   *Node:* compile-time `SENSOR_NODE_AUTH` switch (0/1) in the sketch;
        when off, the node transmits `authTag = 0`.
*   **Keys:** one 128-bit pre-shared key per node.
    *   *Gateway:* loaded at startup from the key file (one
        `nodeId:32-hex-chars` per line, recommend mode 0600); never compiled
        in. With auth on, a frame from a node with no key entry is dropped
        and counted.
    *   *Node:* key resides in the sketch as a `PROGMEM` constant — an
        accepted dev-grade limitation, documented here; production would move
        it to EEPROM or a secure element. Key never leaves the node.
    *   *Selftest/simulator:* fixed test keys baked into `--selftest` and
        `frame_simulator.py` (test-only, clearly labeled).
*   **Verification is constant-time:** tag comparison uses a branch-free
    accumulate-XOR loop, not `memcmp`, to avoid a timing oracle.
*   **Failure handling:** bad/missing tag → drop, increment per-node
    `authErrors`, counts toward quarantine (SR-4) and is exported to
    Prometheus. An auth-error spike is the spoofing signal to alert on.
*   **Known-answer tripwire:** SipHash-2-4 reference test vectors (from the
    reference implementation's `vectors_sip64`) asserted in `--selftest` on
    the C++ side and in `frame_simulator.py` on the Python side, mirroring the
    CRC `0x29B1` tripwire.

**Flags-extension frame (Phase 5, stretch — firmware version reporting):** when
flags bit1 (`kFlagVersionReport`) is set, `temperatureCx100` and
`humidityPctX100` do not carry a sensor reading — they pack a firmware
version instead, so no wire-size change is needed. `temperatureCx100`
(reinterpreted as `uint16`): high byte = major, low byte = minor.
`humidityPctX100` (reinterpreted as `uint16`): low byte = patch, high byte
reserved (0). The decoder's SR-1 range gate is skipped for these frames; the
gateway tracks the version per node without counting it toward `valid` sensor
readings. The node announces its version once at startup and re-announces
periodically so a gateway that (re)starts later still learns it.

---

## Phase 3: Implementation (Secure Coding)

### 3.1 Directory Structure
```text
app01_cpp/
├── node-arduino/
│   └── sensor_node/
│       └── sensor_node.ino          # C++ sketch: sample, frame, CRC, transmit
├── gateway-rpi/
│   ├── src/
│   │   ├── main.cpp                 # --selftest | --read <tty|file|-> [--verbose]; SIGUSR1 dumps counters
│   │   ├── Protocol.h               # wire struct + CRC (mirror of the sketch's copy)
│   │   ├── FrameDecoder.cpp/.h      # framing, CRC, validation gates (SR-1)
│   │   └── NodeRegistry.cpp/.h      # sequence/rate/quarantine + aggregates (SR-2/3/4, FR-3)
│   │   └── SipHash.h                # header-only SipHash-2-4 (SR-6), shared style with crc16Ccitt
│   ├── systemd/
│   │   └── iot-gateway.service      # Phase 5 packaging: Restart=on-failure, journald, SIGUSR1 dump
│   ├── fuzz/
│   │   ├── fuzz_decoder.cpp         # AFL++ harness (Phase 4, stretch), opt-in BUILD_FUZZER target
│   │   └── seeds/                   # seed corpus: valid, bad-CRC, multi-frame, garbage-prefixed
│   └── CMakeLists.txt               # -Wall -Wextra -Wpedantic -Werror -fanalyzer
├── tools/
│   └── frame_simulator.py           # executable protocol spec + conformance scenarios
└── SSDLC_IoT_Sensor_Pipeline_Plan.md
```

### 3.2 Secure Foundation Principles (code level)
*   **Decoder as pure function:** `FrameDecoder` consumes a byte stream and yields validated `SensorReading`s — no I/O inside, so it is unit-testable and fuzzable offline.
*   **Validation order:** magic → length → CRC → reserved-zero → range → sequence. Cheapest checks first; nothing touches `NodeRegistry` until all gates pass.
*   **Resync on garbage:** on framing failure, slide one byte and rescan for magic — a hostile byte stream may embed fake magics, so CRC remains the authority.
*   **Testability without hardware:** the gateway reads from any file descriptor — a recorded byte file or a PTY fed by a Python simulator stands in for the Arduino during CI. The Python frame simulator plays the same role as the UDP test clients in the shooter project: an executable specification of the protocol.

---

## Phase 4: Verification & Testing (Security Assessment)

*   **SAST:** GCC `-fanalyzer` + `-Wall -Wextra -Wpedantic -Werror` baked into CMake (build fails on any finding). `arduino-cli compile` (or PlatformIO check) for the sketch if available.
*   **Offline self-test:** `gateway --selftest` asserts: valid frame accepted; bad CRC dropped; out-of-range temperature dropped; replayed sequence ignored; reserved-nonzero dropped; quarantine engages after N consecutive errors and other nodes stay live; (SR-6) SipHash known-answer vectors pass, valid tag accepted, forged tag dropped, tampered-frame-with-recomputed-CRC dropped by tag, unknown-node frame dropped, and with auth off a zero-tag frame is accepted.
*   **Protocol conformance (Python simulator):** feeds the gateway valid frames, bit-flipped frames, truncated frames, interleaved multi-node streams, and a full-baud garbage flood; asserts counters and outputs.
*   **Fuzzing:** decoder entry point fuzzed with random byte streams. Simple Python random fuzz (`frame_simulator.py`'s garbage-flood scenario) plus a deterministic in-process fuzz in `--selftest`. Stretch: coverage-guided AFL++ via `gateway-rpi/fuzz/fuzz_decoder.cpp`, an opt-in `BUILD_FUZZER` CMake target (off by default, so it never affects the required verify workflow) — the decoder must never crash or over-read.

---

## Phase 5: Deployment & Maintenance (Operations)

*   **Gateway packaging:** systemd unit (`gateway-rpi/systemd/iot-gateway.service`) on Raspberry Pi OS; `Restart=on-failure` as the watchdog-restart mechanism; journald logging (systemd default) with per-node counters dumped via `systemctl kill -s SIGUSR1`.
*   **Firmware updates:** versioned sketch; node reports firmware version in a `flags`-extension frame (§2.2) once at startup and periodically thereafter.
*   **Monitoring:** per-node counters (valid/CRC/auth/reserved/range/replay/rate-limited/quarantine/firmware-reports) exported as Prometheus text via `gateway --read <path> --metrics <file>` (`NodeRegistry::writePrometheusText`), written atomically for the node_exporter textfile collector — CRC-error spikes are the tamper/EMI signal to alert on.
