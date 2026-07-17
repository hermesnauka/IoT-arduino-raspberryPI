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
| **Spoofing** | A rogue device on the bus impersonating a legitimate node ID. | Per-node sequence tracking; (stretch) HMAC over the frame with a per-node key. |
| **Tampering** | Bit flips or injected bytes corrupting frames in transit. | Magic-byte framing + CRC-16 over the payload; resynchronization scan on framing errors. |
| **Information Disclosure** | Serial sniffing of telemetry. | Telemetry is low-sensitivity; document the boundary. (Stretch: encrypt gateway→cloud leg with TLS/MQTTs.) |
| **Denial of Service** | A stuck node streaming garbage at full baud rate. | Per-node rate limiting (SR-3) and quarantine (SR-4); bounded read loop budget per tick. |
| **Elevation of Privilege** | Malformed frame exploiting a gateway parsing bug (buffer overflow). | Fixed-size frame, explicit bounds checks, `-Werror -fanalyzer` SAST gate, fuzz test of the decoder. |

### 2.2 Wire Protocol (shared contract)
Fixed 16-byte frame, little-endian, no padding — mirrored byte-for-byte between the Arduino firmware and the gateway decoder (same discipline as a game-server input packet):

| Offset | Field | Type | Notes |
| :--- | :--- | :--- | :--- |
| 0 | magic | `uint16` | `0xA55A` frame delimiter |
| 2 | nodeId | `uint8` | 1–255 |
| 3 | flags | `uint8` | bit0: sensor fault self-report |
| 4 | sequence | `uint32` | monotonic per node, wraps |
| 8 | temperatureCx100 | `int16` | °C × 100 (fixed-point, no floats on wire) |
| 10 | humidityPctX100 | `uint16` | %RH × 100 |
| 12 | reserved | `uint16` | must be 0 |
| 14 | crc16 | `uint16` | CRC-16/CCITT over bytes 0–13 |

`static_assert(sizeof(SensorFrame) == 16)` on both sides is the tripwire.

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
│   │   ├── main.cpp                 # --selftest | --read <tty|file|-> [--verbose]
│   │   ├── Protocol.h               # wire struct + CRC (mirror of the sketch's copy)
│   │   ├── FrameDecoder.cpp/.h      # framing, CRC, validation gates (SR-1)
│   │   └── NodeRegistry.cpp/.h      # sequence/rate/quarantine + aggregates (SR-2/3/4, FR-3)
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
*   **Offline self-test:** `gateway --selftest` asserts: valid frame accepted; bad CRC dropped; out-of-range temperature dropped; replayed sequence ignored; reserved-nonzero dropped; quarantine engages after N consecutive errors and other nodes stay live.
*   **Protocol conformance (Python simulator):** feeds the gateway valid frames, bit-flipped frames, truncated frames, interleaved multi-node streams, and a full-baud garbage flood; asserts counters and outputs.
*   **Fuzzing:** decoder entry point fuzzed with random byte streams (simple Python random fuzz first; AFL++ as stretch) — the decoder must never crash or over-read.

---

## Phase 5: Deployment & Maintenance (Operations)

*   **Gateway packaging:** systemd unit on Raspberry Pi OS; watchdog restart; journald logging with per-node counters dumped on SIGUSR1.
*   **Firmware updates:** versioned sketch; node reports firmware version in `flags`-extension frame (stretch).
*   **Monitoring:** per-node error counters exported (stretch: Prometheus text endpoint) — CRC-error spikes are the tamper/EMI signal to alert on.
