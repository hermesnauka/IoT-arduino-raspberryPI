// Wire protocol shared contract (SSDLC plan §2.2).
// Must stay byte-identical with node-arduino/sensor_node/sensor_node.ino —
// update both together.
#pragma once

#include <cstddef>
#include <cstdint>

namespace iot {

constexpr uint16_t kMagic = 0xA55A;
constexpr uint8_t kMagicByte0 = 0x5A;  // little-endian byte order on the wire
constexpr uint8_t kMagicByte1 = 0xA5;
constexpr uint8_t kFlagSensorFault = 0x01;
// Flags-extension frame (Plan Phase 5, stretch): when set, temperatureCx100
// and humidityPctX100 do not carry a sensor reading — they pack a firmware
// version instead. This keeps the frame byte-identical (still 16 bytes) while
// letting a node announce itself without a protocol version bump.
//   temperatureCx100 (reinterpreted as uint16): high byte = major, low byte = minor
//   humidityPctX100 (reinterpreted as uint16):   low byte = patch, high byte reserved (0)
constexpr uint8_t kFlagVersionReport = 0x02;
constexpr std::size_t kFrameSize = 24;
constexpr std::size_t kCrcCoverage = 14;   // bytes 0–13
constexpr std::size_t kAuthCoverage = 14;  // SipHash-2-4 tag covers the same span (SR-6, plan §2.3)

// Validation ranges (SR-1)
constexpr int16_t kTempMinCx100 = -4000;   // -40.00 °C
constexpr int16_t kTempMaxCx100 = 8500;    // +85.00 °C
constexpr uint16_t kHumMaxPctX100 = 10000; // 100.00 %RH

#pragma pack(push, 1)
struct SensorFrame {
  uint16_t magic;
  uint8_t nodeId;
  uint8_t flags;
  uint32_t sequence;
  int16_t temperatureCx100;   // °C × 100
  uint16_t humidityPctX100;   // %RH × 100
  uint16_t reserved;          // must be 0
  uint16_t crc16;             // CRC-16/CCITT-FALSE over bytes 0–13
  uint64_t authTag;           // SipHash-2-4 over bytes 0–13, per-node key (SR-6);
                              // 0 when the node transmits unauthenticated
};
#pragma pack(pop)

static_assert(sizeof(SensorFrame) == kFrameSize, "wire contract violated: frame must be 24 bytes");

// CRC-16/CCITT-FALSE: poly 0x1021, init 0xFFFF, no reflection, xorout 0.
// Known-answer: crc16Ccitt("123456789") == 0x29B1 (checked in --selftest).
inline uint16_t crc16Ccitt(const uint8_t* data, std::size_t len) {
  uint16_t crc = 0xFFFF;
  for (std::size_t i = 0; i < len; ++i) {
    crc = static_cast<uint16_t>(crc ^ (static_cast<uint16_t>(data[i]) << 8));
    for (int b = 0; b < 8; ++b) {
      crc = (crc & 0x8000u) ? static_cast<uint16_t>((crc << 1) ^ 0x1021)
                            : static_cast<uint16_t>(crc << 1);
    }
  }
  return crc;
}

}  // namespace iot
