// SipHash-2-4 keyed PRF (SR-6 frame authentication, plan §2.3).
// Header-only, shared style with crc16Ccitt in Protocol.h. Mirrored in
// node-arduino/sensor_node/sensor_node.ino and tools/frame_simulator.py —
// update all three together.
// Known-answer tripwire (checked in --selftest and the simulator):
// key 00 01 … 0f, empty input → 0x726fdb47dd0e0e31.
#pragma once

#include <cstddef>
#include <cstdint>

namespace iot {

inline uint64_t sipHash24(const uint8_t key[16], const uint8_t* data, std::size_t len) {
  auto rotl = [](uint64_t x, int b) { return (x << b) | (x >> (64 - b)); };
  auto readLe64 = [](const uint8_t* p) {
    uint64_t v = 0;
    for (int i = 7; i >= 0; --i) v = (v << 8) | p[i];
    return v;
  };
  uint64_t v0 = 0x736f6d6570736575ULL ^ readLe64(key);
  uint64_t v1 = 0x646f72616e646f6dULL ^ readLe64(key + 8);
  uint64_t v2 = 0x6c7967656e657261ULL ^ readLe64(key);
  uint64_t v3 = 0x7465646279746573ULL ^ readLe64(key + 8);
  auto sipRound = [&]() {
    v0 += v1; v1 = rotl(v1, 13); v1 ^= v0; v0 = rotl(v0, 32);
    v2 += v3; v3 = rotl(v3, 16); v3 ^= v2;
    v0 += v3; v3 = rotl(v3, 21); v3 ^= v0;
    v2 += v1; v1 = rotl(v1, 17); v1 ^= v2; v2 = rotl(v2, 32);
  };
  const std::size_t full = len & ~static_cast<std::size_t>(7);
  for (std::size_t off = 0; off < full; off += 8) {
    uint64_t m = readLe64(data + off);
    v3 ^= m;
    sipRound(); sipRound();
    v0 ^= m;
  }
  // Final block: remaining bytes little-endian, top byte = len mod 256.
  uint64_t last = static_cast<uint64_t>(len & 0xff) << 56;
  for (std::size_t i = 0; i < (len & 7); ++i) {
    last |= static_cast<uint64_t>(data[full + i]) << (8 * i);
  }
  v3 ^= last;
  sipRound(); sipRound();
  v0 ^= last;
  v2 ^= 0xff;
  sipRound(); sipRound(); sipRound(); sipRound();
  return v0 ^ v1 ^ v2 ^ v3;
}

}  // namespace iot
