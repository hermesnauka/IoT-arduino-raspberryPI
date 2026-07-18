// Framing + integrity + range + authenticity gates (SR-1, SR-6). Pure
// byte-stream consumer: no I/O, no clock — unit-testable and fuzzable offline
// (plan §3.2).
// Validation order: magic → length → CRC → reserved-zero → nodeId → auth → range.
// Auth is optional (plan §2.3): no KeyStore set means the tag is ignored.
// Sequence gating is per-node state and lives in NodeRegistry.
#pragma once

#include <cstddef>
#include <cstdint>

#include "Protocol.h"

namespace iot {

// Per-node pre-shared keys (SR-6). Loaded from the --keys file by main;
// the decoder only reads it. A node without an entry fails the auth gate.
struct KeyStore {
  bool present[256] = {};
  uint8_t keys[256][16] = {};
};

class FrameDecoder {
 public:
  enum class Status : uint8_t {
    Ok,           // frame passed every stateless gate
    BadCrc,       // magic found but CRC mismatch (or garbage mimicking magic)
    BadReserved,  // authentic frame with reserved != 0
    BadNodeId,    // authentic frame with nodeId == 0
    BadAuth,      // auth enforced and tag missing/forged/keyless node (SR-6)
    BadRange,     // authentic frame with implausible reading (SR-1)
  };

  struct Result {
    Status status;
    SensorFrame frame;  // claimed contents; trust only after status == Ok
  };

  struct Stats {
    uint64_t bytesIn = 0;
    uint64_t bytesDropped = 0;   // ring overflow (bounded memory, SR-3 adjacent)
    uint64_t resyncBytes = 0;    // bytes skipped hunting for magic
    uint64_t framesOk = 0;
    uint64_t crcErrors = 0;
    uint64_t reservedErrors = 0;
    uint64_t nodeIdErrors = 0;
    uint64_t authErrors = 0;
    uint64_t rangeErrors = 0;
  };

  // Enable SR-6 auth enforcement. nullptr (the default) = auth off: the
  // authTag field is ignored. The KeyStore must outlive the decoder.
  void setKeyStore(const KeyStore* keys) { keys_ = keys; }

  // Append raw serial bytes. Bounded: if the ring fills, oldest bytes are
  // dropped and counted (a flooding wire cannot grow memory).
  void push(const uint8_t* data, std::size_t len);

  // Extract the next frame attempt. Returns false when more bytes are needed.
  // On a CRC failure the scan advances one byte (a hostile stream may embed
  // fake magics — CRC is the authority; plan §3.2 resync rule).
  bool next(Result& out);

  const Stats& stats() const { return stats_; }

 private:
  static constexpr std::size_t kRingSize = 4096;

  std::size_t buffered() const { return count_; }
  uint8_t at(std::size_t i) const { return ring_[(head_ + i) % kRingSize]; }
  void drop(std::size_t n);

  uint8_t ring_[kRingSize] = {};
  std::size_t head_ = 0;   // index of oldest byte
  std::size_t count_ = 0;  // bytes currently buffered
  const KeyStore* keys_ = nullptr;  // non-owning; nullptr = auth off
  Stats stats_;
};

}  // namespace iot
