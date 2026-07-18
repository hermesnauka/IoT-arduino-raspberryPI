// Per-node stateful gates and telemetry state (SR-2/3/4, FR-3/4).
// Sequence/replay gating, token-bucket rate limiting, error-streak quarantine,
// and a rolling window of validated readings for aggregation.
// Time is injected (milliseconds) so tests control the clock.
#pragma once

#include <cstdint>
#include <ostream>

#include "Protocol.h"

namespace iot {

class NodeRegistry {
 public:
  enum class Accept : uint8_t {
    Accepted,
    Replay,       // stale or duplicated sequence (SR-2)
    RateLimited,  // token bucket empty (SR-3)
    Quarantined,  // node is in the penalty box (SR-4)
  };

  // Kinds of decode-stage errors attributed to a (claimed) node id.
  enum class ErrorKind : uint8_t { Crc, Reserved, Range, Auth };

  // Tuning (plan Phase 4 self-test pins these).
  static constexpr uint32_t kBucketCapacity = 100;   // frames of burst
  static constexpr uint32_t kRefillPerSec = 20;      // sustained frames/sec
  static constexpr uint32_t kQuarantineStreak = 8;   // consecutive errors
  static constexpr uint32_t kQuarantineMs = 30000;   // penalty duration
  static constexpr uint8_t kWindowCapacity = 32;     // readings per node
  static constexpr uint32_t kSeqWindow = 0x80000000u; // forward half-space

  struct NodeState {
    bool seen = false;
    bool quarantined = false;
    uint32_t lastSequence = 0;
    uint32_t lastSeenMs = 0;
    uint32_t quarantineUntilMs = 0;
    uint32_t consecutiveErrors = 0;
    // Counters (User Story 2). CRC errors are attributed to the *claimed*
    // node id — a corrupt frame's id is untrusted, so this counter is a
    // diagnostic signal, never a key into trusted state.
    uint32_t valid = 0;
    uint32_t crcErrors = 0;
    uint32_t reservedErrors = 0;
    uint32_t rangeErrors = 0;
    uint32_t authErrors = 0;  // SR-6: forged/missing tag — the spoofing signal
    uint32_t replays = 0;
    uint32_t rateLimited = 0;
    uint32_t quarantineDrops = 0;
    uint32_t quarantineEvents = 0;
    uint32_t versionReports = 0;
    uint8_t lastFlags = 0;
    int16_t lastTempCx100 = 0;
    uint16_t lastHumPctX100 = 0;
    // Firmware version (Plan Phase 5, stretch), from the latest version-report
    // frame (Protocol.h kFlagVersionReport). Not a sensor reading.
    bool haveFirmwareVersion = false;
    uint8_t firmwareMajor = 0;
    uint8_t firmwareMinor = 0;
    uint8_t firmwarePatch = 0;
    // Token bucket, in milli-tokens (integer math only).
    uint32_t tokensMilli = kBucketCapacity * 1000;
    uint32_t lastRefillMs = 0;
    // Rolling window for FR-3 aggregates.
    int16_t tempWindow[kWindowCapacity] = {};
    uint16_t humWindow[kWindowCapacity] = {};
    uint8_t windowCount = 0;
    uint8_t windowHead = 0;
  };

  struct Aggregate {
    uint8_t count = 0;
    int16_t tempMin = 0, tempMax = 0;
    int32_t tempAvgCx100 = 0;
    uint16_t humMin = 0, humMax = 0;
    uint32_t humAvgPctX100 = 0;
  };

  // Stateful gates for a frame that passed every decoder gate.
  // Order: quarantine → rate limit → sequence. Returns the verdict;
  // quarantineTriggered is set when this call tips the node into quarantine
  // (caller emits exactly one alert — no log storms).
  Accept accept(const SensorFrame& frame, uint32_t nowMs, bool& quarantineTriggered);

  // Attribute a decode-stage error to the claimed node id.
  void recordDecodeError(uint8_t claimedNodeId, ErrorKind kind, uint32_t nowMs,
                         bool& quarantineTriggered);

  const NodeState& state(uint8_t nodeId) const { return nodes_[nodeId]; }
  Aggregate aggregate(uint8_t nodeId) const;

  void printStats(std::ostream& os) const;

  // Prometheus text-exposition format (Plan Phase 5, stretch monitoring).
  // Intended for the node_exporter textfile collector: the caller writes
  // this to a file, not a live HTTP endpoint (see main.cpp --metrics).
  void writePrometheusText(std::ostream& os) const;

 private:
  void noteError(NodeState& n, uint32_t nowMs, bool& quarantineTriggered);
  void refill(NodeState& n, uint32_t nowMs);

  NodeState nodes_[256];  // indexed by nodeId; 0 unused (statically bounded)
};

}  // namespace iot
