#include "NodeRegistry.h"

#include <iomanip>

namespace iot {

void NodeRegistry::refill(NodeState& n, uint32_t nowMs) {
  uint32_t elapsed = nowMs - n.lastRefillMs;  // wraps safely (unsigned)
  n.lastRefillMs = nowMs;
  uint64_t add = static_cast<uint64_t>(elapsed) * kRefillPerSec;  // milli-tokens
  uint64_t total = static_cast<uint64_t>(n.tokensMilli) + add;
  uint64_t cap = static_cast<uint64_t>(kBucketCapacity) * 1000;
  n.tokensMilli = static_cast<uint32_t>(total < cap ? total : cap);
}

void NodeRegistry::noteError(NodeState& n, uint32_t nowMs, bool& quarantineTriggered) {
  ++n.consecutiveErrors;
  if (!n.quarantined && n.consecutiveErrors >= kQuarantineStreak) {
    n.quarantined = true;
    n.quarantineUntilMs = nowMs + kQuarantineMs;
    ++n.quarantineEvents;
    quarantineTriggered = true;
  }
}

NodeRegistry::Accept NodeRegistry::accept(const SensorFrame& frame, uint32_t nowMs,
                                          bool& quarantineTriggered) {
  quarantineTriggered = false;
  NodeState& n = nodes_[frame.nodeId];

  if (n.quarantined) {
    if (static_cast<int32_t>(nowMs - n.quarantineUntilMs) < 0) {
      ++n.quarantineDrops;
      return Accept::Quarantined;
    }
    n.quarantined = false;  // penalty served; start clean
    n.consecutiveErrors = 0;
  }

  refill(n, nowMs);
  if (n.tokensMilli < 1000) {
    ++n.rateLimited;
    // A flooding node is an error source: streaks feed quarantine (SR-3→SR-4).
    noteError(n, nowMs, quarantineTriggered);
    return Accept::RateLimited;
  }
  n.tokensMilli -= 1000;

  if (n.seen) {
    uint32_t delta = frame.sequence - n.lastSequence;  // wrap-aware
    if (delta == 0 || delta > kSeqWindow) {
      ++n.replays;
      noteError(n, nowMs, quarantineTriggered);
      return Accept::Replay;
    }
  }

  n.seen = true;
  n.lastSequence = frame.sequence;
  n.lastSeenMs = nowMs;
  n.lastFlags = frame.flags;
  n.consecutiveErrors = 0;

  if (frame.flags & kFlagVersionReport) {
    // Flags-extension frame: temp/hum fields carry a firmware version, not a
    // sensor reading — track it separately, don't feed the FR-3 window.
    uint16_t packedTemp = static_cast<uint16_t>(frame.temperatureCx100);
    n.firmwareMajor = static_cast<uint8_t>(packedTemp >> 8);
    n.firmwareMinor = static_cast<uint8_t>(packedTemp & 0xFF);
    n.firmwarePatch = static_cast<uint8_t>(frame.humidityPctX100 & 0xFF);
    n.haveFirmwareVersion = true;
    ++n.versionReports;
    return Accept::Accepted;
  }

  n.lastTempCx100 = frame.temperatureCx100;
  n.lastHumPctX100 = frame.humidityPctX100;
  ++n.valid;

  n.tempWindow[n.windowHead] = frame.temperatureCx100;
  n.humWindow[n.windowHead] = frame.humidityPctX100;
  n.windowHead = static_cast<uint8_t>((n.windowHead + 1) % kWindowCapacity);
  if (n.windowCount < kWindowCapacity) ++n.windowCount;

  return Accept::Accepted;
}

void NodeRegistry::recordDecodeError(uint8_t claimedNodeId, ErrorKind kind,
                                     uint32_t nowMs, bool& quarantineTriggered) {
  quarantineTriggered = false;
  NodeState& n = nodes_[claimedNodeId];
  switch (kind) {
    case ErrorKind::Crc: ++n.crcErrors; break;
    case ErrorKind::Reserved: ++n.reservedErrors; break;
    case ErrorKind::Range: ++n.rangeErrors; break;
    case ErrorKind::Auth: ++n.authErrors; break;
  }
  noteError(n, nowMs, quarantineTriggered);
}

NodeRegistry::Aggregate NodeRegistry::aggregate(uint8_t nodeId) const {
  const NodeState& n = nodes_[nodeId];
  Aggregate a;
  if (n.windowCount == 0) return a;
  a.count = n.windowCount;
  a.tempMin = a.tempMax = n.tempWindow[0];
  a.humMin = a.humMax = n.humWindow[0];
  int32_t tempSum = 0;
  uint32_t humSum = 0;
  for (uint8_t i = 0; i < n.windowCount; ++i) {
    int16_t t = n.tempWindow[i];
    uint16_t h = n.humWindow[i];
    if (t < a.tempMin) a.tempMin = t;
    if (t > a.tempMax) a.tempMax = t;
    if (h < a.humMin) a.humMin = h;
    if (h > a.humMax) a.humMax = h;
    tempSum += t;
    humSum += h;
  }
  a.tempAvgCx100 = tempSum / n.windowCount;
  a.humAvgPctX100 = humSum / n.windowCount;
  return a;
}

void NodeRegistry::printAggregates(std::ostream& os) const {
  for (unsigned id = 1; id < 256; ++id) {
    Aggregate a = aggregate(static_cast<uint8_t>(id));
    if (a.count == 0) continue;
    os << "[aggregate] node " << std::setw(3) << std::setfill('0') << id
       << std::setfill(' ') << " n=" << static_cast<unsigned>(a.count)
       << " tempMin=" << a.tempMin / 100.0 << " tempMax=" << a.tempMax / 100.0
       << " tempAvg=" << a.tempAvgCx100 / 100.0
       << " humMin=" << a.humMin / 100.0 << " humMax=" << a.humMax / 100.0
       << " humAvg=" << a.humAvgPctX100 / 100.0 << "\n";
  }
}

void NodeRegistry::printStats(std::ostream& os) const {
  for (unsigned id = 1; id < 256; ++id) {
    const NodeState& n = nodes_[id];
    bool touched = n.seen || n.crcErrors || n.reservedErrors || n.rangeErrors ||
                   n.authErrors || n.replays || n.rateLimited || n.quarantineDrops;
    if (!touched) continue;
    os << "[node " << std::setw(3) << std::setfill('0') << id << std::setfill(' ')
       << "] valid=" << n.valid << " crc=" << n.crcErrors
       << " auth=" << n.authErrors
       << " reserved=" << n.reservedErrors << " range=" << n.rangeErrors
       << " replay=" << n.replays << " rate=" << n.rateLimited
       << " qdrop=" << n.quarantineDrops << " quarantines=" << n.quarantineEvents
       << " fw=" << n.versionReports << " lastSeq=" << n.lastSequence << "\n";
    if (n.haveFirmwareVersion) {
      os << "[node " << std::setw(3) << std::setfill('0') << id << std::setfill(' ')
         << "] firmware=" << static_cast<unsigned>(n.firmwareMajor) << "."
         << static_cast<unsigned>(n.firmwareMinor) << "."
         << static_cast<unsigned>(n.firmwarePatch) << "\n";
    }
    Aggregate a = aggregate(static_cast<uint8_t>(id));
    if (a.count > 0) {
      os << "[node " << std::setw(3) << std::setfill('0') << id << std::setfill(' ')
         << "] window n=" << static_cast<unsigned>(a.count)
         << " tempMin=" << a.tempMin / 100.0 << " tempMax=" << a.tempMax / 100.0
         << " tempAvg=" << a.tempAvgCx100 / 100.0
         << " humAvg=" << a.humAvgPctX100 / 100.0 << "\n";
    }
  }
}

void NodeRegistry::writePrometheusText(std::ostream& os) const {
  uint16_t touched[256];
  std::size_t touchedCount = 0;
  for (unsigned id = 1; id < 256; ++id) {
    const NodeState& n = nodes_[id];
    if (n.seen || n.crcErrors || n.reservedErrors || n.rangeErrors ||
        n.authErrors || n.replays || n.rateLimited || n.quarantineDrops) {
      touched[touchedCount++] = static_cast<uint16_t>(id);
    }
  }

  auto emitCounter = [&](const char* name, const char* help, auto accessor) {
    os << "# HELP " << name << " " << help << "\n# TYPE " << name << " counter\n";
    for (std::size_t i = 0; i < touchedCount; ++i) {
      uint16_t id = touched[i];
      os << name << "{node=\"" << id << "\"} " << accessor(nodes_[id]) << "\n";
    }
  };
  auto emitGauge = [&](const char* name, const char* help, auto accessor) {
    os << "# HELP " << name << " " << help << "\n# TYPE " << name << " gauge\n";
    for (std::size_t i = 0; i < touchedCount; ++i) {
      uint16_t id = touched[i];
      os << name << "{node=\"" << id << "\"} " << accessor(nodes_[id]) << "\n";
    }
  };

  emitCounter("iot_gateway_node_valid_total", "Valid sensor readings accepted.",
              [](const NodeState& n) { return n.valid; });
  emitCounter("iot_gateway_node_crc_errors_total", "Frames dropped for a bad CRC (SR-1).",
              [](const NodeState& n) { return n.crcErrors; });
  emitCounter("iot_gateway_node_reserved_errors_total",
              "Frames dropped for a nonzero reserved field.",
              [](const NodeState& n) { return n.reservedErrors; });
  emitCounter("iot_gateway_node_range_errors_total",
              "Frames dropped for an implausible reading (SR-1).",
              [](const NodeState& n) { return n.rangeErrors; });
  emitCounter("iot_gateway_node_auth_errors_total",
              "Frames dropped for a forged or missing auth tag (SR-6) — spoofing signal.",
              [](const NodeState& n) { return n.authErrors; });
  emitCounter("iot_gateway_node_replay_total",
              "Stale or duplicated sequence numbers ignored (SR-2).",
              [](const NodeState& n) { return n.replays; });
  emitCounter("iot_gateway_node_rate_limited_total", "Frames dropped by the SR-3 rate limiter.",
              [](const NodeState& n) { return n.rateLimited; });
  emitCounter("iot_gateway_node_quarantine_events_total",
              "Times this node has entered quarantine (SR-4).",
              [](const NodeState& n) { return n.quarantineEvents; });
  emitCounter("iot_gateway_node_firmware_reports_total",
              "Firmware-version report frames received.",
              [](const NodeState& n) { return n.versionReports; });
  emitGauge("iot_gateway_node_quarantined", "Whether the node is currently quarantined.",
            [](const NodeState& n) { return n.quarantined ? 1 : 0; });

  os << "# HELP iot_gateway_node_last_temperature_celsius Last accepted temperature reading.\n"
     << "# TYPE iot_gateway_node_last_temperature_celsius gauge\n";
  for (std::size_t i = 0; i < touchedCount; ++i) {
    uint16_t id = touched[i];
    const NodeState& n = nodes_[id];
    if (n.valid == 0) continue;
    os << "iot_gateway_node_last_temperature_celsius{node=\"" << id << "\"} "
       << n.lastTempCx100 / 100.0 << "\n";
  }
  os << "# HELP iot_gateway_node_last_humidity_percent Last accepted humidity reading.\n"
     << "# TYPE iot_gateway_node_last_humidity_percent gauge\n";
  for (std::size_t i = 0; i < touchedCount; ++i) {
    uint16_t id = touched[i];
    const NodeState& n = nodes_[id];
    if (n.valid == 0) continue;
    os << "iot_gateway_node_last_humidity_percent{node=\"" << id << "\"} "
       << n.lastHumPctX100 / 100.0 << "\n";
  }
}

}  // namespace iot
