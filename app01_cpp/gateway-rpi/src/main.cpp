// Gateway entry point.
//   gateway --selftest          run the offline security self-test (plan Phase 4)
//   gateway --read <path|->     decode a byte stream (tty, file, or - for stdin)
//                               [--verbose] print each accepted reading
// Prints decoder + per-node stats on EOF. Exit code 0 = healthy.

#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <istream>

#include "FrameDecoder.h"
#include "NodeRegistry.h"
#include "Protocol.h"

namespace {

using iot::FrameDecoder;
using iot::NodeRegistry;
using iot::SensorFrame;

// ---------------------------------------------------------------------------
// Frame construction helper (used by self-test only; the real producer is the
// Arduino sketch / Python simulator).
SensorFrame makeFrame(uint8_t nodeId, uint32_t seq, int16_t tempCx100,
                      uint16_t humPctX100, uint8_t flags = 0, uint16_t reserved = 0) {
  SensorFrame f{};
  f.magic = iot::kMagic;
  f.nodeId = nodeId;
  f.flags = flags;
  f.sequence = seq;
  f.temperatureCx100 = tempCx100;
  f.humidityPctX100 = humPctX100;
  f.reserved = reserved;
  uint8_t raw[iot::kFrameSize];
  std::memcpy(raw, &f, iot::kFrameSize);
  f.crc16 = iot::crc16Ccitt(raw, iot::kCrcCoverage);
  return f;
}

void pushFrame(FrameDecoder& dec, const SensorFrame& f) {
  uint8_t raw[iot::kFrameSize];
  std::memcpy(raw, &f, iot::kFrameSize);
  dec.push(raw, iot::kFrameSize);
}

// ---------------------------------------------------------------------------
// Self-test harness
int g_failures = 0;

#define CHECK(cond)                                                        \
  do {                                                                     \
    if (!(cond)) {                                                         \
      ++g_failures;                                                        \
      std::cerr << "FAIL " << __func__ << ":" << __LINE__ << "  " #cond    \
                << "\n";                                                   \
    }                                                                      \
  } while (0)

void testWireContract() {
  static_assert(sizeof(SensorFrame) == 16);
  // Runtime little-endian check: the wire is LE; a BE host would need byte
  // swaps in the decoder (not supported — fail loudly instead of corrupting).
  uint16_t probe = 0x0102;
  uint8_t first;
  std::memcpy(&first, &probe, 1);
  CHECK(first == 0x02);
  // CRC-16/CCITT-FALSE known-answer test.
  CHECK(iot::crc16Ccitt(reinterpret_cast<const uint8_t*>("123456789"), 9) == 0x29B1);
}

void testValidFrameAccepted() {
  FrameDecoder dec;
  NodeRegistry reg;
  pushFrame(dec, makeFrame(1, 1, 2250, 4500));
  FrameDecoder::Result r{};
  CHECK(dec.next(r));
  CHECK(r.status == FrameDecoder::Status::Ok);
  bool q = false;
  CHECK(reg.accept(r.frame, 0, q) == NodeRegistry::Accept::Accepted);
  CHECK(!q);
  CHECK(reg.state(1).valid == 1);
  CHECK(reg.state(1).lastTempCx100 == 2250);
}

void testBadCrcDropped() {
  FrameDecoder dec;
  SensorFrame f = makeFrame(1, 1, 2250, 4500);
  f.crc16 = static_cast<uint16_t>(f.crc16 ^ 0xFFFF);
  pushFrame(dec, f);
  FrameDecoder::Result r{};
  CHECK(dec.next(r));
  CHECK(r.status == FrameDecoder::Status::BadCrc);
  CHECK(dec.stats().crcErrors == 1);
  CHECK(dec.stats().framesOk == 0);
}

void testOutOfRangeDropped() {
  FrameDecoder dec;
  pushFrame(dec, makeFrame(1, 1, 30000, 4500));  // 300 °C
  FrameDecoder::Result r{};
  CHECK(dec.next(r));
  CHECK(r.status == FrameDecoder::Status::BadRange);
  pushFrame(dec, makeFrame(1, 2, 2250, 20000));  // 200 %RH
  CHECK(dec.next(r));
  CHECK(r.status == FrameDecoder::Status::BadRange);
  CHECK(dec.stats().rangeErrors == 2);
}

void testReservedNonzeroDropped() {
  FrameDecoder dec;
  pushFrame(dec, makeFrame(1, 1, 2250, 4500, 0, 0xBEEF));
  FrameDecoder::Result r{};
  CHECK(dec.next(r));
  CHECK(r.status == FrameDecoder::Status::BadReserved);
}

void testReplayIgnored() {
  NodeRegistry reg;
  bool q = false;
  CHECK(reg.accept(makeFrame(1, 10, 2250, 4500), 0, q) == NodeRegistry::Accept::Accepted);
  CHECK(reg.accept(makeFrame(1, 10, 2250, 4500), 100, q) == NodeRegistry::Accept::Replay);
  CHECK(reg.accept(makeFrame(1, 5, 2250, 4500), 200, q) == NodeRegistry::Accept::Replay);
  CHECK(reg.accept(makeFrame(1, 11, 2250, 4500), 300, q) == NodeRegistry::Accept::Accepted);
  CHECK(reg.state(1).replays == 2);
  CHECK(reg.state(1).valid == 2);
  // Sequence wrap: 0xFFFFFFFF → 0 is a forward step, not a replay (SR-2).
  NodeRegistry reg2;
  CHECK(reg2.accept(makeFrame(2, 0xFFFFFFFFu, 2250, 4500), 0, q) == NodeRegistry::Accept::Accepted);
  CHECK(reg2.accept(makeFrame(2, 0, 2250, 4500), 100, q) == NodeRegistry::Accept::Accepted);
}

void testResyncOnGarbage() {
  FrameDecoder dec;
  const uint8_t garbage[] = {0x00, 0x5A, 0xA5, 0x13, 0x37, 0xFF, 0x5A};  // embeds fake magic
  dec.push(garbage, sizeof(garbage));
  pushFrame(dec, makeFrame(3, 7, 2000, 5000));
  FrameDecoder::Result r{};
  bool sawOk = false;
  while (dec.next(r)) {
    if (r.status == FrameDecoder::Status::Ok) {
      sawOk = true;
      CHECK(r.frame.nodeId == 3);
      CHECK(r.frame.sequence == 7);
    }
  }
  CHECK(sawOk);
}

void testTruncatedThenCompleted() {
  FrameDecoder dec;
  SensorFrame f = makeFrame(4, 1, 2100, 4000);
  uint8_t raw[iot::kFrameSize];
  std::memcpy(raw, &f, iot::kFrameSize);
  dec.push(raw, 9);  // first half only
  FrameDecoder::Result r{};
  CHECK(!dec.next(r));  // NeedMore
  dec.push(raw + 9, iot::kFrameSize - 9);
  CHECK(dec.next(r));
  CHECK(r.status == FrameDecoder::Status::Ok);
}

void testRateLimit() {
  NodeRegistry reg;
  bool q = false;
  uint32_t seq = 1;
  // Drain the burst bucket at t=0…
  for (uint32_t i = 0; i < NodeRegistry::kBucketCapacity; ++i) {
    CHECK(reg.accept(makeFrame(1, seq++, 2250, 4500), 0, q) == NodeRegistry::Accept::Accepted);
  }
  CHECK(reg.accept(makeFrame(1, seq++, 2250, 4500), 0, q) == NodeRegistry::Accept::RateLimited);
  // …after 1 s, kRefillPerSec tokens are back.
  uint32_t accepted = 0;
  for (uint32_t i = 0; i < NodeRegistry::kBucketCapacity; ++i) {
    if (reg.accept(makeFrame(1, seq++, 2250, 4500), 1000, q) == NodeRegistry::Accept::Accepted)
      ++accepted;
  }
  CHECK(accepted == NodeRegistry::kRefillPerSec);
}

void testQuarantineIsolatesNode() {
  NodeRegistry reg;
  bool q = false;
  int alerts = 0;
  // Node 1 spews consecutive CRC garbage → quarantined after the streak,
  // with exactly one alert.
  for (uint32_t i = 0; i < NodeRegistry::kQuarantineStreak + 4; ++i) {
    reg.recordDecodeError(1, NodeRegistry::ErrorKind::Crc, i * 10, q);
    if (q) ++alerts;
  }
  CHECK(alerts == 1);
  CHECK(reg.state(1).quarantined);
  // While quarantined, even a valid frame from node 1 is dropped…
  CHECK(reg.accept(makeFrame(1, 1, 2250, 4500), 200, q) == NodeRegistry::Accept::Quarantined);
  // …but node 2 is unaffected (SR-4: per-node fail-safe).
  CHECK(reg.accept(makeFrame(2, 1, 2250, 4500), 200, q) == NodeRegistry::Accept::Accepted);
  // After the penalty window the node recovers.
  uint32_t later = 200 + NodeRegistry::kQuarantineMs + 1000;
  CHECK(reg.accept(makeFrame(1, 2, 2250, 4500), later, q) == NodeRegistry::Accept::Accepted);
  CHECK(!reg.state(1).quarantined);
}

void testAggregates() {
  NodeRegistry reg;
  bool q = false;
  const int16_t temps[] = {2000, 2500, 3000};
  for (uint32_t i = 0; i < 3; ++i) {
    reg.accept(makeFrame(1, i + 1, temps[i], static_cast<uint16_t>(4000 + i * 500)), i * 10, q);
  }
  NodeRegistry::Aggregate a = reg.aggregate(1);
  CHECK(a.count == 3);
  CHECK(a.tempMin == 2000);
  CHECK(a.tempMax == 3000);
  CHECK(a.tempAvgCx100 == 2500);
  CHECK(a.humAvgPctX100 == 4500);
}

void testFuzzDecoderNeverCrashes() {
  // Deterministic LCG byte storm: the decoder must stay bounded and sane.
  FrameDecoder dec;
  uint32_t lcg = 0xC0FFEE01u;
  uint8_t chunk[257];
  for (int iter = 0; iter < 512; ++iter) {
    std::size_t len = (lcg % sizeof(chunk)) + 1;
    for (std::size_t i = 0; i < len; ++i) {
      lcg = lcg * 1664525u + 1013904223u;
      chunk[i] = static_cast<uint8_t>(lcg >> 24);
    }
    dec.push(chunk, len);
    FrameDecoder::Result r{};
    while (dec.next(r)) {
      // Whatever comes out must be a classified verdict, never uninitialized.
      CHECK(r.status == FrameDecoder::Status::Ok ||
            r.status == FrameDecoder::Status::BadCrc ||
            r.status == FrameDecoder::Status::BadReserved ||
            r.status == FrameDecoder::Status::BadNodeId ||
            r.status == FrameDecoder::Status::BadRange);
    }
  }
  const FrameDecoder::Stats& s = dec.stats();
  CHECK(s.bytesIn > 0);
  // Every byte is accounted for: dropped, skipped, consumed, or still buffered.
  CHECK(s.resyncBytes + s.bytesDropped <= s.bytesIn);
}

int runSelfTest() {
  testWireContract();
  testValidFrameAccepted();
  testBadCrcDropped();
  testOutOfRangeDropped();
  testReservedNonzeroDropped();
  testReplayIgnored();
  testResyncOnGarbage();
  testTruncatedThenCompleted();
  testRateLimit();
  testQuarantineIsolatesNode();
  testAggregates();
  testFuzzDecoderNeverCrashes();
  if (g_failures == 0) {
    std::cout << "selftest: all checks passed\n";
    return 0;
  }
  std::cerr << "selftest: " << g_failures << " check(s) FAILED\n";
  return 1;
}

// ---------------------------------------------------------------------------
// Stream mode
int runRead(const char* path, bool verbose) {
  std::ifstream file;
  std::istream* in = &std::cin;
  if (std::strcmp(path, "-") != 0) {
    file.open(path, std::ios::binary);
    if (!file) {
      std::cerr << "error: cannot open " << path << "\n";
      return 2;
    }
    in = &file;
  }

  FrameDecoder dec;
  NodeRegistry reg;
  uint32_t syntheticMs = 0;  // file replay has no wall clock; one tick per chunk

  uint8_t buf[512];
  while (in->read(reinterpret_cast<char*>(buf), sizeof(buf)) || in->gcount() > 0) {
    std::size_t got = static_cast<std::size_t>(in->gcount());
    dec.push(buf, got);
    ++syntheticMs;

    FrameDecoder::Result r{};
    while (dec.next(r)) {
      bool alert = false;
      switch (r.status) {
        case FrameDecoder::Status::Ok: {
          NodeRegistry::Accept verdict = reg.accept(r.frame, syntheticMs, alert);
          if (verdict == NodeRegistry::Accept::Accepted && verbose) {
            std::cout << "node " << static_cast<unsigned>(r.frame.nodeId)
                      << " seq=" << r.frame.sequence
                      << " temp=" << r.frame.temperatureCx100 / 100.0
                      << "C hum=" << r.frame.humidityPctX100 / 100.0 << "%"
                      << (r.frame.flags & iot::kFlagSensorFault ? " [FAULT]" : "")
                      << "\n";
          }
          break;
        }
        case FrameDecoder::Status::BadCrc:
          reg.recordDecodeError(r.frame.nodeId, NodeRegistry::ErrorKind::Crc,
                                syntheticMs, alert);
          break;
        case FrameDecoder::Status::BadReserved:
        case FrameDecoder::Status::BadNodeId:
          reg.recordDecodeError(r.frame.nodeId, NodeRegistry::ErrorKind::Reserved,
                                syntheticMs, alert);
          break;
        case FrameDecoder::Status::BadRange:
          std::cerr << "ALERT node " << static_cast<unsigned>(r.frame.nodeId)
                    << ": out-of-range reading dropped (possible tamper)\n";
          reg.recordDecodeError(r.frame.nodeId, NodeRegistry::ErrorKind::Range,
                                syntheticMs, alert);
          break;
      }
      if (alert) {
        std::cerr << "ALERT node " << static_cast<unsigned>(r.frame.nodeId)
                  << ": quarantined after error streak\n";
      }
    }
  }

  const FrameDecoder::Stats& s = dec.stats();
  std::cout << "[decoder] bytesIn=" << s.bytesIn << " framesOk=" << s.framesOk
            << " crcErrors=" << s.crcErrors << " resyncBytes=" << s.resyncBytes
            << " rangeErrors=" << s.rangeErrors
            << " reservedErrors=" << s.reservedErrors
            << " bytesDropped=" << s.bytesDropped << "\n";
  reg.printStats(std::cout);
  return 0;
}

}  // namespace

int main(int argc, char** argv) {
  if (argc >= 2 && std::strcmp(argv[1], "--selftest") == 0) {
    return runSelfTest();
  }
  if (argc >= 3 && std::strcmp(argv[1], "--read") == 0) {
    bool verbose = (argc >= 4 && std::strcmp(argv[3], "--verbose") == 0);
    return runRead(argv[2], verbose);
  }
  std::cerr << "usage: " << argv[0] << " --selftest | --read <path|-> [--verbose]\n";
  return 2;
}
