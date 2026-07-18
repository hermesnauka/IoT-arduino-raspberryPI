// Gateway entry point.
//   gateway --selftest          run the offline security self-test (plan Phase 4)
//   gateway --read <path|->     decode a byte stream (tty, file, or - for stdin)
//                               [--verbose] print each accepted reading
//                               [--metrics <path>] write Prometheus textfile
//                               metrics after each processed chunk (plan Phase 5)
//                               [--aggregate <n>] publish per-node min/max/avg
//                               every n accepted readings (FR-3)
// Prints decoder + per-node stats on EOF. Exit code 0 = healthy.
// SIGUSR1 dumps per-node counters on demand while running.

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <csignal>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>

#include "FrameDecoder.h"
#include "NodeRegistry.h"
#include "Protocol.h"
#include "SipHash.h"

namespace {

using iot::FrameDecoder;
using iot::KeyStore;
using iot::NodeRegistry;
using iot::SensorFrame;

// SR-6 key file: one `nodeId:32-hex-chars` per line; '#' comments and blank
// lines ignored. Fail-closed: any malformed line rejects the whole file.
// Group/world-accessible modes get a warning (plan §2.3 recommends 0600) —
// advisory only, since dev setups legitimately use throwaway test keys.
bool loadKeyFile(const char* path, KeyStore& out, std::string& err) {
  struct stat st = {};
  if (stat(path, &st) == 0 && (st.st_mode & 077) != 0) {
    std::cerr << "warning: key file " << path
              << " is group/world-accessible; recommend chmod 0600\n";
  }
  std::ifstream in(path);
  if (!in) {
    err = "cannot open key file";
    return false;
  }
  std::string line;
  int lineNo = 0;
  while (std::getline(in, line)) {
    ++lineNo;
    if (line.empty() || line[0] == '#') continue;
    std::size_t colon = line.find(':');
    if (colon == std::string::npos || line.size() != colon + 1 + 32) {
      err = "line " + std::to_string(lineNo) + ": expected nodeId:32-hex-chars";
      return false;
    }
    unsigned long id = 0;
    try {
      std::size_t used = 0;
      id = std::stoul(line.substr(0, colon), &used);
      if (used != colon) throw std::invalid_argument("trailing junk");
    } catch (const std::exception&) {
      err = "line " + std::to_string(lineNo) + ": bad node id";
      return false;
    }
    if (id < 1 || id > 255) {
      err = "line " + std::to_string(lineNo) + ": node id out of range 1-255";
      return false;
    }
    for (int i = 0; i < 16; ++i) {
      unsigned byte = 0;
      for (int nib = 0; nib < 2; ++nib) {
        char c = line[colon + 1 + i * 2 + nib];
        unsigned v;
        if (c >= '0' && c <= '9') v = static_cast<unsigned>(c - '0');
        else if (c >= 'a' && c <= 'f') v = static_cast<unsigned>(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') v = static_cast<unsigned>(c - 'A' + 10);
        else {
          err = "line " + std::to_string(lineNo) + ": bad hex digit";
          return false;
        }
        byte = (byte << 4) | v;
      }
      out.keys[id][i] = static_cast<uint8_t>(byte);
    }
    out.present[id] = true;
  }
  return true;
}

// SIGUSR1 dumps per-node counters to stdout on demand (Plan Phase 5:
// journald captures stdout under systemd, so `systemctl kill -s SIGUSR1
// <unit>` + `journalctl` is the operator's counter-dump workflow). The
// handler only sets a flag; the actual print happens back in the read loop,
// since std::cout is not async-signal-safe.
volatile std::sig_atomic_t g_dumpRequested = 0;
void handleSigUsr1(int /*signum*/) { g_dumpRequested = 1; }

// ---------------------------------------------------------------------------
// Frame construction helper (used by self-test only; the real producer is the
// Arduino sketch / Python simulator).
SensorFrame makeFrame(uint8_t nodeId, uint32_t seq, int16_t tempCx100,
                      uint16_t humPctX100, uint8_t flags = 0, uint16_t reserved = 0,
                      const uint8_t* key = nullptr) {
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
  f.authTag = key ? iot::sipHash24(key, raw, iot::kAuthCoverage) : 0;
  return f;
}

// Fixed test-only key (also baked into frame_simulator.py — never a real key).
const uint8_t kTestKey[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                              0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

// Builds a flags-extension version-report frame (Protocol.h kFlagVersionReport).
SensorFrame makeVersionFrame(uint8_t nodeId, uint32_t seq, uint8_t major, uint8_t minor,
                             uint8_t patch) {
  uint16_t packedTemp = static_cast<uint16_t>((static_cast<uint16_t>(major) << 8) | minor);
  return makeFrame(nodeId, seq, static_cast<int16_t>(packedTemp), patch,
                   iot::kFlagVersionReport, 0);
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
  static_assert(sizeof(SensorFrame) == 24);
  // Runtime little-endian check: the wire is LE; a BE host would need byte
  // swaps in the decoder (not supported — fail loudly instead of corrupting).
  uint16_t probe = 0x0102;
  uint8_t first;
  std::memcpy(&first, &probe, 1);
  CHECK(first == 0x02);
  // CRC-16/CCITT-FALSE known-answer test.
  CHECK(iot::crc16Ccitt(reinterpret_cast<const uint8_t*>("123456789"), 9) == 0x29B1);
  // SipHash-2-4 known-answer tests (reference vectors_sip64, key 00…0f):
  // empty input, and a 15-byte input 00…0e exercising the partial-block path.
  const uint8_t seq15[15] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14};
  CHECK(iot::sipHash24(kTestKey, seq15, 0) == 0x726fdb47dd0e0e31ULL);
  CHECK(iot::sipHash24(kTestKey, seq15, 15) == 0xa129ca6149be45e5ULL);
}

void testAuthGate() {
  KeyStore ks;
  ks.present[1] = true;
  std::memcpy(ks.keys[1], kTestKey, 16);

  FrameDecoder dec;
  dec.setKeyStore(&ks);

  // Correctly signed frame accepted.
  pushFrame(dec, makeFrame(1, 1, 2250, 4500, 0, 0, kTestKey));
  FrameDecoder::Result r{};
  CHECK(dec.next(r));
  CHECK(r.status == FrameDecoder::Status::Ok);

  // Forged tag dropped.
  SensorFrame forged = makeFrame(1, 2, 2250, 4500, 0, 0, kTestKey);
  forged.authTag ^= 1;
  pushFrame(dec, forged);
  CHECK(dec.next(r));
  CHECK(r.status == FrameDecoder::Status::BadAuth);

  // Tampered payload with a recomputed CRC but a stale tag: the CRC gate
  // passes, the auth gate catches it — the exact spoofing scenario (SR-6).
  SensorFrame tampered = makeFrame(1, 3, 2250, 4500, 0, 0, kTestKey);
  tampered.temperatureCx100 = 3000;
  uint8_t raw[iot::kFrameSize];
  std::memcpy(raw, &tampered, iot::kFrameSize);
  tampered.crc16 = iot::crc16Ccitt(raw, iot::kCrcCoverage);
  pushFrame(dec, tampered);
  CHECK(dec.next(r));
  CHECK(r.status == FrameDecoder::Status::BadAuth);

  // Node with no key entry fails closed, even with tag = 0.
  pushFrame(dec, makeFrame(2, 1, 2250, 4500));
  CHECK(dec.next(r));
  CHECK(r.status == FrameDecoder::Status::BadAuth);
  CHECK(dec.stats().authErrors == 3);

  // Auth off (no KeyStore): a zero-tag frame is accepted (plan §2.3).
  FrameDecoder open;
  pushFrame(open, makeFrame(2, 1, 2250, 4500));
  CHECK(open.next(r));
  CHECK(r.status == FrameDecoder::Status::Ok);
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

void testVersionReportFrame() {
  FrameDecoder dec;
  NodeRegistry reg;
  // major=200 packs a temp field well outside the sensor range: proves the
  // range gate is actually skipped for version frames, not coincidentally passing.
  pushFrame(dec, makeVersionFrame(1, 1, 200, 1, 5));
  FrameDecoder::Result r{};
  CHECK(dec.next(r));
  CHECK(r.status == FrameDecoder::Status::Ok);
  bool q = false;
  CHECK(reg.accept(r.frame, 0, q) == NodeRegistry::Accept::Accepted);
  const NodeRegistry::NodeState& n = reg.state(1);
  CHECK(n.haveFirmwareVersion);
  CHECK(n.firmwareMajor == 200);
  CHECK(n.firmwareMinor == 1);
  CHECK(n.firmwarePatch == 5);
  CHECK(n.versionReports == 1);
  CHECK(n.valid == 0);  // not counted as a sensor reading
}

void testPrometheusExport() {
  NodeRegistry reg;
  bool q = false;
  CHECK(reg.accept(makeFrame(1, 1, 2250, 4500), 0, q) == NodeRegistry::Accept::Accepted);
  CHECK(reg.accept(makeVersionFrame(1, 2, 1, 2, 3), 100, q) == NodeRegistry::Accept::Accepted);
  std::ostringstream oss;
  reg.writePrometheusText(oss);
  std::string text = oss.str();
  CHECK(text.find("iot_gateway_node_valid_total{node=\"1\"} 1") != std::string::npos);
  CHECK(text.find("iot_gateway_node_firmware_reports_total{node=\"1\"} 1") != std::string::npos);
  CHECK(text.find("# TYPE iot_gateway_node_quarantined gauge") != std::string::npos);
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
            r.status == FrameDecoder::Status::BadAuth ||
            r.status == FrameDecoder::Status::BadRange);
    }
  }
  const FrameDecoder::Stats& s = dec.stats();
  CHECK(s.bytesIn > 0);
  // Every byte is accounted for: dropped, skipped, consumed, or still buffered.
  CHECK(s.resyncBytes + s.bytesDropped <= s.bytesIn);
}

void testSigUsr1SetsDumpFlag() {
  g_dumpRequested = 0;
  std::signal(SIGUSR1, handleSigUsr1);
  std::raise(SIGUSR1);
  CHECK(g_dumpRequested == 1);
  g_dumpRequested = 0;
  std::signal(SIGUSR1, SIG_DFL);
}

int runSelfTest() {
  testWireContract();
  testAuthGate();
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
  testVersionReportFrame();
  testPrometheusExport();
  testFuzzDecoderNeverCrashes();
  testSigUsr1SetsDumpFlag();
  if (g_failures == 0) {
    std::cout << "selftest: all checks passed\n";
    return 0;
  }
  std::cerr << "selftest: " << g_failures << " check(s) FAILED\n";
  return 1;
}

// ---------------------------------------------------------------------------
// Prometheus textfile-collector export (plan Phase 5, stretch monitoring):
// write-then-rename so a concurrent scrape/collector never reads a partial
// file (the standard node_exporter textfile-collector contract).
void writeMetricsAtomic(const char* path, const NodeRegistry& reg) {
  char tmpPath[512];
  int n = std::snprintf(tmpPath, sizeof(tmpPath), "%s.tmp", path);
  if (n < 0 || static_cast<std::size_t>(n) >= sizeof(tmpPath)) {
    std::cerr << "warning: metrics path too long, skipping export\n";
    return;
  }
  std::ofstream out(tmpPath, std::ios::trunc);
  if (!out) {
    std::cerr << "warning: cannot write metrics file " << tmpPath << "\n";
    return;
  }
  reg.writePrometheusText(out);
  out.close();
  if (std::rename(tmpPath, path) != 0) {
    std::cerr << "warning: cannot rename metrics file to " << path << "\n";
  }
}

// ---------------------------------------------------------------------------
// Stream mode. Reads the raw fd with POSIX read(), not iostreams: on a tty a
// read must return as soon as any bytes arrive — istream::read would block
// until a full buffer accumulated (~107 s of frames at one node's 5 s
// cadence) and discard the partial tail on hangup.
int runRead(const char* path, bool verbose, const char* metricsPath,
            const char* keysPath, uint32_t aggregateEvery) {
  int fd = 0;  // "-" = stdin
  if (std::strcmp(path, "-") != 0) {
    fd = ::open(path, O_RDONLY | O_NOCTTY);
    if (fd < 0) {
      std::cerr << "error: cannot open " << path << ": " << std::strerror(errno)
                << "\n";
      return 2;
    }
  }

  FrameDecoder dec;
  NodeRegistry reg;
  KeyStore keys;  // auth enforced iff --keys given (plan §2.3)
  if (keysPath) {
    std::string err;
    if (!loadKeyFile(keysPath, keys, err)) {
      std::cerr << "error: key file " << keysPath << ": " << err << "\n";
      return 2;  // fail closed: never run half-configured auth
    }
    dec.setKeyStore(&keys);
  }
  // Time source for the SR-2/3/4 gates (quarantine duration, token refill).
  // Live tty: CLOCK_MONOTONIC, so a 30 s quarantine is 30 real seconds. File
  // or pipe replay: one synthetic tick per chunk, so conformance tests stay
  // deterministic regardless of host speed. uint32 ms wraps at ~49 days; the
  // registry only uses unsigned deltas, so wrap is safe.
  const bool liveClock = isatty(fd) == 1;
  uint32_t nowMs = 0;
  // FR-3 publish interval, counted in accepted sensor readings rather than
  // wall time so replayed byte files and PTY streams behave identically.
  uint32_t acceptedSincePublish = 0;
  // sigaction without SA_RESTART: SIGUSR1 must interrupt a blocked read()
  // (EINTR) so a counter dump does not wait for the next frame to arrive.
  struct sigaction sa = {};
  sa.sa_handler = handleSigUsr1;
  sigemptyset(&sa.sa_mask);
  sigaction(SIGUSR1, &sa, nullptr);

  uint8_t buf[512];
  for (;;) {
    ssize_t got = ::read(fd, buf, sizeof(buf));

    if (g_dumpRequested) {
      g_dumpRequested = 0;
      std::cout << "[SIGUSR1] per-node counters dump:\n";
      reg.printStats(std::cout);
      std::cout.flush();
    }

    if (got < 0) {
      if (errno == EINTR) continue;  // signal during blocked read; dump done above
      if (errno != EIO) {            // EIO = tty hangup, the normal serial EOF
        std::cerr << "error: read " << path << ": " << std::strerror(errno) << "\n";
      }
      break;
    }
    if (got == 0) break;  // EOF (file replay or closed pipe)
    dec.push(buf, static_cast<std::size_t>(got));
    if (liveClock) {
      struct timespec ts = {};
      clock_gettime(CLOCK_MONOTONIC, &ts);
      nowMs = static_cast<uint32_t>(static_cast<uint64_t>(ts.tv_sec) * 1000u +
                                    static_cast<uint64_t>(ts.tv_nsec) / 1000000u);
    } else {
      ++nowMs;
    }

    FrameDecoder::Result r{};
    while (dec.next(r)) {
      bool alert = false;
      switch (r.status) {
        case FrameDecoder::Status::Ok: {
          NodeRegistry::Accept verdict = reg.accept(r.frame, nowMs, alert);
          if (verdict == NodeRegistry::Accept::Accepted && aggregateEvery > 0 &&
              !(r.frame.flags & iot::kFlagVersionReport)) {
            // Version reports carry no sensor payload (plan §2.2), so they
            // never advance the publish interval.
            if (++acceptedSincePublish >= aggregateEvery) {
              acceptedSincePublish = 0;
              reg.printAggregates(std::cout);
              std::cout.flush();
            }
          }
          if (verdict == NodeRegistry::Accept::Accepted && verbose) {
            if (r.frame.flags & iot::kFlagVersionReport) {
              const NodeRegistry::NodeState& n = reg.state(r.frame.nodeId);
              std::cout << "node " << static_cast<unsigned>(r.frame.nodeId)
                        << " seq=" << r.frame.sequence << " firmware="
                        << static_cast<unsigned>(n.firmwareMajor) << "."
                        << static_cast<unsigned>(n.firmwareMinor) << "."
                        << static_cast<unsigned>(n.firmwarePatch) << "\n";
            } else {
              std::cout << "node " << static_cast<unsigned>(r.frame.nodeId)
                        << " seq=" << r.frame.sequence
                        << " temp=" << r.frame.temperatureCx100 / 100.0
                        << "C hum=" << r.frame.humidityPctX100 / 100.0 << "%"
                        << (r.frame.flags & iot::kFlagSensorFault ? " [FAULT]" : "")
                        << "\n";
            }
          }
          break;
        }
        case FrameDecoder::Status::BadCrc:
          reg.recordDecodeError(r.frame.nodeId, NodeRegistry::ErrorKind::Crc,
                                nowMs, alert);
          break;
        case FrameDecoder::Status::BadReserved:
        case FrameDecoder::Status::BadNodeId:
          reg.recordDecodeError(r.frame.nodeId, NodeRegistry::ErrorKind::Reserved,
                                nowMs, alert);
          break;
        case FrameDecoder::Status::BadAuth:
          reg.recordDecodeError(r.frame.nodeId, NodeRegistry::ErrorKind::Auth,
                                nowMs, alert);
          break;
        case FrameDecoder::Status::BadRange:
          std::cerr << "ALERT node " << static_cast<unsigned>(r.frame.nodeId)
                    << ": out-of-range reading dropped (possible tamper)\n";
          reg.recordDecodeError(r.frame.nodeId, NodeRegistry::ErrorKind::Range,
                                nowMs, alert);
          break;
      }
      if (alert) {
        std::cerr << "ALERT node " << static_cast<unsigned>(r.frame.nodeId)
                  << ": quarantined after error streak\n";
      }
    }

    if (metricsPath) {
      writeMetricsAtomic(metricsPath, reg);
    }
  }

  if (fd != 0) ::close(fd);

  const FrameDecoder::Stats& s = dec.stats();
  std::cout << "[decoder] bytesIn=" << s.bytesIn << " framesOk=" << s.framesOk
            << " crcErrors=" << s.crcErrors << " resyncBytes=" << s.resyncBytes
            << " rangeErrors=" << s.rangeErrors
            << " reservedErrors=" << s.reservedErrors
            << " authErrors=" << s.authErrors
            << " bytesDropped=" << s.bytesDropped << "\n";
  reg.printStats(std::cout);
  return 0;
}

}  // namespace

namespace {
const char kUsage[] =
    " --selftest | --read <path|-> [--verbose] [--metrics <path>] [--keys <path>]"
    " [--aggregate <n>]\n";
}

int main(int argc, char** argv) {
  if (argc >= 2 && std::strcmp(argv[1], "--selftest") == 0) {
    return runSelfTest();
  }
  if (argc >= 3 && std::strcmp(argv[1], "--read") == 0) {
    bool verbose = false;
    const char* metricsPath = nullptr;
    const char* keysPath = nullptr;
    uint32_t aggregateEvery = 0;  // 0 = periodic publishing off (FR-3)
    for (int i = 3; i < argc; ++i) {
      if (std::strcmp(argv[i], "--verbose") == 0) {
        verbose = true;
      } else if (std::strcmp(argv[i], "--metrics") == 0 && i + 1 < argc) {
        metricsPath = argv[++i];
      } else if (std::strcmp(argv[i], "--keys") == 0 && i + 1 < argc) {
        keysPath = argv[++i];
      } else if (std::strcmp(argv[i], "--aggregate") == 0 && i + 1 < argc) {
        char* end = nullptr;
        unsigned long n = std::strtoul(argv[++i], &end, 10);
        if (end == nullptr || *end != '\0' || n == 0 || n > 1000000) {
          std::cerr << "error: --aggregate needs a count in [1, 1000000]\n";
          return 2;
        }
        aggregateEvery = static_cast<uint32_t>(n);
      } else {
        std::cerr << "usage: " << argv[0] << kUsage;
        return 2;
      }
    }
    return runRead(argv[2], verbose, metricsPath, keysPath, aggregateEvery);
  }
  std::cerr << "usage: " << argv[0] << kUsage;
  return 2;
}
