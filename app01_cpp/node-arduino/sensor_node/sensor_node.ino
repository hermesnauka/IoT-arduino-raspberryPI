// app01 sensor node — samples temperature/humidity every 5 s and emits one
// fixed 24-byte binary frame per reading over serial (115200 baud).
//
// Wire contract: SensorFrame below must stay byte-identical with
// gateway-rpi/src/Protocol.h (SSDLC plan §2.2). Update both together.
// SR-5: no dynamic allocation — static buffers only.

#include <stdint.h>
#include <string.h>

// ---- wire protocol (mirror of gateway Protocol.h) --------------------------

static const uint16_t kMagic = 0xA55A;
static const uint8_t kFlagSensorFault = 0x01;
// Flags-extension frame (mirror of gateway Protocol.h kFlagVersionReport):
// temp/hum fields carry a firmware version instead of a sensor reading.
static const uint8_t kFlagVersionReport = 0x02;

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
  uint64_t authTag;           // SipHash-2-4 over bytes 0–13 (SR-6); 0 when auth off
};
#pragma pack(pop)

static_assert(sizeof(SensorFrame) == 24, "wire contract violated: frame must be 24 bytes");

static uint16_t crc16Ccitt(const uint8_t *data, uint16_t len) {
  uint16_t crc = 0xFFFF;
  for (uint16_t i = 0; i < len; ++i) {
    crc ^= (uint16_t)((uint16_t)data[i] << 8);
    for (uint8_t b = 0; b < 8; ++b) {
      crc = (crc & 0x8000) ? (uint16_t)((uint16_t)(crc << 1) ^ 0x1021)
                           : (uint16_t)(crc << 1);
    }
  }
  return crc;
}

// ---- frame authentication (SR-6, plan §2.3) --------------------------------
// Compile-time switch: 0 = transmit authTag=0 (accepted by a gateway running
// without --keys), 1 = sign every frame with the per-node key below.
// Enable via: arduino-cli compile --build-property
//   "compiler.cpp.extra_flags=-DSENSOR_NODE_AUTH=1" ...
#ifndef SENSOR_NODE_AUTH
#define SENSOR_NODE_AUTH 0
#endif

#if SENSOR_NODE_AUTH
// Per-node 128-bit pre-shared key, mirrored in this node's line of the
// gateway's --keys file. Flash-resident (PROGMEM) is a documented dev-grade
// placement; production moves it to EEPROM or a secure element (plan §2.3).
// THIS VALUE IS THE SHARED TEST KEY — replace per device before deployment.
static const uint8_t kNodeKey[16] PROGMEM = {
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};

// SipHash-2-4, mirror of gateway-rpi/src/SipHash.h (known-answer vectors are
// asserted there and in frame_simulator.py; update all three together).
static uint64_t rotl64(uint64_t x, uint8_t b) { return (x << b) | (x >> (64 - b)); }

static uint64_t readLe64(const uint8_t *p) {
  uint64_t v = 0;
  for (int8_t i = 7; i >= 0; --i) v = (v << 8) | p[i];
  return v;
}

#define SIPROUND                                                          \
  do {                                                                    \
    v0 += v1; v1 = rotl64(v1, 13); v1 ^= v0; v0 = rotl64(v0, 32);        \
    v2 += v3; v3 = rotl64(v3, 16); v3 ^= v2;                             \
    v0 += v3; v3 = rotl64(v3, 21); v3 ^= v0;                             \
    v2 += v1; v1 = rotl64(v1, 17); v1 ^= v2; v2 = rotl64(v2, 32);        \
  } while (0)

static uint64_t sipHash24(const uint8_t key[16], const uint8_t *data, uint16_t len) {
  uint64_t v0 = 0x736f6d6570736575ULL ^ readLe64(key);
  uint64_t v1 = 0x646f72616e646f6dULL ^ readLe64(key + 8);
  uint64_t v2 = 0x6c7967656e657261ULL ^ readLe64(key);
  uint64_t v3 = 0x7465646279746573ULL ^ readLe64(key + 8);
  const uint16_t full = (uint16_t)(len & ~(uint16_t)7);
  for (uint16_t off = 0; off < full; off += 8) {
    uint64_t m = readLe64(data + off);
    v3 ^= m;
    SIPROUND; SIPROUND;
    v0 ^= m;
  }
  uint64_t last = (uint64_t)(len & 0xff) << 56;
  for (uint16_t i = 0; i < (len & 7); ++i) {
    last |= (uint64_t)data[full + i] << (8 * i);
  }
  v3 ^= last;
  SIPROUND; SIPROUND;
  v0 ^= last;
  v2 ^= 0xff;
  SIPROUND; SIPROUND; SIPROUND; SIPROUND;
  return v0 ^ v1 ^ v2 ^ v3;
}
#endif  // SENSOR_NODE_AUTH

// ---- configuration ---------------------------------------------------------

static const uint8_t kNodeId = 1;              // unique per device on the bus
static const uint32_t kSampleIntervalMs = 5000; // FR-1

// Firmware version, announced via a kFlagVersionReport frame (Plan Phase 5,
// stretch): once at startup and then every kVersionReportEverySamples
// readings, so a gateway that (re)starts after the node still learns it.
static const uint8_t kFirmwareMajor = 1;
static const uint8_t kFirmwareMinor = 0;
static const uint8_t kFirmwarePatch = 0;
static const uint32_t kVersionReportEverySamples = 60; // ~5 min at 5 s/sample

// ---- sensor access ---------------------------------------------------------
// Replace readSensor() with a real driver (e.g. DHT22 on pin 2) when hardware
// is attached. Returns false on read failure; the node then retransmits the
// last-known values with the fault flag set (SR-4 self-report).

struct Reading {
  int16_t temperatureCx100;
  uint16_t humidityPctX100;
};

// Explicit prototypes: the Arduino builder auto-inserts its own above this
// struct's definition otherwise, which does not compile.
static bool readSensor(Reading &out);
static void sendFrame(const Reading &r, bool fault);
static void sealAndSend(SensorFrame &frame);

static bool readSensor(Reading &out) {
  // Synthetic plausible values so the pipeline is exercisable without
  // hardware: slow triangle wave around 22 °C / 45 %RH.
  uint32_t t = millis() / 1000;
  int16_t wobble = (int16_t)(t % 120);
  if (wobble > 60) wobble = (int16_t)(120 - wobble);
  out.temperatureCx100 = (int16_t)(2200 + wobble * 10); // 22.00–28.00 °C
  out.humidityPctX100 = (uint16_t)(4500 + wobble * 20); // 45.00–57.00 %RH
  return true;
}

// ---- transmit --------------------------------------------------------------

static uint32_t g_sequence = 0;      // monotonic, wraps at 2^32 (SR-2)
static uint32_t g_lastSampleMs = 0;
static uint32_t g_sampleCount = 0;
static Reading g_lastGood = {2200, 4500};

// Seals (CRC + auth tag) and transmits a frame whose payload fields are set.
// AVR is little-endian, matching the wire byte order; the static_assert plus
// the gateway's decode self-test guard the layout.
static void sealAndSend(SensorFrame &frame) {
  uint8_t buf[sizeof(SensorFrame)];      // static-size stack buffer, no heap
  memcpy(buf, &frame, sizeof(frame));
  frame.crc16 = crc16Ccitt(buf, 14);
  memcpy(buf + 14, &frame.crc16, 2);
#if SENSOR_NODE_AUTH
  uint8_t key[16];
  memcpy_P(key, kNodeKey, sizeof(key));  // PROGMEM → RAM for the hash
  frame.authTag = sipHash24(key, buf, 14);
#else
  frame.authTag = 0;
#endif
  memcpy(buf + 16, &frame.authTag, 8);
  Serial.write(buf, sizeof(buf));
}

static void sendVersionFrame() {
  uint16_t packedTemp = (uint16_t)(((uint16_t)kFirmwareMajor << 8) | kFirmwareMinor);

  SensorFrame frame;
  frame.magic = kMagic;
  frame.nodeId = kNodeId;
  frame.flags = kFlagVersionReport;
  frame.sequence = g_sequence++;
  frame.temperatureCx100 = (int16_t)packedTemp;
  frame.humidityPctX100 = (uint16_t)kFirmwarePatch;
  frame.reserved = 0;

  sealAndSend(frame);
}

static void sendFrame(const Reading &r, bool fault) {
  SensorFrame frame;
  frame.magic = kMagic;
  frame.nodeId = kNodeId;
  frame.flags = fault ? kFlagSensorFault : 0;
  frame.sequence = g_sequence++;
  frame.temperatureCx100 = r.temperatureCx100;
  frame.humidityPctX100 = r.humidityPctX100;
  frame.reserved = 0;

  sealAndSend(frame);
}

void setup() {
  Serial.begin(115200);
  sendVersionFrame();  // announce firmware version once at startup
}

void loop() {
  uint32_t now = millis();
  if (now - g_lastSampleMs < kSampleIntervalMs) {
    return;
  }
  g_lastSampleMs = now;

  Reading r;
  bool ok = readSensor(r);
  if (ok) {
    g_lastGood = r;
  }
  sendFrame(g_lastGood, !ok);

  ++g_sampleCount;
  if (g_sampleCount % kVersionReportEverySamples == 0) {
    sendVersionFrame();  // re-announce for gateways that (re)started late
  }
}
