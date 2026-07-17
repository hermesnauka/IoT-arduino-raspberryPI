// app01 sensor node — samples temperature/humidity every 5 s and emits one
// fixed 16-byte binary frame per reading over serial (115200 baud).
//
// Wire contract: SensorFrame below must stay byte-identical with
// gateway-rpi/src/Protocol.h (SSDLC plan §2.2). Update both together.
// SR-5: no dynamic allocation — static buffers only.

#include <stdint.h>
#include <string.h>

// ---- wire protocol (mirror of gateway Protocol.h) --------------------------

static const uint16_t kMagic = 0xA55A;
static const uint8_t kFlagSensorFault = 0x01;

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
};
#pragma pack(pop)

static_assert(sizeof(SensorFrame) == 16, "wire contract violated: frame must be 16 bytes");

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

// ---- configuration ---------------------------------------------------------

static const uint8_t kNodeId = 1;              // unique per device on the bus
static const uint32_t kSampleIntervalMs = 5000; // FR-1

// ---- sensor access ---------------------------------------------------------
// Replace readSensor() with a real driver (e.g. DHT22 on pin 2) when hardware
// is attached. Returns false on read failure; the node then retransmits the
// last-known values with the fault flag set (SR-4 self-report).

struct Reading {
  int16_t temperatureCx100;
  uint16_t humidityPctX100;
};

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
static Reading g_lastGood = {2200, 4500};

static void sendFrame(const Reading &r, bool fault) {
  SensorFrame frame;
  frame.magic = kMagic;
  frame.nodeId = kNodeId;
  frame.flags = fault ? kFlagSensorFault : 0;
  frame.sequence = g_sequence++;
  frame.temperatureCx100 = r.temperatureCx100;
  frame.humidityPctX100 = r.humidityPctX100;
  frame.reserved = 0;

  uint8_t buf[sizeof(SensorFrame)];      // static-size stack buffer, no heap
  memcpy(buf, &frame, sizeof(frame));
  // AVR is little-endian, matching the wire byte order; the static_assert
  // plus the gateway's decode self-test guard the layout.
  frame.crc16 = crc16Ccitt(buf, 14);
  memcpy(buf + 14, &frame.crc16, 2);

  Serial.write(buf, sizeof(buf));
}

void setup() {
  Serial.begin(115200);
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
}
