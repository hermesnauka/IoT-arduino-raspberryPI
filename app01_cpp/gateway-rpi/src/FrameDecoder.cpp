#include "FrameDecoder.h"

#include <cstring>

namespace iot {

void FrameDecoder::push(const uint8_t* data, std::size_t len) {
  stats_.bytesIn += len;
  for (std::size_t i = 0; i < len; ++i) {
    if (count_ == kRingSize) {
      // Bounded memory: overwrite the oldest byte rather than grow.
      head_ = (head_ + 1) % kRingSize;
      --count_;
      ++stats_.bytesDropped;
    }
    ring_[(head_ + count_) % kRingSize] = data[i];
    ++count_;
  }
}

void FrameDecoder::drop(std::size_t n) {
  if (n > count_) n = count_;
  head_ = (head_ + n) % kRingSize;
  count_ -= n;
}

bool FrameDecoder::next(Result& out) {
  while (buffered() >= kFrameSize) {
    // Gate 1: magic. Slide byte-by-byte until the delimiter lines up.
    if (at(0) != kMagicByte0 || at(1) != kMagicByte1) {
      drop(1);
      ++stats_.resyncBytes;
      continue;
    }

    // Gate 2: length is implicit — we only enter with >= kFrameSize buffered.
    uint8_t raw[kFrameSize];
    for (std::size_t i = 0; i < kFrameSize; ++i) raw[i] = at(i);

    SensorFrame frame;
    std::memcpy(&frame, raw, kFrameSize);

    // Gate 3: CRC — the authority over whether this is a real frame at all.
    if (crc16Ccitt(raw, kCrcCoverage) != frame.crc16) {
      drop(1);  // fake magic inside garbage; resync one byte at a time
      ++stats_.crcErrors;
      out = {Status::BadCrc, frame};
      return true;
    }

    // From here the frame is authentic (modulo CRC collisions): consume it
    // whole and judge its contents.
    drop(kFrameSize);

    if (frame.reserved != 0) {
      ++stats_.reservedErrors;
      out = {Status::BadReserved, frame};
      return true;
    }
    if (frame.nodeId == 0) {
      ++stats_.nodeIdErrors;
      out = {Status::BadNodeId, frame};
      return true;
    }
    if (frame.temperatureCx100 < kTempMinCx100 ||
        frame.temperatureCx100 > kTempMaxCx100 ||
        frame.humidityPctX100 > kHumMaxPctX100) {
      ++stats_.rangeErrors;
      out = {Status::BadRange, frame};
      return true;
    }

    ++stats_.framesOk;
    out = {Status::Ok, frame};
    return true;
  }
  return false;
}

}  // namespace iot
