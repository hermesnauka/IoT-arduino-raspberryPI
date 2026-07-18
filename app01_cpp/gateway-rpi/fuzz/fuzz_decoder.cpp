// AFL++ fuzz harness for FrameDecoder (Plan Phase 4, stretch — coverage-guided
// fuzzing beyond the simple Python random fuzz in tools/frame_simulator.py).
//
// Classic (non-persistent) AFL file-based harness: reads the whole input file
// into memory, feeds it to the decoder, and drains every frame. The decoder
// must never crash, and every input byte must be accounted for (consumed,
// dropped, or still buffered) — the same invariant the offline self-test
// checks in testFuzzDecoderNeverCrashes (main.cpp).
//
// Build (needs afl++: sudo apt install afl++):
//   cmake -S gateway-rpi -B gateway-rpi/build-fuzz -DBUILD_FUZZER=ON \
//         -DCMAKE_CXX_COMPILER=afl-clang-fast++
//   cmake --build gateway-rpi/build-fuzz --target fuzz_decoder
//
// Run:
//   afl-fuzz -i gateway-rpi/fuzz/seeds -o gateway-rpi/fuzz/findings \
//            -- gateway-rpi/build-fuzz/fuzz_decoder @@

#include <cassert>
#include <cstdint>
#include <cstdio>
#include <vector>

#include "FrameDecoder.h"

int main(int argc, char** argv) {
  if (argc != 2) {
    std::fprintf(stderr, "usage: %s <input-file>\n", argv[0]);
    return 1;
  }
  FILE* f = std::fopen(argv[1], "rb");
  if (!f) return 1;
  std::vector<uint8_t> data;
  uint8_t chunk[4096];
  size_t n;
  while ((n = std::fread(chunk, 1, sizeof(chunk), f)) > 0) {
    data.insert(data.end(), chunk, chunk + n);
  }
  std::fclose(f);

  iot::FrameDecoder dec;
  dec.push(data.data(), data.size());

  iot::FrameDecoder::Result r{};
  while (dec.next(r)) {
    // Any status is acceptable output; the invariant under fuzzing is
    // "never crash, never hang, never over-read" — AFL's instrumentation
    // and ASan (if enabled) catch violations as crashes.
  }

  const iot::FrameDecoder::Stats& s = dec.stats();
  assert(s.resyncBytes + s.bytesDropped <= s.bytesIn);
  return 0;
}
