# app01_cpp — app-specific rules

Design source of truth: `SSDLC_IoT_Sensor_Pipeline_Plan.md` (read before changing code).

## Wire contract

`SensorFrame` exists in two deliberately duplicated copies —
`gateway-rpi/src/Protocol.h` and `node-arduino/sensor_node/sensor_node.ino` —
plus the Python packer in `tools/frame_simulator.py` (`FRAME_FMT`). The same
triplication applies to SipHash-2-4 (`gateway-rpi/src/SipHash.h`, the sketch,
and `siphash24` in the simulator). Any protocol change updates all three in
one commit; the tripwires are the `static_assert(sizeof == 24)` on both C++
sides, the CRC known-answer test (`0x29B1` for `"123456789"`), and the SipHash
reference vectors (`0x726fdb47dd0e0e31` empty / `0xa129ca6149be45e5` 15-byte,
key `00…0f`) asserted in `--selftest` and the simulator.

Frame auth (SR-6) is optional: the gateway enforces it iff `--read … --keys
<file>` is given (`nodeId:32-hex` lines); the sketch signs iff compiled with
`-DSENSOR_NODE_AUTH=1`. Off by default on both sides.

## Verify (all three must pass before claiming done)

```bash
cmake -S gateway-rpi -B gateway-rpi/build && cmake --build gateway-rpi/build  # SAST gate
gateway-rpi/build/gateway --selftest                                          # offline security tests
python3 tools/frame_simulator.py --gateway gateway-rpi/build/gateway          # protocol conformance
```

Optional stretch verify — coverage-guided fuzzing (needs `afl++` installed and
`core_pattern` set to `core`; never use `AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES`):

```bash
cmake -S gateway-rpi -B gateway-rpi/build-fuzz -DBUILD_FUZZER=ON \
      -DCMAKE_CXX_COMPILER=afl-clang-fast++
cmake --build gateway-rpi/build-fuzz --target fuzz_decoder
timeout 180 afl-fuzz -i gateway-rpi/fuzz/seeds -o gateway-rpi/fuzz/findings \
      -- gateway-rpi/build-fuzz/fuzz_decoder @@
# pass = fuzzer_stats shows saved_crashes:0 and saved_hangs:0
```

Sketch compile check (arduino-cli is installed user-locally in `~/.local/bin`):

```bash
~/.local/bin/arduino-cli compile --fqbn arduino:avr:uno --warnings all node-arduino/sensor_node
```

The sketch must produce zero warnings of its own (Arduino core warnings are
outside our control). Beware the Arduino builder's auto-generated prototypes:
functions taking user-defined types need explicit prototypes *after* the type
definition or the sketch will not compile.
