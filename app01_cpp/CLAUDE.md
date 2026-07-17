# app01_cpp — app-specific rules

Design source of truth: `SSDLC_IoT_Sensor_Pipeline_Plan.md` (read before changing code).

## Wire contract

`SensorFrame` exists in two deliberately duplicated copies —
`gateway-rpi/src/Protocol.h` and `node-arduino/sensor_node/sensor_node.ino` —
plus the Python packer in `tools/frame_simulator.py` (`FRAME_FMT`). Any protocol
change updates all three in one commit; the `static_assert(sizeof == 16)` on
both C++ sides and the CRC known-answer test (`0x29B1` for `"123456789"`) are
the tripwires.

## Verify (all three must pass before claiming done)

```bash
cmake -S gateway-rpi -B gateway-rpi/build && cmake --build gateway-rpi/build  # SAST gate
gateway-rpi/build/gateway --selftest                                          # offline security tests
python3 tools/frame_simulator.py --gateway gateway-rpi/build/gateway          # protocol conformance
```

Sketch compile check (arduino-cli is installed user-locally in `~/.local/bin`):

```bash
~/.local/bin/arduino-cli compile --fqbn arduino:avr:uno --warnings all node-arduino/sensor_node
```

The sketch must produce zero warnings of its own (Arduino core warnings are
outside our control). Beware the Arduino builder's auto-generated prototypes:
functions taking user-defined types need explicit prototypes *after* the type
definition or the sketch will not compile.
