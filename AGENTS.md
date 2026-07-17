# IoT-arduino-raspberryPI — Agent Instructions

Two-tier IoT telemetry pipeline: Arduino sensor node (C++) + Raspberry Pi gateway (C++17/CMake).
Each `appNN_*/` directory is a self-contained app. app01_cpp's design lives in
`app01_cpp/SSDLC_IoT_Sensor_Pipeline_Plan.md` — read it before touching app01 code; don't duplicate it here.

## Workflow: build each app in these steps, in order

1. **Plan doc first.** Before any code, write (or update) an SSDLC/PRD plan markdown in the app
   directory — requirements (FR/SR), user stories, STRIDE threat model, wire protocol, directory
   structure, test strategy. The agent drafts it; the human reviews before step 2 starts.
2. **Arduino sensor node.** C++ sketch under `node-arduino/` (arduino-cli or PlatformIO layout):
   sample sensors, frame readings per the plan's wire protocol, transmit over serial.
   No dynamic allocation in firmware (SR-5).
3. **Raspberry Pi gateway.** C++17 CMake app under `gateway-rpi/`: decode + validate frames,
   per-node state and quarantine, publish/aggregate. Must build and self-test on this dev machine —
   never require real hardware to verify logic.
4. **Full pipeline integration.** Wire node + gateway together behind the shared protocol; verify
   end-to-end with a Python frame simulator standing in for the Arduino (executable protocol spec,
   like the UDP test clients in the last-target-game repo).

## Invariants (all apps)

- The serial wire is untrusted input: validate size → CRC → ranges → sequence before anything
  touches application state. The gateway is the trust boundary.
- Wire structs are byte-identical between firmware and gateway (packed, little-endian, fixed size);
  guard with `static_assert(sizeof(...))` on both sides and update both together.
- SAST gate stays on: `-Wall -Wextra -Wpedantic -Werror -fanalyzer` in every CMake target.
  Fix findings; never suppress them to make a build pass.
- Every increment is verified by running something (self-test, simulator, build gate) — not by
  reading the code.

## Conventions

- Keep this file and CLAUDE.md short and universal; put app-specific rules in a nested
  `appNN_*/CLAUDE.md` scoped to that app.
- Build artifacts (`build/`, `bin/`, `obj/`, `.pio/`) never get committed — extend `.gitignore`
  when adding a new toolchain.
