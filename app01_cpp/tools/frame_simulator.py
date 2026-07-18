#!/usr/bin/env python3
"""Protocol conformance simulator for app01 (SSDLC plan Phase 4).

Stands in for the Arduino node: builds wire frames independently from the C++
code (executable specification of plan §2.2), feeds hostile and benign byte
streams to `gateway --read -` over stdin, and asserts the gateway's decoder
and per-node counters. Exit 0 = all scenarios pass.

Usage: python3 frame_simulator.py [--gateway PATH]
"""

import argparse
import random
import re
import struct
import subprocess
import sys

MAGIC = 0xA55A
FRAME_FMT = "<HBBIhHH"  # magic, nodeId, flags, sequence, tempCx100, humX100, reserved
FRAME_SIZE = 24
FLAG_VERSION_REPORT = 0x02  # Protocol.h kFlagVersionReport (Plan Phase 5, stretch)

# Fixed test-only key (also baked into gateway --selftest — never a real key).
TEST_KEY = bytes(range(16))


def crc16_ccitt(data: bytes) -> int:
    """CRC-16/CCITT-FALSE: poly 0x1021, init 0xFFFF, no reflect, xorout 0."""
    crc = 0xFFFF
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc


assert crc16_ccitt(b"123456789") == 0x29B1, "CRC known-answer test failed"


def siphash24(key: bytes, data: bytes) -> int:
    """SipHash-2-4 (SR-6): independent Python mirror of gateway SipHash.h."""
    mask = 0xFFFFFFFFFFFFFFFF

    def rotl(x, b):
        return ((x << b) | (x >> (64 - b))) & mask

    k0, k1 = struct.unpack("<QQ", key)
    v0 = 0x736F6D6570736575 ^ k0
    v1 = 0x646F72616E646F6D ^ k1
    v2 = 0x6C7967656E657261 ^ k0
    v3 = 0x7465646279746573 ^ k1

    def sipround():
        nonlocal v0, v1, v2, v3
        v0 = (v0 + v1) & mask; v1 = rotl(v1, 13); v1 ^= v0; v0 = rotl(v0, 32)
        v2 = (v2 + v3) & mask; v3 = rotl(v3, 16); v3 ^= v2
        v0 = (v0 + v3) & mask; v3 = rotl(v3, 21); v3 ^= v0
        v2 = (v2 + v1) & mask; v1 = rotl(v1, 17); v1 ^= v2; v2 = rotl(v2, 32)

    full = len(data) & ~7
    for off in range(0, full, 8):
        m = struct.unpack_from("<Q", data, off)[0]
        v3 ^= m
        sipround(); sipround()
        v0 ^= m
    last = (len(data) & 0xFF) << 56
    for i, byte in enumerate(data[full:]):
        last |= byte << (8 * i)
    v3 ^= last
    sipround(); sipround()
    v0 ^= last
    v2 ^= 0xFF
    sipround(); sipround(); sipround(); sipround()
    return v0 ^ v1 ^ v2 ^ v3


# Reference vectors_sip64 known-answer tests (key 00…0f), mirroring the
# gateway --selftest tripwire: empty input + 15-byte partial-block input.
assert siphash24(TEST_KEY, b"") == 0x726FDB47DD0E0E31, "SipHash KAT (empty) failed"
assert siphash24(TEST_KEY, bytes(range(15))) == 0xA129CA6149BE45E5, "SipHash KAT (15B) failed"


def frame(node_id, seq, temp_c=22.5, hum_pct=45.0, flags=0, reserved=0, corrupt=False,
          key=None, corrupt_tag=False):
    body = struct.pack(FRAME_FMT, MAGIC, node_id, flags, seq,
                       int(round(temp_c * 100)), int(round(hum_pct * 100)), reserved)
    crc = crc16_ccitt(body)
    if corrupt:
        crc ^= 0xFFFF
    tag = siphash24(key, body) if key else 0
    if corrupt_tag:
        tag ^= 1
    out = body + struct.pack("<HQ", crc, tag)
    assert len(out) == FRAME_SIZE
    return out


def version_frame(node_id, seq, major=1, minor=0, patch=0, key=None):
    """Flags-extension frame: temp/hum fields carry a firmware version."""
    packed_temp = ((major & 0xFF) << 8) | (minor & 0xFF)
    temp_raw = struct.unpack("<h", struct.pack("<H", packed_temp))[0]
    body = struct.pack(FRAME_FMT, MAGIC, node_id, FLAG_VERSION_REPORT, seq,
                       temp_raw, patch & 0xFF, 0)
    crc = crc16_ccitt(body)
    tag = siphash24(key, body) if key else 0
    out = body + struct.pack("<HQ", crc, tag)
    assert len(out) == FRAME_SIZE
    return out


NODE_RE = re.compile(
    r"\[node (\d+)\] valid=(\d+) crc=(\d+) auth=(\d+) reserved=(\d+) range=(\d+) "
    r"replay=(\d+) rate=(\d+) qdrop=(\d+) quarantines=(\d+) fw=(\d+) lastSeq=(\d+)")
DEC_RE = re.compile(
    r"\[decoder\] bytesIn=(\d+) framesOk=(\d+) crcErrors=(\d+) resyncBytes=(\d+)")


def run_gateway(gateway, payload, extra_args=()):
    proc = subprocess.run([gateway, "--read", "-", *extra_args], input=payload,
                          capture_output=True, timeout=30)
    if proc.returncode != 0:
        raise AssertionError(f"gateway exited {proc.returncode}: {proc.stderr.decode()}")
    out = proc.stdout.decode()
    nodes = {}
    for m in NODE_RE.finditer(out):
        vals = list(map(int, m.groups()))
        nodes[vals[0]] = dict(zip(
            ["valid", "crc", "auth", "reserved", "range", "replay", "rate", "qdrop",
             "quarantines", "fw", "lastSeq"], vals[1:]))
    dec = DEC_RE.search(out)
    decoder = dict(zip(["bytesIn", "framesOk", "crcErrors", "resyncBytes"],
                       map(int, dec.groups()))) if dec else {}
    return nodes, decoder, proc.stderr.decode()


FAILURES = []


def check(scenario, cond, detail):
    status = "ok" if cond else "FAIL"
    print(f"  [{status}] {detail}")
    if not cond:
        FAILURES.append(f"{scenario}: {detail}")


def scenario_valid_stream(gw):
    print("scenario: valid stream (FR-1/FR-2)")
    payload = b"".join(frame(1, s, 20 + s * 0.1) for s in range(1, 21))
    nodes, dec, _ = run_gateway(gw, payload)
    check("valid_stream", nodes.get(1, {}).get("valid") == 20, "20/20 frames accepted")
    check("valid_stream", dec["framesOk"] == 20 and dec["crcErrors"] == 0,
          "decoder clean")


def scenario_multi_node(gw):
    print("scenario: interleaved multi-node (FR-4)")
    payload = b"".join(frame(n, s) for s in range(1, 11) for n in (1, 2, 3, 4))
    nodes, _, _ = run_gateway(gw, payload)
    ok = all(nodes.get(n, {}).get("valid") == 10 for n in (1, 2, 3, 4))
    check("multi_node", ok, "4 nodes x 10 frames each tracked independently")


def scenario_bad_crc(gw):
    print("scenario: corrupted frames (SR-1, User Story 1)")
    payload = (frame(1, 1) + frame(1, 2, corrupt=True) + frame(1, 3)
               + frame(1, 4, corrupt=True) + frame(1, 5))
    nodes, dec, _ = run_gateway(gw, payload)
    n1 = nodes.get(1, {})
    check("bad_crc", n1.get("valid") == 3, "valid frames still accepted")
    check("bad_crc", n1.get("crc") == 2 and dec["crcErrors"] == 2,
          "both corrupted frames counted, none accepted")


def scenario_out_of_range(gw):
    print("scenario: implausible values (SR-1)")
    payload = (frame(1, 1) + frame(1, 2, temp_c=300.0) + frame(1, 3, hum_pct=150.0)
               + frame(1, 4))
    nodes, _, err = run_gateway(gw, payload)
    n1 = nodes.get(1, {})
    check("range", n1.get("valid") == 2 and n1.get("range") == 2,
          "300C and 150%RH frames dropped and counted")
    check("range", "out-of-range" in err, "security alert emitted on stderr")


def scenario_reserved(gw):
    print("scenario: reserved-nonzero (forward-compat gate)")
    payload = frame(1, 1) + frame(1, 2, reserved=0xBEEF) + frame(1, 3)
    nodes, _, _ = run_gateway(gw, payload)
    n1 = nodes.get(1, {})
    check("reserved", n1.get("valid") == 2 and n1.get("reserved") == 1,
          "reserved!=0 frame dropped and counted")


def scenario_replay(gw):
    print("scenario: replay/stale sequence (SR-2)")
    payload = (frame(1, 1) + frame(1, 2) + frame(1, 2)  # duplicate
               + frame(1, 1)                            # stale
               + frame(1, 3))
    nodes, _, _ = run_gateway(gw, payload)
    n1 = nodes.get(1, {})
    check("replay", n1.get("valid") == 3 and n1.get("replay") == 2,
          "duplicate and stale sequences ignored, lastSeq intact")
    check("replay", n1.get("lastSeq") == 3, "sequence state uncorrupted")


def scenario_garbage_resync(gw):
    print("scenario: garbage between frames (framing resync)")
    rng = random.Random(1337)
    junk = bytes(rng.randrange(256) for _ in range(97))
    payload = frame(1, 1) + junk + frame(1, 2) + junk + frame(1, 3)
    nodes, _, _ = run_gateway(gw, payload)
    check("resync", nodes.get(1, {}).get("valid") == 3,
          "all real frames recovered around junk")


def scenario_flood(gw):
    print("scenario: single-node flood (SR-3/SR-4 DoS containment)")
    flood = b"".join(frame(9, s) for s in range(1, 3001))
    victim = b"".join(frame(2, s) for s in range(1, 11))
    nodes, _, err = run_gateway(gw, flood + victim)
    n9, n2 = nodes.get(9, {}), nodes.get(2, {})
    check("flood", n2.get("valid") == 10, "well-behaved node unaffected by flood")
    check("flood", n9.get("valid", 0) < 3000, "flooding node throttled")
    check("flood", n9.get("rate", 0) > 0 and n9.get("quarantines", 0) >= 1,
          "flood rate-limited then quarantined")
    check("flood", err.count("quarantined after error streak") == 1,
          "exactly one quarantine alert (no log storm)")


def scenario_firmware_version(gw):
    print("scenario: firmware version report (Plan Phase 5, stretch)")
    # major=200 packs a temp field well outside the sensor range, proving the
    # range gate is actually skipped for version frames, not just coincidentally passing.
    payload = version_frame(1, 1, major=200, minor=1, patch=5) + frame(1, 2) + frame(1, 3)
    nodes, dec, _ = run_gateway(gw, payload)
    n1 = nodes.get(1, {})
    check("firmware", n1.get("valid") == 2, "version frame not counted as a sensor reading")
    check("firmware", n1.get("fw") == 1, "version frame counted separately")
    check("firmware", n1.get("range") == 0, "version frame's packed fields don't trip SR-1 range gate")
    check("firmware", dec["framesOk"] == 3, "all three frames decode Ok")


def scenario_aggregate_publish(gw):
    print("scenario: periodic aggregate publishing (FR-3)")
    # Node 1: three readings, a version report (carries no sensor payload, so
    # it must not advance the publish interval), then the reading that
    # completes the interval of 4 and triggers exactly one publish.
    payload = (frame(1, 1, 20.0) + frame(1, 2, 21.0) + frame(1, 3, 22.0) +
               version_frame(1, 4) + frame(1, 5, 23.0))
    proc = subprocess.run([gw, "--read", "-", "--aggregate", "4"], input=payload,
                          capture_output=True, timeout=30)
    if proc.returncode != 0:
        raise AssertionError(f"gateway exited {proc.returncode}: {proc.stderr.decode()}")
    agg = [l for l in proc.stdout.decode().splitlines() if l.startswith("[aggregate]")]
    check("aggregate", len(agg) == 1,
          "one publish after 4 accepted sensor readings (version frame excluded)")
    line = agg[0] if agg else ""
    check("aggregate", "node 001 n=4" in line and "tempMin=20" in line and
          "tempMax=23" in line and "tempAvg=21.5" in line,
          "min/max/avg computed over the rolling window")

    # Interleaved nodes: the interval counts accepted readings bus-wide, and
    # each publish reports every node with a non-empty window.
    payload = b"".join(frame(n, s, 20.0 + n) for s in (1, 2, 3, 4) for n in (1, 2))
    proc = subprocess.run([gw, "--read", "-", "--aggregate", "4"], input=payload,
                          capture_output=True, timeout=30)
    if proc.returncode != 0:
        raise AssertionError(f"gateway exited {proc.returncode}: {proc.stderr.decode()}")
    agg = [l for l in proc.stdout.decode().splitlines() if l.startswith("[aggregate]")]
    check("aggregate", len(agg) == 4 and
          sum("node 001" in l for l in agg) == 2 and
          sum("node 002" in l for l in agg) == 2,
          "8 interleaved frames -> two publishes, each covering both nodes")


def scenario_metrics_export(gw):
    print("scenario: Prometheus metrics export (Plan Phase 5, stretch)")
    import tempfile
    import os as _os
    payload = frame(1, 1) + frame(1, 2) + frame(1, 3) + frame(1, 4, corrupt=True)
    with tempfile.TemporaryDirectory() as d:
        path = _os.path.join(d, "gateway.prom")
        proc = subprocess.run([gw, "--read", "-", "--metrics", path], input=payload,
                              capture_output=True, timeout=30)
        if proc.returncode != 0:
            raise AssertionError(f"gateway exited {proc.returncode}: {proc.stderr.decode()}")
        text = open(path).read()
    check("metrics", 'iot_gateway_node_valid_total{node="1"} 3' in text,
          "valid counter exported")
    check("metrics", 'iot_gateway_node_crc_errors_total{node="1"} 1' in text,
          "crc error counter exported")
    check("metrics", "# TYPE iot_gateway_node_quarantined gauge" in text,
          "gauge metric type declared")


def scenario_auth(gw):
    print("scenario: frame authentication (SR-6, plan §2.3)")
    import tempfile
    import os as _os
    with tempfile.TemporaryDirectory() as d:
        keyfile = _os.path.join(d, "keys.txt")
        with open(keyfile, "w") as f:
            f.write("# test keys\n1:" + TEST_KEY.hex() + "\n")
        payload = (
            frame(1, 1, key=TEST_KEY)                          # signed → accepted
            + frame(1, 2, key=TEST_KEY, corrupt_tag=True)      # forged tag → dropped
            + frame(1, 3, temp_c=30.0)                         # valid CRC, no tag → dropped
            + frame(2, 1)                                      # no key entry → dropped
            + frame(1, 4, key=TEST_KEY)                        # signed → accepted
        )
        nodes, _, _ = run_gateway(gw, payload, extra_args=("--keys", keyfile))
    n1, n2 = nodes.get(1, {}), nodes.get(2, {})
    check("auth", n1.get("valid") == 2, "correctly signed frames accepted")
    check("auth", n1.get("auth") == 2, "forged-tag and untagged frames dropped and counted")
    check("auth", n2.get("auth") == 1 and n2.get("valid", 0) == 0,
          "node without a key entry fails closed")
    check("auth", n1.get("lastSeq") == 4, "sequence state fed only by authentic frames")
    # Auth off (no --keys): the same zero-tag frame is accepted (optional mode).
    nodes, _, _ = run_gateway(gw, frame(3, 1))
    check("auth", nodes.get(3, {}).get("valid") == 1,
          "zero-tag frame accepted when auth is off")


def scenario_garbage_flood(gw):
    print("scenario: 64 KiB random flood (fuzz — decoder must survive)")
    rng = random.Random(0xC0FFEE)
    payload = bytes(rng.randrange(256) for _ in range(65536))
    nodes, dec, _ = run_gateway(gw, payload)  # nonzero exit would raise
    check("fuzz", dec["framesOk"] == 0, "no garbage accepted as a frame")
    check("fuzz", dec["bytesIn"] == 65536, "all bytes consumed without crash")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--gateway", default="gateway-rpi/build/gateway")
    gw = ap.parse_args().gateway
    for scenario in (scenario_valid_stream, scenario_multi_node, scenario_bad_crc,
                     scenario_out_of_range, scenario_reserved, scenario_replay,
                     scenario_garbage_resync, scenario_flood, scenario_garbage_flood,
                     scenario_firmware_version, scenario_aggregate_publish,
                     scenario_metrics_export, scenario_auth):
        scenario(gw)
    if FAILURES:
        print(f"\n{len(FAILURES)} scenario check(s) FAILED:")
        for f in FAILURES:
            print(f"  - {f}")
        return 1
    print("\nall protocol conformance scenarios passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
