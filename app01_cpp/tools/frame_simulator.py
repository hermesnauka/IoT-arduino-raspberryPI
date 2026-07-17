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
FRAME_SIZE = 16


def crc16_ccitt(data: bytes) -> int:
    """CRC-16/CCITT-FALSE: poly 0x1021, init 0xFFFF, no reflect, xorout 0."""
    crc = 0xFFFF
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc


assert crc16_ccitt(b"123456789") == 0x29B1, "CRC known-answer test failed"


def frame(node_id, seq, temp_c=22.5, hum_pct=45.0, flags=0, reserved=0, corrupt=False):
    body = struct.pack(FRAME_FMT, MAGIC, node_id, flags, seq,
                       int(round(temp_c * 100)), int(round(hum_pct * 100)), reserved)
    crc = crc16_ccitt(body)
    if corrupt:
        crc ^= 0xFFFF
    out = body + struct.pack("<H", crc)
    assert len(out) == FRAME_SIZE
    return out


NODE_RE = re.compile(
    r"\[node (\d+)\] valid=(\d+) crc=(\d+) reserved=(\d+) range=(\d+) "
    r"replay=(\d+) rate=(\d+) qdrop=(\d+) quarantines=(\d+) lastSeq=(\d+)")
DEC_RE = re.compile(
    r"\[decoder\] bytesIn=(\d+) framesOk=(\d+) crcErrors=(\d+) resyncBytes=(\d+)")


def run_gateway(gateway, payload):
    proc = subprocess.run([gateway, "--read", "-"], input=payload,
                          capture_output=True, timeout=30)
    if proc.returncode != 0:
        raise AssertionError(f"gateway exited {proc.returncode}: {proc.stderr.decode()}")
    out = proc.stdout.decode()
    nodes = {}
    for m in NODE_RE.finditer(out):
        vals = list(map(int, m.groups()))
        nodes[vals[0]] = dict(zip(
            ["valid", "crc", "reserved", "range", "replay", "rate", "qdrop",
             "quarantines", "lastSeq"], vals[1:]))
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
                     scenario_garbage_resync, scenario_flood, scenario_garbage_flood):
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
