#!/usr/bin/env python3
"""
Offline Behinder detector for TLS-record + flow-level behavior.

Runs the four fingerprint dimensions measured in the lab against pcap files:
  R1  memory-shell pattern: many short-lived flows, one exchange each,
      ~13 TLS records, big request chunks, request > response
  R2  file-webshell pattern: one long-lived flow, many exchanges, constant
      8225B request chunks
  R3  JA3 signal: reported only (same stack as normal Java/OkHttp apps)

Usage: detect.py <pcap> [<pcap> ...]
"""

import os
import sys

import analyze


# Record sizes measured in the lab: 8192B okio chunk + TLS overhead = 8225B
BIG_RECORD_MIN = 8000
BIG_RECORD_MAX = 8500


def flow_features(c):
    exchanges = c["exchanges"]
    req_bytes = sum(e["req_bytes"] for e in exchanges)
    resp_bytes = sum(e["resp_bytes"] for e in exchanges)
    big_req = sum(
        1 for e in exchanges for s in e["req_sizes"] if s >= BIG_RECORD_MIN
    )
    chunks = sum(
        1
        for e in exchanges
        for s in e["req_sizes"]
        if BIG_RECORD_MIN <= s <= BIG_RECORD_MAX
    )
    records = sum(c["tls_records"].values())
    duration = (c["last"] - c["first"]) if c["first"] is not None else 0
    return {
        "conn": c["conn"],
        "first": c["first"],
        "exchanges": len(exchanges),
        "records": records,
        "req_bytes": req_bytes,
        "resp_bytes": resp_bytes,
        "big_req": big_req,
        "chunks_8225": chunks,
        "duration": duration,
    }


def r1_mem_shell(f):
    """Single-exchange short flows with big request chunks, req > resp."""
    return (
        f["exchanges"] == 1
        and 10 <= f["records"] <= 16
        and f["big_req"] >= 1
        and f["req_bytes"] > f["resp_bytes"]
        and f["duration"] < 2.5
    )


def r2_file_shell(f):
    """Long-lived reuse flow with constant 8225B request chunks."""
    return (
        f["exchanges"] >= 5
        and f["records"] >= 40
        and f["chunks_8225"] >= 5
        and f["req_bytes"] > f["resp_bytes"]
    )


def detect(path):
    conns, ja3s = analyze.analyze_capture(path)
    flows = [flow_features(c) for c in conns]
    hits = {"mem": [], "file": []}
    for f in flows:
        if r1_mem_shell(f):
            hits["mem"].append(f)
        if r2_file_shell(f):
            hits["file"].append(f)

    verdict = "CLEAN"
    reasons = []
    if len(hits["mem"]) >= 3:
        verdict = "DETECTED"
        reasons.append(
            f"memory-shell pattern: {len(hits['mem'])} short single-exchange flows"
        )
    if hits["file"]:
        verdict = "DETECTED"
        reasons.append(
            f"file-webshell pattern: {len(hits['file'])} long-lived reuse flow(s)"
        )

    return {
        "path": path,
        "verdict": verdict,
        "reasons": reasons,
        "flows": flows,
        "hits": hits,
        "ja3": sorted(set(ja3s)),
    }


def main():
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)

    print(f"{'file':<42} {'verdict':<9} notes")
    print("-" * 90)
    for path in sys.argv[1:]:
        r = detect(path)
        note = "; ".join(r["reasons"]) or f"flows={len(r['flows'])}, ja3={len(r['ja3'])}"
        print(f"{os.path.basename(path):<42} {r['verdict']:<9} {note}")

        # per-flow detail for hits
        for tag, fl in r["hits"].items():
            for f in fl:
                print(
                    f"    [{tag}] conn={f['conn']} exch={f['exchanges']} "
                    f"records={f['records']} req={f['req_bytes']}B "
                    f"resp={f['resp_bytes']}B big_req={f['big_req']} "
                    f"chunk8225={f['chunks_8225']} dur={f['duration']:.2f}s"
                )

        if r["ja3"] and r["verdict"] == "CLEAN":
            print(f"    [ja3-signal] matches Behinder JA3: {r['ja3'][0][:60]}...")


if __name__ == "__main__":
    main()
