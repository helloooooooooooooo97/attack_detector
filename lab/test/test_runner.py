#!/usr/bin/env python3
"""Scenario test runner: validate probe alerts against expected.json.

Usage:
  python3 test/test_runner.py                    # all scenarios in out/
  python3 test/test_runner.py behinder ligolo    # specific scenarios

For each scenario it checks out/probe_<name>.jsonl against
scenarios/<name>/expected.json (or scenario.json "expected").
"""

import collections
import json
import os
import sys

LAB = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load(path):
    with open(path) as f:
        return json.load(f)


def check_scenario(name):
    scenario = load(os.path.join(LAB, "scenarios", name, "scenario.json"))
    expected = scenario.get("expected", [])
    negative = scenario.get("negative", False)
    probe_file = os.path.join(LAB, "out", f"probe_{name}.jsonl")

    if not os.path.exists(probe_file):
        return name, "FAIL", f"missing {probe_file}"

    events = []
    with open(probe_file) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    counts = collections.Counter(e.get("event") for e in events)

    if negative:
        if counts:
            return name, "FAIL", f"negative scenario alerted: {dict(counts)}"
        return name, "PASS", "no alerts (negative baseline)"

    missing = []
    for req in expected:
        if counts.get(req["event"], 0) < req.get("min_count", 1):
            missing.append(f"{req['event']}(got {counts.get(req['event'], 0)}, need {req.get('min_count', 1)})")
    if missing:
        return name, "FAIL", "missing expected alerts: " + ", ".join(missing)
    detail = ", ".join(f"{k}={v}" for k, v in sorted(counts.items()))
    return name, "PASS", detail


def main():
    names = sys.argv[1:] or sorted(
        d for d in os.listdir(os.path.join(LAB, "scenarios"))
        if os.path.isdir(os.path.join(LAB, "scenarios", d))
    )
    print(f"{'scenario':<12} {'result':<6} detail")
    print("-" * 80)
    failed = 0
    for name in names:
        scenario_name, result, detail = check_scenario(name)
        print(f"{scenario_name:<12} {result:<6} {detail}")
        if result == "FAIL":
            failed += 1
    print("-" * 80)
    print(f"{len(names) - failed}/{len(names)} passed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
