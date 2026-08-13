#!/usr/bin/env python3
"""Merge probe alert outputs (out/probe_*.jsonl) into web/public/data/alerts.json.

Each line in a probe jsonl is one alert JSON (event + flow features). The
merger enriches alerts with tool/category metadata (parsed from the Go rule
registry) and writes a single file the React alert center polls.

Usage:
  python3 frontend/collect_alerts.py [out/*.jsonl glob] [alerts.json]
"""

import glob
import json
import os
import re
import sys
from datetime import datetime, timezone

LAB = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RULES_DIR = os.path.join(LAB, "framework", "probe", "rules")
RULES_MAIN = os.path.join(LAB, "framework", "probe", "rules.go")
TOOLS_JSON = os.path.join(LAB, "frontend", "tools.json")
WEB_DATA = os.path.join(LAB, "web", "public", "data")


def build_event_map():
    """event -> {tool, tool_name, category, source} from rule registrations."""
    pairs = []
    for path in glob.glob(os.path.join(RULES_DIR, "*.go")):
        if os.path.basename(path) in ("rules.go", "helpers.go"):
            continue
        src = open(path, encoding="utf-8").read()
        names = re.findall(r'Name:\s*"([^"]+)"', src)
        scen = re.findall(r'Scenario:\s*"([^"]+)"', src)
        for n in names:
            pairs.append((n, scen[0] if scen else "?"))
    # aggregate / signal events emitted from the probe core
    main_src = open(RULES_MAIN, encoding="utf-8").read()
    for m in re.finditer(r'e\.emit\("([^"]+)"', main_src):
        pairs.append((m.group(1), "system"))
    pairs.append(("tls.ja3_signal", "system"))

    tools = json.load(open(TOOLS_JSON, encoding="utf-8"))["tools"]
    by_id = {t["id"]: t for t in tools}
    emap = {}
    for event, tool_id in pairs:
        t = by_id.get(tool_id)
        emap[event] = {
            "tool": tool_id,
            "tool_name": t["name"] if t else tool_id,
            "category": t["category"] if t else "system",
        }
    return emap


def collect(patterns):
    alerts = []
    for pat in patterns:
        for path in glob.glob(pat):
            with open(path, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        a = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if "event" not in a:
                        continue
                    alerts.append(a)
    alerts.sort(key=lambda a: a.get("ts", 0))
    return alerts


def main():
    pattern = sys.argv[1] if len(sys.argv) > 1 else os.path.join(LAB, "data", "alerts", "probe_*.jsonl")
    out = sys.argv[2] if len(sys.argv) > 2 else os.path.join(WEB_DATA, "alerts.json")
    emap = build_event_map()
    alerts = collect([pattern])
    total = len(alerts)
    # keep the most recent 2000 alerts for the dashboard
    recent = alerts[-2000:]
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        json.dump({
            "generated": datetime.now(timezone.utc).isoformat(),
            "source": pattern,
            "total": total,
            "shown": len(recent),
            "events": emap,
            "alerts": recent,
        }, f, ensure_ascii=False)
    print(f"alerts.json: {total} total, {len(recent)} shown -> {out}")


if __name__ == "__main__":
    main()
