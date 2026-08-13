#!/usr/bin/env python3
"""Alert center backend: keeps web/public/data/alerts.json fresh and serves
the dashboard.

Usage (lab, all scenario outputs):
  python3 frontend/alert_server.py --port 4174

Usage (production, live probe output file):
  python3 frontend/alert_server.py --source /var/log/tflab/alerts.jsonl --port 4174

The React app polls ./data/alerts.json every few seconds; this server
re-collects from the source on the same cadence and serves the static web
dir, so the alert center works without the vite dev server.
"""

import argparse
import glob
import http.server
import os
import socketserver
import subprocess
import sys
import threading
import time

LAB = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
COLLECT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "collect_alerts.py")
WEB = os.path.join(LAB, "web", "public")
DIST = os.path.join(LAB, "web", "dist", "data")


def refresh(source, interval):
    last = 0.0
    while True:
        try:
            st = os.stat(source) if os.path.isfile(source) else max(
                (os.stat(p).st_mtime for p in glob.glob(source)), default=0)
            if st != last:
                subprocess.run([sys.executable, COLLECT, source,
                                os.path.join(WEB, "data", "alerts.json")],
                               cwd=LAB, check=False)
                os.makedirs(DIST, exist_ok=True)
                subprocess.run([sys.executable, COLLECT, source,
                                os.path.join(DIST, "alerts.json")],
                               cwd=LAB, check=False)
                last = st
        except Exception as e:  # noqa: BLE001
            print(f"[alert_server] refresh failed: {e}", file=sys.stderr)
        time.sleep(interval)


class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=WEB, **kwargs)

    def end_headers(self):
        self.send_header("Cache-Control", "no-store")
        super().end_headers()

    def log_message(self, *args):
        pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--source", default=os.path.join(LAB, "data", "alerts", "probe_*.jsonl"))
    ap.add_argument("--port", type=int, default=4174)
    ap.add_argument("--interval", type=float, default=3.0)
    args = ap.parse_args()

    threading.Thread(target=refresh, args=(args.source, args.interval),
                     daemon=True).start()
    with socketserver.ThreadingTCPServer(("", args.port), Handler) as httpd:
        print(f"[alert_server] dashboard on http://localhost:{args.port} "
              f"(source={args.source})", flush=True)
        httpd.serve_forever()


if __name__ == "__main__":
    main()
