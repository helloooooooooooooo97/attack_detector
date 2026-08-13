#!/usr/bin/env python3
"""Batch generator for the final HTTP(S) beacon tool batch.

Produces, for each tool spec:
  - framework/drivers/beacon/profiles/<tool>.json
  - scenarios/<tool>/{scenario.json, expected.json, run.sh}
  - framework/probe/rules/<tool>.go
  - TLS certs (for https profiles)
"""

import json
import os
import subprocess

LAB = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
PROF_DIR = os.path.join(LAB, "framework", "drivers", "beacon", "profiles")
RULES_DIR = os.path.join(LAB, "framework", "probe", "rules")
SCEN_DIR = os.path.join(LAB, "scenarios")


def spec(tool, category, transport, host, port, path, event, interval, jitter,
         req, resp, note, ua=None, kind="short", params=None, keep_alive=False,
         phase2_interval=None):
    return dict(tool=tool, category=category, transport=transport, host=host,
                port=port, path=path, event=event, interval=interval,
                jitter=jitter, req=req, resp=resp, note=note, ua=ua,
                kind=kind, params=params or [["data", "b64"]],
                keep_alive=keep_alive, phase2_interval=phase2_interval)


SPECS = [
    # ---- webshell ----
    spec("vagent", "webshell", "https", "vagent-c2.local", 8460, "/vagent/check",
         "vagent.heartbeat", 15, 0.2, [300, 600], [100, 300],
         "注入型内存马加密通信（闭源，HTTPS 长连接周期小包心跳，协议驱动仿真）",
         ua="Mozilla/5.0 (Windows NT 10.0; Win64; x64)", kind="long", keep_alive=True),
    # ---- c2 ----
    spec("evilox", "c2", "https", "evilox-c2.local", 8461, "/api/checkin",
         "evilox.checkin", 20, 0.2, [400, 800], [200, 500],
         "macOS 后渗透框架（agent 仅 macOS，HTTPS 周期 checkin + JXA 载荷，UA 伪装 Mac 浏览器，协议驱动仿真）",
         ua="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15"),
    spec("octopus", "c2", "http", "127.0.0.1", 8084, "/api/v1/beacon",
         "octopus.beacon", 15, 0.2, [300, 700], [300, 700],
         "Go C2，多协议通信（PowerShell agent 仅 Windows，HTTP beacon + 加密 JSON 载荷，协议驱动仿真）",
         ua="Mozilla/5.0 (Windows NT 10.0; Win64; x64)"),
    # ---- rat ----
    spec("sparkrat", "rat", "http", "127.0.0.1", 8085, "/spark/check",
         "sparkrat.beacon", 10, 0.2, [300, 600], [200, 500],
         "远控木马（闭源，HTTP 周期上线心跳，固定 UA/URL，协议驱动仿真）",
         ua="Mozilla/5.0 (Windows NT 6.1; WOW64)"),
    spec("ksrat", "rat", "http", "127.0.0.1", 8086, "/ks/login",
         "ksrat.beacon", 20, 0.15, [400, 800], [200, 400],
         "海莲花使用的远控木马（闭源，HTTP POST 分钟级周期回连，固定 UA/URL，实验室 20s，协议驱动仿真）",
         ua="Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1)"),
    spec("loki", "rat", "http", "127.0.0.1", 8087, "/loki/status",
         "loki.beacon", 15, 0.2, [300, 700], [200, 500],
         "远控工具（闭源，HTTP 周期回连短流 + 心跳节奏，协议驱动仿真）",
         ua="Mozilla/5.0 (Windows NT 10.0; Win64; x64)"),
    spec("zloader", "rat", "https", "zloader-c2.local", 8462, "/api/module",
         "zloader.beacon", 15, 0.2, [400, 700], [800, 1500],
         "银行木马家族（闭源，HTTPS 周期 C2 心跳 + 模块下载，响应显著大于请求，协议驱动仿真）",
         ua="Mozilla/5.0 (Windows NT 10.0; Win64; x64)"),
    spec("wmrat", "rat", "http", "127.0.0.1", 8088, "/wm/update",
         "wmrat.beacon", 12, 0.2, [300, 600], [150, 400],
         "蔓灵花组织远控木马（闭源，HTTP POST 周期回连 + 3DES 等自定义加密，协议驱动仿真）",
         ua="Mozilla/5.0 (Windows NT 6.1; Win64; x64)"),
    spec("badnews", "rat", "http", "127.0.0.1", 8089, "/news/check",
         "badnews.beacon", 20, 0.15, [400, 800], [200, 400],
         "白象组织木马（闭源，HTTP 分钟级周期回连，固定 URL/UA，实验室 20s，协议驱动仿真）",
         ua="Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)"),
    spec("perfspyrat", "rat", "http", "127.0.0.1", 8090, "/perf/report",
         "perfspyrat.beacon", 10, 0.2, [250, 550], [150, 400],
         "海莲花远控木马（闭源，HTTP 周期回连，短流节奏固定，协议驱动仿真）",
         ua="Mozilla/5.0 (Windows NT 10.0; Win64; x64)"),
    spec("fatalrat", "rat", "http", "127.0.0.1", 8091, "/fatal/check",
         "fatalrat.beacon", 12, 0.15, [300, 600], [200, 450],
         "针对中国的远控木马（闭源，HTTP 短流周期回连，心跳间隔稳定，协议驱动仿真）",
         ua="Mozilla/5.0 (Windows NT 6.1; Win64; x64)"),
    # ---- apt ----
    spec("sidewinder", "apt", "https", "sidewinder-c2.local", 8463, "/c2",
         "sidewinder.c2_phase", 12, 0.1, [400, 700], [300, 600],
         "响尾蛇 APT（闭源，投递期 HTTP 下载突发 + C2 HTTPS 周期短流，多阶段协议驱动仿真）",
         ua="Mozilla/5.0 (Windows NT 10.0; Win64; x64)", kind="multiphase",
         phase2_interval=12),
    spec("aptc60", "apt", "https", "pan.aptc60.local", 8464, "/api/list",
         "aptc60.poll", 20, 0.2, [400, 800], [400, 900],
         "伪猎者 APT-C-60（闭源，借道云盘/网盘 HTTPS 加密 C2，周期轮询，协议驱动仿真）",
         ua="Mozilla/5.0 (Windows NT 10.0; Win64; x64)"),
    spec("aptc68", "apt", "https", "aptc68-c2.local", 8465, "/checkin",
         "aptc68.beacon", 15, 0.2, [400, 700], [300, 600],
         "寄生虫 APT-C-68（闭源，多阶段投递 + HTTPS 加密回连周期心跳，协议驱动仿真）",
         ua="Mozilla/5.0 (Windows NT 6.1; Win64; x64)"),
    spec("hemao", "apt", "https", "hemao-c2.local", 8466, "/status",
         "hemao.beacon", 15, 0.15, [350, 650], [250, 500],
         "黑猫团伙（闭源，HTTPS 加密回连周期心跳，UA/URL 固定，协议驱动仿真）",
         ua="Mozilla/5.0 (Windows NT 10.0; Win64; x64)"),
    spec("lazarus", "apt", "https", "lazarus-c2.local", 8467, "/api/beacon",
         "lazarus.beacon", 25, 0.3, [500, 900], [300, 600],
         "Lazarus（闭源，木马化软件投递 + HTTPS 加密 C2 回连，beacon 周期+抖动，协议驱动仿真）",
         ua="Mozilla/5.0 (Windows NT 10.0; Win64; x64)"),
    spec("apt29", "apt", "https", "apt29-c2.local", 8468, "/load",
         "apt29.beacon", 20, 0.25, [500, 900], [300, 700],
         "APT29（闭源，beacon 型 HTTPS 回连，周期+抖动，载荷加密，协议驱动仿真）",
         ua="Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1)"),
    spec("oilrig", "apt", "http", "127.0.0.1", 8093, "/ps/run",
         "oilrig.beacon", 18, 0.2, [400, 800], [200, 500],
         "OilRig（闭源，PowerShell 后门 HTTP(S) 周期回连 + DNS 隧道备用，协议驱动仿真）",
         ua="Mozilla/5.0 (Windows NT 6.1; Win64; x64)"),
    spec("donot", "apt", "https", "donot-c2.local", 8469, "/c2",
         "donot.c2_phase", 14, 0.1, [400, 700], [300, 600],
         "Donot（闭源，多阶段 HTTP(S) 通信，RC4 等加密载荷，URL/UA 随阶段变化，多阶段协议驱动仿真）",
         ua="Mozilla/5.0 (Windows NT 10.0; Win64; x64)", kind="multiphase",
         phase2_interval=14),
    spec("ghostwriter", "apt", "https", "drive.ghostwriter.local", 8470, "/files",
         "ghostwriter.poll", 22, 0.2, [400, 800], [500, 1000],
         "Ghostwriter（闭源，借道云存储 HTTPS 加密 C2，周期轮询，载荷伪装文件，协议驱动仿真）",
         ua="Mozilla/5.0 (Windows NT 10.0; Win64; x64)"),
]


def duration_for(s):
    if s["kind"] == "multiphase":
        return 80
    if s["kind"] == "long":
        return int(s["interval"] * 4 + 20)
    return int(s["interval"] * 3 + 25)


def gen_profile(s):
    p = {
        "name": s["tool"], "transport": s["transport"], "host": s["host"],
        "port": s["port"], "method": "POST", "path": s["path"],
        "params": s["params"], "headers": {"User-Agent": s["ua"]},
        "interval": s["interval"], "jitter": s["jitter"],
        "req_size": s["req"], "resp_size": s["resp"],
        "keep_alive": s["keep_alive"], "duration": duration_for(s),
        "note": s["note"],
    }
    if s["kind"] == "multiphase":
        p["mode"] = "multiphase"
        p["port"] = 8092 if s["tool"] == "sidewinder" else 8094
        p["transport"] = "http"
        p["host"] = "127.0.0.1"
        p["phases"] = [
            {"phase": "delivery", "mode": "burst", "transport": "http",
             "port": p["port"], "path": "/drop" if s["tool"] == "sidewinder" else "/push",
             "params": [["p", "b64"]], "burst_n": 4, "burst_gap": 0.5,
             "idle_gap": 8.0, "req_size": [700, 1400], "resp_size": [100, 300],
             "duration": 25},
            {"phase": "c2", "transport": "https", "host": s["host"],
             "port": s["port"], "path": s["path"], "params": [["e", "b64"]],
             "interval": s["phase2_interval"], "jitter": s["jitter"],
             "req_size": s["req"], "resp_size": s["resp"], "keep_alive": True,
             "duration": 55},
        ]
    return p


def gen_rule(s):
    ev = s["event"]
    if s["kind"] == "multiphase":
        body = (
            f'\t\t\treturn f.TLSDetected &&\n'
            f'\t\t\t\tf.ServerName == "{s["host"]}" &&\n'
            f'\t\t\t\tf.Duration > 20 &&\n'
            f'\t\t\t\tf.RawIntervalC >= {max(6, s["phase2_interval"] - 5)} && f.RawIntervalC <= {s["phase2_interval"] + 8} &&\n'
            f'\t\t\t\tf.RawCBytes >= 1200, ""'
        )
    elif s["kind"] == "long":
        lo, hi = max(6, s["interval"] - 5), s["interval"] + 8
        body = (
            f'\t\t\treturn f.TLSDetected &&\n'
            f'\t\t\t\tf.ServerName == "{s["host"]}" &&\n'
            f'\t\t\t\tf.Duration > 30 &&\n'
            f'\t\t\t\tf.RawIntervalC >= {lo} && f.RawIntervalC <= {hi} &&\n'
            f'\t\t\t\tf.RawCBytes >= 1200, ""'
        )
    else:
        lo, hi = max(4, int(s["interval"] * 0.6)), int(s["interval"] * 1.7)
        if s["transport"] == "https":
            body = (
                f'\t\t\treturn f.TLSDetected &&\n'
                f'\t\t\t\tf.ServerName == "{s["host"]}" &&\n'
                f'\t\t\t\tf.Duration < 8 &&\n'
                f'\t\t\t\tf.PeerGap >= {lo} && f.PeerGap <= {hi}, ""'
            )
        else:
            body = (
                f'\t\t\treturn !f.TLSDetected &&\n'
                f'\t\t\t\tstrings.Contains(f.RawClient, "POST {s["path"]}") &&\n'
                f'\t\t\t\tf.Duration < 4 &&\n'
                f'\t\t\t\tf.PeerGap >= {lo} && f.PeerGap <= {hi}, ""'
            )
    imports = 'import "strings"\n\n' if s["transport"] == "http" and s["kind"] != "multiphase" else ""
    return (
        f'package rules\n\n'
        f'{imports}'
        f'func init() {{\n'
        f'\tRegister(Rule{{\n'
        f'\t\tName:     "{ev}",\n'
        f'\t\tScenario: "{s["tool"]}",\n'
        f'\t\tMatch: func(f Features) (bool, string) {{\n'
        f'{body}\n'
        f'\t\t}},\n'
        f'\t}})\n'
        f'}}\n'
    )


def gen_scenario(s):
    dur = duration_for(s) + 12
    filters = []
    ports = [s["port"]]
    if s["kind"] == "multiphase":
        ports.append(8092 if s["tool"] == "sidewinder" else 8094)
    filters = " or ".join(f"tcp port {p}" for p in sorted(set(ports)))
    scenario = {
        "name": s["tool"],
        "description": f"{s['note'].split('（')[0]}（{s['category']}，协议驱动仿真）",
        "image": "behinder-lab",
        "duration": dur,
        "capture_filter": filters,
        "probe_args": f"-json -ja3=false -idle 15 -scenario {s['tool']} -debug",
        "expected": [{"event": s["event"], "min_count": 1 if s["kind"] in ("long", "multiphase") else 2}],
        "negative": False,
    }
    expected = {
        "description": f"{s['tool']} 金标准（{s['category']} 类）",
        "events": [{"event": s["event"], "min_count": 1 if s["kind"] in ("long", "multiphase") else 2}],
        "features_note": s["note"],
    }
    return scenario, expected


def main():
    for s in SPECS:
        tool = s["tool"]
        prof = gen_profile(s)
        with open(os.path.join(PROF_DIR, f"{tool}.json"), "w") as f:
            json.dump(prof, f, ensure_ascii=False, indent=2)
        with open(os.path.join(RULES_DIR, f"{tool}.go"), "w") as f:
            f.write(gen_rule(s))
        scenario, expected = gen_scenario(s)
        d = os.path.join(SCEN_DIR, tool)
        os.makedirs(os.path.join(d, "assets"), exist_ok=True)
        with open(os.path.join(d, "scenario.json"), "w") as f:
            json.dump(scenario, f, ensure_ascii=False, indent=2)
        with open(os.path.join(d, "expected.json"), "w") as f:
            json.dump(expected, f, ensure_ascii=False, indent=2)
        with open(os.path.join(d, "run.sh"), "w") as f:
            f.write(f"#!/bin/bash\nexec bash /lab/src/framework/harness/run_beacon_scenario.sh {tool}\n")
        os.chmod(os.path.join(d, "run.sh"), 0o755)
        if s["transport"] == "https":
            subprocess.run(
                ["openssl", "req", "-x509", "-newkey", "rsa:2048",
                 "-keyout", os.path.join(d, "assets", f"{tool}_key.pem"),
                 "-out", os.path.join(d, "assets", f"{tool}_cert.pem"),
                 "-days", "30", "-nodes", "-subj", f"/CN={s['host']}",
                 "-addext", f"subjectAltName=DNS:{s['host']}"],
                check=True, capture_output=True)
        print(f"generated {tool} (kind={s['kind']}, port={s['port']})")


if __name__ == "__main__":
    main()
