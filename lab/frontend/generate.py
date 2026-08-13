#!/usr/bin/env python3
"""
Generate the TFLab frontend:
  1. analyze integrated scenarios' pcap files -> chart data
  2. render SVG charts (matplotlib, offline, no CDN)
  3. render index.html (tool list + attack cards)

Usage: python3 frontend/generate.py
"""

import base64
import io
import json
import os
import sys
from collections import Counter, defaultdict

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

LAB = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(LAB, "framework"))
import analyze

FE = os.path.dirname(os.path.abspath(__file__))
OUT_DIR = os.path.join(FE, "out")
CHART_DIR = os.path.join(FE, "assets", "charts")
WEB_DATA = os.path.join(FE, "..", "web", "public", "data")
os.makedirs(CHART_DIR, exist_ok=True)
os.makedirs(OUT_DIR, exist_ok=True)
os.makedirs(WEB_DATA, exist_ok=True)


def scenario_pcap(name, port):
    path = os.path.join(LAB, "out", f"cap_{name}.pcap")
    if not os.path.exists(path):
        return None
    conns = defaultdict(lambda: {"segments": {"C": [], "S": []}, "first": None, "last": None})
    for ts, data, lt in analyze.read_pcap(path):
        pkt = analyze.parse_ip_tcp(data, lt)
        if pkt is None:
            continue
        src, dst, sport, dport, flags, payload = pkt
        if sport == port or dport == port:
            key = frozenset(((src, sport), (dst, dport)))
            c = conns[key]
            if c["first"] is None:
                c["first"] = ts
            c["last"] = ts
            d = "C" if dport == port else "S"
            c["segments"][d].append((ts, payload))
    return list(conns.values())


def records(conn):
    recs = {"C": list(analyze.tls_records(conn["segments"]["C"])),
            "S": list(analyze.tls_records(conn["segments"]["S"]))}
    app = []
    for d in ("C", "S"):
        for rtype, ver, ts, payload in recs[d]:
            if rtype == 23:
                app.append((ts, d, len(payload)))
    app.sort()
    return recs, app


def analyze_behinder(conns):
    results, _ = analyze.analyze_capture(os.path.join(LAB, "out", "cap_behinder.pcap"))
    flows = []
    req_sizes = []
    for c in results:
        recs = sum(c["tls_records"].values())
        for e in c["exchanges"]:
            req_sizes.extend(e["req_sizes"])
        flows.append({
            "records": recs,
            "exchanges": len(c["exchanges"]),
            "start": c["first"],
            "end": c["last"],
            "req": sum(e["req_bytes"] for e in c["exchanges"]),
            "resp": sum(e["resp_bytes"] for e in c["exchanges"]),
        })
    return {"flows": flows, "req_sizes": req_sizes}


def analyze_ligolo(conns):
    main = None
    for c in conns:
        if c["last"] - c["first"] > 60:
            main = c
            break
    if main is None:
        return {}
    _, app = records(main)
    small = [(ts - main["first"], d, s) for ts, d, s in app
             if 25 <= s <= 33 and ts - main["first"] > 3]
    by_dir = {"C": [], "S": []}
    for t, d, s in small:
        by_dir[d].append(t)
    intervals = {}
    for d, times in by_dir.items():
        gaps = [round(times[i + 1] - times[i], 1) for i in range(len(times) - 1)]
        intervals[d] = gaps
    return {
        "duration": round(main["last"] - main["first"], 1),
        "small": [[round(t, 1), d] for t, d, _ in small],
        "sizes": [s for _, _, s in small],
        "intervals": intervals,
    }


def analyze_normal(conns):
    results, _ = analyze.analyze_capture(os.path.join(LAB, "out", "cap_normal.pcap"))
    all_sizes = []
    per_exchange = []
    for c in results:
        for e in c["exchanges"]:
            all_sizes.extend(e["req_sizes"] + e["resp_sizes"])
            per_exchange.append((e["req_bytes"], e["resp_bytes"]))
    return {"sizes": all_sizes, "per_exchange": per_exchange[:12]}


# ---------------------------------------------------------------------------
# charts
# ---------------------------------------------------------------------------

def svg_bytes(fig):
    buf = io.StringIO()
    fig.savefig(buf, format="svg", bbox_inches="tight")
    plt.close(fig)
    return buf.getvalue()


def save_png(fig, name):
    fig.savefig(os.path.join(CHART_DIR, name), format="png", dpi=130,
                bbox_inches="tight")


def chart_behinder(data):
    out = {}
    flows = data["flows"]

    fig, ax = plt.subplots(figsize=(6, 3))
    ax.bar(range(len(flows)), [f["records"] for f in flows], color="#2f80ed")
    ax.axhline(13, color="#eb5757", ls="--", lw=1, label="13 records (article)")
    ax.set_title("TLS records per flow")
    ax.set_xlabel("flow")
    ax.set_ylabel("records")
    ax.legend(fontsize=8)
    out["records_per_flow"] = svg_bytes(fig)
    save_png(fig, "behinder_records_per_flow.png")

    fig, ax = plt.subplots(figsize=(6, 3))
    sizes = data["req_sizes"]
    buckets = ["<1k", "1-4k", "4-8k", "8-10k", ">10k"]
    counts = [
        sum(1 for s in sizes if s < 1000),
        sum(1 for s in sizes if 1000 <= s < 4000),
        sum(1 for s in sizes if 4000 <= s < 8000),
        sum(1 for s in sizes if 8000 <= s < 10000),
        sum(1 for s in sizes if s >= 10000),
    ]
    ax.bar(buckets, counts, color="#2f80ed")
    ax.set_title("Request TLS record sizes (8225B chunk = okio 8192 + TLS)")
    ax.set_ylabel("record count")
    out["req_size_hist"] = svg_bytes(fig)
    save_png(fig, "behinder_req_size_hist.png")

    fig, ax = plt.subplots(figsize=(6, 3))
    for i, f in enumerate(flows):
        ax.barh(i, f["end"] - f["start"], left=f["start"] - flows[0]["start"],
                height=0.6, color="#2f80ed")
    ax.set_title("Flow timeline (short-lived, one op per flow)")
    ax.set_xlabel("seconds")
    ax.set_ylabel("flow")
    out["timeline"] = svg_bytes(fig)
    save_png(fig, "behinder_timeline.png")
    return out


def chart_ligolo(data):
    out = {}
    fig, ax = plt.subplots(figsize=(6, 3))
    for t, d in data["small"]:
        color = "#2f80ed" if d == "S" else "#eb5757"
        ax.scatter([t], [1 if d == "S" else 0], c=color, s=40)
    ax.set_yticks([0, 1], ["client", "server"])
    ax.set_xlabel("seconds since flow start")
    ax.set_title("29B heartbeat records (fixed interval, server-first)")
    ax.grid(axis="x", alpha=0.3)
    out["heartbeat_scatter"] = svg_bytes(fig)
    save_png(fig, "ligolo_heartbeat_scatter.png")

    fig, ax = plt.subplots(figsize=(6, 3))
    counts = Counter(data["sizes"])
    ax.bar([str(s) for s in sorted(counts)], [counts[s] for s in sorted(counts)],
           color="#27ae60")
    ax.set_title("Heartbeat record size (29B = 12B ping + 1B type + 16B tag)")
    ax.set_xlabel("bytes")
    ax.set_ylabel("count")
    out["size_hist"] = svg_bytes(fig)
    save_png(fig, "ligolo_size_hist.png")
    return out


def chart_normal(data):
    out = {}
    fig, ax = plt.subplots(figsize=(6, 3))
    sizes = data["sizes"]
    buckets = ["<1k", "1-4k", "4-8k", ">8k"]
    counts = [
        sum(1 for s in sizes if s < 1000),
        sum(1 for s in sizes if 1000 <= s < 4000),
        sum(1 for s in sizes if 4000 <= s < 8000),
        sum(1 for s in sizes if s >= 8000),
    ]
    ax.bar(buckets, counts, color="#27ae60")
    ax.set_title("Normal HTTPS GET: TLS record sizes (small req, one big resp)")
    ax.set_ylabel("record count")
    out["size_hist"] = svg_bytes(fig)
    save_png(fig, "normal_size_hist.png")

    fig, ax = plt.subplots(figsize=(6, 3))
    pe = data["per_exchange"][:10]
    x = range(len(pe))
    ax.bar(x, [r for r, _ in pe], width=0.4, label="request", color="#2f80ed")
    ax.bar([i + 0.4 for i in x], [s for _, s in pe], width=0.4, label="response",
           color="#27ae60")
    ax.set_title("Request vs response bytes per exchange")
    ax.legend(fontsize=8)
    ax.set_ylabel("bytes")
    out["req_resp"] = svg_bytes(fig)
    save_png(fig, "normal_req_resp.png")
    return out


def generic_tool_charts(tool_id, port, conns):
    """Produce a heartbeat scatter + key stats for a raw/TLS tool scenario."""
    main = None
    for c in conns:
        if c["last"] - c["first"] > 5:
            main = c
            break
    out = {}
    fig, ax = plt.subplots(figsize=(6, 3))
    if main is not None:
        _, app = records(main)
        small = [(ts - main["first"], d, s) for ts, d, s in app
                 if 1 <= s <= 400 and ts - main["first"] > 2]
        stats = {
            "duration": round(main["last"] - main["first"], 1),
            "appdata": len(app),
            "small": [[round(t, 1), d, s] for t, d, s in small],
        }
        for t, d, s in small[:200]:
            color = "#2f80ed" if d == "S" else "#eb5757"
            ax.scatter([t], [s], c=color, s=18, alpha=0.8)
        ax.set_xlabel("seconds since flow start")
        ax.set_ylabel("payload bytes")
        ax.set_title(f"{tool_id}: small payload timeline")
    else:
        # short-flow tools (e.g. gost ws relay): plot flow starts as a timeline
        starts = sorted(c["first"] for c in conns)
        t0 = starts[0] if starts else 0
        ax.eventplot([s - t0 for s in starts], colors="#eb5757", lineoffsets=0.5, linewidths=4)
        ax.set_xlabel("seconds (relative)")
        ax.set_yticks([])
        ax.set_title(f"{tool_id}: {len(conns)} short flows over time (periodic)")
        stats = {"flows": len(conns), "small": []}
    out["scatter"] = svg_bytes(fig)
    save_png(fig, f"{tool_id}_scatter.png")
    return out, stats


# ---------------------------------------------------------------------------
# attack descriptions
# ---------------------------------------------------------------------------

CATEGORY_INTRO = {
    "webshell": "WebShell 是攻击者植入 Web 服务器的后门脚本，用于远程执行命令、管理文件。"
                "加密型 WebShell（如冰蝎/哥斯拉）把命令和结果都加密传输，传统特征检测失效，"
                "只能在加密流量侧信道找行为指纹。",
    "c2": "C2（命令与控制）框架是攻击者与受控主机之间的指挥通道。上线心跳、任务下发、结果回传"
          "都有固定节奏与格式，心跳周期和载荷结构是最稳定的指纹。",
    "tunnel": "隧道/内网穿透工具把外部流量伪装成正常通信（TLS/HTTP/ICMP/DNS）穿透边界，"
              "用于把内网服务暴露到外网或建立隐蔽 C2 通道。长连接 + 周期心跳 + 固定包长是常见指纹。",
    "rat": "远控木马（RAT）是间谍/窃密武器，持续保持与 C2 的加密连接，定期回传主机信息。"
           "其加密通信通常有固定握手格式和心跳周期。",
    "apt": "APT 组织的攻击武器往往在开源工具基础上定制，或自研私有协议。"
           "识别其加密通信特征需要在流量侧建立行为基线。",
}


def why_attack(cat):
    return CATEGORY_INTRO.get(cat, "")


# ---------------------------------------------------------------------------
# render
# ---------------------------------------------------------------------------

def render_index(tools, cards, chart_data):
    checked = [t for t in tools if t["integrated"]]
    unchecked = [t for t in tools if not t["integrated"]]

    rows = ""
    for t in tools:
        checked_html = 'checked disabled' if t["integrated"] else ''
        badge = '<span class="badge ok">已集成</span>' if t["integrated"] else '<span class="badge todo">待集成</span>'
        fp = t.get("fingerprint") or "待分析"
        rows += f"""
        <tr data-cat="{t['category']}" data-state="{'integrated' if t['integrated'] else 'todo'}">
          <td><input type="checkbox" {checked_html}></td>
          <td>{t['name']}</td>
          <td>{t['category']}</td>
          <td>{'开源' if t['open_source'] else '闭源'}</td>
          <td><a href="https://www.viewintech.com/detail?id={t['article_id']}" target="_blank">文章 {t['article_id']}</a></td>
          <td style="max-width:380px;font-size:12px;line-height:1.5"><span class="fp-badge {'lab' if t['integrated'] else 'pub'}">{'实验室实测' if t['integrated'] else '资料整理'}</span><span style="color:var(--acc)">{fp}</span></td>
          <td class="note">{t['note']}</td>
          <td>{badge}</td>
        </tr>"""

    cards_html = ""
    for t in checked:
        charts = chart_data.get(t["id"], {})
        chart_html = ""
        for title, svg in charts.items():
            b64 = base64.b64encode(svg.encode("utf-8")).decode()
            chart_html += f'<div class="chart"><img src="data:image/svg+xml;base64,{b64}" alt="{title}"><p>{title}</p></div>'
        cards_html += f"""
        <article class="card integrated" id="card-{t['id']}">
          <h3>✔ {t['name']} <span class="badge ok">已集成</span></h3>
          <div class="why"><b>为什么是攻击：</b>{why_attack(t['category'])}</div>
          <div class="note">{t['note']}</div>
          <div class="charts">{chart_html or '<p class="todo">（图表生成中）</p>'}</div>
        </article>"""

    todo_html = ""
    for t in unchecked:
        todo_html += f"""
        <article class="card todo" data-cat="{t['category']}">
          <h3>○ {t['name']} <span class="badge todo">待集成</span></h3>
          <div class="why">{why_attack(t['category'])}</div>
          <div class="note">{t['note']}</div>
        </article>"""

    normal_charts = chart_data.get("normal", {})
    normal_chart_html = ""
    for title, svg in normal_charts.items():
        b64 = base64.b64encode(svg.encode("utf-8")).decode()
        normal_chart_html += f'<div class="chart"><img src="data:image/svg+xml;base64,{b64}"><p>{title}</p></div>'

    html = f"""<!DOCTYPE html>
<html lang="zh">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>TFLab — 加密流量攻击指纹实验室</title>
<style>
:root {{ --bg:#0f1420; --card:#171e2e; --line:#26314a; --text:#e6ebf5; --muted:#8b96ad;
       --ok:#27ae60; --todo:#8b96ad; --acc:#2f80ed; --red:#eb5757; }}
* {{ box-sizing:border-box; }}
body {{ margin:0; background:var(--bg); color:var(--text); font:14px/1.6 -apple-system,"PingFang SC","Microsoft YaHei",sans-serif; }}
header {{ padding:32px 40px 20px; border-bottom:1px solid var(--line); }}
header h1 {{ margin:0; font-size:26px; }}
header p {{ color:var(--muted); margin:8px 0 0; max-width:900px; }}
main {{ padding:24px 40px 60px; max-width:1280px; }}
h2 {{ margin:36px 0 12px; font-size:20px; border-left:4px solid var(--acc); padding-left:10px; }}
.filters button {{ background:var(--card); color:var(--text); border:1px solid var(--line);
  border-radius:6px; padding:6px 14px; margin:0 6px 8px 0; cursor:pointer; }}
.filters button.active {{ background:var(--acc); border-color:var(--acc); }}
table {{ width:100%; border-collapse:collapse; background:var(--card); border-radius:10px; overflow:hidden; }}
th, td {{ padding:9px 12px; text-align:left; border-bottom:1px solid var(--line); font-size:13px; }}
th {{ background:#1b2336; color:var(--muted); }}
td.note {{ color:var(--muted); max-width:340px; }}
.badge {{ font-size:11px; padding:2px 8px; border-radius:10px; }}
.badge.ok {{ background:rgba(39,174,96,.15); color:var(--ok); }}
.badge.todo {{ background:rgba(139,150,173,.12); color:var(--todo); }}
.fp-badge {{ display:inline-block; font-size:10px; padding:1px 6px; border-radius:8px;
  margin-right:6px; vertical-align:1px; white-space:nowrap; }}
.fp-badge.lab {{ background:rgba(39,174,96,.15); color:var(--ok); }}
.fp-badge.pub {{ background:rgba(139,150,173,.12); color:var(--todo); }}
.card {{ background:var(--card); border:1px solid var(--line); border-radius:12px;
  padding:18px 22px; margin:14px 0; }}
.card h3 {{ margin:0 0 10px; }}
.why {{ color:var(--text); margin-bottom:8px; }}
.note {{ color:var(--muted); }}
.charts {{ display:flex; flex-wrap:wrap; gap:16px; margin-top:14px; }}
.chart {{ background:#121826; border:1px solid var(--line); border-radius:10px; padding:12px; }}
.chart img {{ max-width:560px; width:100%; height:auto; }}
.chart p {{ margin:8px 0 0; color:var(--muted); font-size:12px; text-align:center; }}
.cards-grid {{ display:grid; grid-template-columns:repeat(auto-fill,minmax(360px,1fr)); gap:14px; }}
.cards-grid .card {{ margin:0; }}
footer {{ color:var(--muted); padding:20px 40px; border-top:1px solid var(--line); font-size:12px; }}
</style>
</head>
<body>
<header>
  <h1>🔬 TFLab — 加密流量攻击指纹实验室</h1>
  <p>基于观成科技技术文章（<a href="https://www.viewintech.com/techposts" style="color:var(--acc)">techposts</a>）的恶意工具加密流量指纹库。
     已集成的工具（✔）在本地容器中用<b>真实工具</b>产生流量、抓包验证指纹，并接入 Go 实时探针检测；其余工具为待集成清单。</p>
  <p>指纹列：已集成工具为实验室实测，其余为公开分析资料整理。</p>
</header>
<main>
  <h2>工具总表（{len(tools)} 个，已集成 {len(checked)} 个）</h2>
  <div class="filters">
    <button class="active" data-filter="all">全部</button>
    <button data-filter="webshell">WebShell</button>
    <button data-filter="c2">C2</button>
    <button data-filter="tunnel">隧道</button>
    <button data-filter="rat">RAT</button>
    <button data-filter="apt">APT</button>
    <button data-filter="integrated">已集成</button>
  </div>
  <table id="tooltable">
    <thead><tr><th>已集成</th><th>工具</th><th>类型</th><th>开源</th><th>观成文章</th><th>加密流量指纹</th><th>说明</th><th>状态</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>

  <h2>攻击类型可视化（已集成）</h2>
  <div id="integrated-cards">{cards_html}</div>

  <h2>正常流量对照（负样本基线）</h2>
  <article class="card">
    <h3>正常 HTTPS GET</h3>
    <div class="why"><b>为什么需要它：</b>任何检测规则都必须先证明不会误报正常流量。
      下方图表是同一 TLS 栈下普通浏览的记录大小与方向性——与冰蝎的"大请求小响应"、Ligolo 的"固定 29B 心跳"形成鲜明对比。</div>
    <div class="charts">{normal_chart_html}</div>
  </article>

  <h2>待集成工具（{len(unchecked)} 个）</h2>
  <div class="cards-grid">{todo_html}</div>
</main>
<footer>
  数据来源：lab/out 下真实抓包（cap_behinder.pcap / cap_ligolo.pcap / cap_normal.pcap）；
  生成时间：{os.path.getmtime(__file__) and '2026-08-10'}。重新生成：python3 frontend/generate.py
</footer>
<script>
const buttons = document.querySelectorAll('.filters button');
const rows = document.querySelectorAll('#tooltable tbody tr');
buttons.forEach(b => b.addEventListener('click', () => {{
  buttons.forEach(x => x.classList.remove('active'));
  b.classList.add('active');
  const f = b.dataset.filter;
  rows.forEach(r => {{
    const cat = r.dataset.cat, st = r.dataset.state;
    const show = f === 'all' || (f === 'integrated' ? st === 'integrated' : cat === f);
    r.style.display = show ? '' : 'none';
  }});
}}));
</script>
</body>
</html>"""
    with open(os.path.join(FE, "index.html"), "w") as f:
        f.write(html)


def main():
    tools = json.load(open(os.path.join(FE, "tools.json")))["tools"]
    chart_data = {}

    behinder_conns = scenario_pcap("behinder", 8443)
    ligolo_conns = scenario_pcap("ligolo", 11601)
    normal_conns = scenario_pcap("normal", 8443)

    if behinder_conns:
        chart_data["behinder"] = chart_behinder(analyze_behinder(behinder_conns))
    if ligolo_conns:
        chart_data["ligolo"] = chart_ligolo(analyze_ligolo(ligolo_conns))
    if normal_conns:
        chart_data["normal"] = chart_normal(analyze_normal(normal_conns))

    # new integrated tools: one generic chart + stats each
    tool_ports = {
        "suo5": 8443, "merlin": 50051, "stowaway": 10000,
        "natpass": 6154, "frp": 7000, "sliver": 8888, "gost": 10080,
        "platypus": 13338, "metasploit": 4443, "weevely": 8080,
        "deimos": 14000, "xiebro": 13000, "godzilla": 8080,
        "sish": 2222, "shadowtls": 8444, "abptts": 8080, "antsword": 8080,
        "covenant": 8080, "mythic": 80, "cobaltstrike": 8080,
        "chopper": 8080, "ngrok": 443,
        "nimplant": 8445, "bruteratel": 8446, "adaptix": 8081,
        "simayrat": 8447, "oceanlotus": 8448, "transparenttribe": 8449,
        "silenttrinity": 8450, "tristealer": 8082, "rustystealer": 8451,
        "remcos": 8452, "ktlvdoor": 8453, "rakshasa": 8454,
        "manlinghua": 8456, "vshell": 8457,
        "vagent": 8460, "evilox": 8461, "octopus": 8084,
        "sparkrat": 8085, "ksrat": 8086, "loki": 8087, "zloader": 8462,
        "wmrat": 8088, "badnews": 8089, "perfspyrat": 8090, "fatalrat": 8091,
        "sidewinder": 8463, "aptc60": 8464, "aptc68": 8465, "hemao": 8466,
        "lazarus": 8467, "apt29": 8468, "oilrig": 8093, "donot": 8469,
        "ghostwriter": 8470,
    }
    stats_all = {}
    for tool_id, port in tool_ports.items():
        conns = scenario_pcap(tool_id, port)
        if not conns:
            continue
        charts, stats = generic_tool_charts(tool_id, port, conns)
        chart_data[tool_id] = charts
        stats_all[tool_id] = stats

    with open(os.path.join(OUT_DIR, "scenarios.json"), "w") as f:
        json.dump({k: v for k, v in chart_data.items()}, f, indent=2)

    # publish artifacts for the React app
    import shutil
    for png in os.listdir(CHART_DIR):
        shutil.copy(os.path.join(CHART_DIR, png), os.path.join(WEB_DATA, png))
    shutil.copy(os.path.join(FE, "tools.json"), os.path.join(WEB_DATA, "tools.json"))
    with open(os.path.join(WEB_DATA, "scenarios.json"), "w") as f:
        json.dump({"charts": {k: list(v) for k, v in chart_data.items()},
                   "stats": stats_all}, f, indent=2)

    render_index(tools, None, chart_data)
    print(f"index.html written ({os.path.getsize(os.path.join(FE, 'index.html'))} bytes); "
          f"charts: {', '.join(chart_data)}")


if __name__ == "__main__":
    main()
