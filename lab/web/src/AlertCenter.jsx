import React, { useEffect, useMemo, useState } from "react";

const CATS = ["webshell", "c2", "tunnel", "rat", "apt", "system"];

function fmtTime(ts) {
  if (!ts) return "-";
  const d = new Date(ts * 1000);
  return d.toLocaleTimeString("zh-CN", { hour12: false }) + "." +
    String(d.getMilliseconds()).padStart(3, "0");
}

function useAlerts() {
  const [data, setData] = useState(null);
  useEffect(() => {
    let alive = true;
    const tick = () => {
      fetch("./data/alerts.json")
        .then((r) => r.json())
        .then((d) => alive && setData(d))
        .catch(() => {});
    };
    tick();
    const t = setInterval(tick, 3000);
    return () => { alive = false; clearInterval(t); };
  }, []);
  return data;
}

export default function AlertCenter() {
  const data = useAlerts();
  const [cat, setCat] = useState("all");
  const [tool, setTool] = useState("all");
  const [q, setQ] = useState("");

  const alerts = data?.alerts || [];
  const evmap = data?.events || {};

  const stats = useMemo(() => {
    const byCat = {}, byTool = {}, byEvent = {};
    for (const a of alerts) {
      const meta = evmap[a.event] || { category: "system", tool_name: a.event };
      byCat[meta.category] = (byCat[meta.category] || 0) + 1;
      byTool[meta.tool_name] = (byTool[meta.tool_name] || 0) + 1;
      byEvent[a.event] = (byEvent[a.event] || 0) + 1;
    }
    return { byCat, byTool, byEvent };
  }, [alerts, evmap]);

  const toolNames = useMemo(
    () => Object.keys(stats.byTool).sort((a, b) => stats.byTool[b] - stats.byTool[a]),
    [stats]
  );

  const visible = useMemo(() => {
    const ql = q.trim().toLowerCase();
    return alerts.filter((a) => {
      const meta = evmap[a.event] || { category: "system", tool_name: a.event };
      if (cat !== "all" && meta.category !== cat) return false;
      if (tool !== "all" && meta.tool_name !== tool) return false;
      if (ql) {
        const hay = `${a.event} ${meta.tool_name} ${a.src_ip || ""} ${a.dst_ip || ""}`.toLowerCase();
        if (!hay.includes(ql)) return false;
      }
      return true;
    });
  }, [alerts, cat, tool, q, evmap]);

  return (
    <section id="alert-center">
      <div className="ac-stats">
        <div className="ac-stat"><b>{data?.total ?? 0}</b><span>总告警</span></div>
        <div className="ac-stat"><b>{alerts.length}</b><span>展示中</span></div>
        {CATS.filter((c) => stats.byCat[c]).map((c) => (
          <div className="ac-stat" key={c}><b>{stats.byCat[c]}</b><span>{c}</span></div>
        ))}
        <div className="ac-stat muted"><b>·</b><span>{data ? new Date(data.generated).toLocaleTimeString("zh-CN") : "—"}</span></div>
      </div>

      <div className="filters">
        {["all", ...CATS].map((c) => (
          <button key={c} className={cat === c ? "active" : ""} onClick={() => setCat(c)}>
            {c === "all" ? "全部" : c.toUpperCase()}
          </button>
        ))}
        <select value={tool} onChange={(e) => setTool(e.target.value)}>
          <option value="all">全部工具</option>
          {toolNames.map((n) => <option key={n} value={n}>{n}</option>)}
        </select>
        <input
          className="ac-search"
          placeholder="搜索 event / 工具 / IP…"
          value={q}
          onChange={(e) => setQ(e.target.value)}
        />
      </div>

      <table className="ac-table">
        <thead>
          <tr>
            <th>时间</th><th>告警事件</th><th>工具</th><th>类型</th>
            <th>源 → 目的</th><th>关键特征</th>
          </tr>
        </thead>
        <tbody>
          {visible.slice(-300).reverse().map((a, i) => {
            const meta = evmap[a.event] || { category: "system", tool_name: a.event };
            const feats = [
              a.records != null && `记录 ${a.records}`,
              a.req_bytes != null && `上行 ${a.req_bytes}B`,
              a.resp_bytes != null && `下行 ${a.resp_bytes}B`,
              a.raw_interval_c ? `周期 ${a.raw_interval_c}s` : null,
              a.interval_c ? `心跳 ${a.interval_c}s` : null,
              a.duration != null && `时长 ${a.duration}s`,
              a.flows != null && `流数 ${a.flows}`,
              a.note,
            ].filter(Boolean).join(" · ");
            return (
              <tr key={i}>
                <td className="ac-time">{fmtTime(a.ts)}</td>
                <td><span className="ac-event">{a.event}</span></td>
                <td>{meta.tool_name}</td>
                <td><span className={`badge cat-${meta.category}`}>{meta.category}</span></td>
                <td>{a.src_ip || "?"}:{a.sport || ""} → {a.dst_ip || "?"}:{a.dport || ""}</td>
                <td className="ac-feats">{feats || "-"}</td>
              </tr>
            );
          })}
          {visible.length === 0 && (
            <tr><td colSpan="6" style={{ color: "var(--muted)", textAlign: "center", padding: 24 }}>
              暂无匹配告警
            </td></tr>
          )}
        </tbody>
      </table>
      <p className="note" style={{ color: "var(--muted)", fontSize: 12 }}>
        数据源：{data?.source || "…"}，每 3 秒自动刷新；共 {data?.total ?? 0} 条（展示最近 2000 条）。
      </p>
    </section>
  );
}
