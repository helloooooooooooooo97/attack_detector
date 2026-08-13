import React, { useEffect, useState } from "react";
import { attacks, categoryIntro } from "./attacks.js";
import AlertCenter from "./AlertCenter.jsx";

const CATS = ["webshell", "c2", "tunnel", "rat", "apt"];

function useData() {
  const [tools, setTools] = useState([]);
  useEffect(() => {
    fetch("./data/tools.json")
      .then((r) => r.json())
      .then((d) => setTools(d.tools))
      .catch(() => setTools([]));
  }, []);
  return tools;
}

function ToolTable({ tools }) {
  const [filter, setFilter] = useState("all");
  const visible = tools.filter((t) => {
    if (filter === "all") return true;
    if (filter === "integrated") return t.integrated;
    return t.category === filter;
  });
  return (
    <>
      <div className="filters">
        {["all", ...CATS, "integrated"].map((f) => (
          <button key={f} className={filter === f ? "active" : ""} onClick={() => setFilter(f)}>
            {f === "all" ? "全部" : f === "integrated" ? "已集成" : f.toUpperCase()}
          </button>
        ))}
      </div>
      <p className="note" style={{ color: "var(--muted)", fontSize: "12px", margin: "0 0 8px" }}>
        指纹列：已集成工具为实验室实测，其余为公开分析资料整理。
      </p>
      <table>
        <thead>
          <tr><th>已集成</th><th>工具</th><th>类型</th><th>开源</th><th>观成文章</th><th>加密流量指纹</th><th>说明</th><th>状态</th></tr>
        </thead>
        <tbody>
          {visible.map((t) => (
            <tr key={t.id}>
              <td><input type="checkbox" checked={t.integrated} readOnly /></td>
              <td>{t.name}</td>
              <td>{t.category}</td>
              <td>{t.open_source ? "开源" : "闭源"}</td>
              <td><a href={`https://www.viewintech.com/detail?id=${t.article_id}`} target="_blank" rel="noreferrer">文章 {t.article_id}</a></td>
              <td style={{ maxWidth: "380px", fontSize: "12px", lineHeight: 1.5 }}>
                <span className={`fp-badge ${t.integrated ? "lab" : "pub"}`}>
                  {t.integrated ? "实验室实测" : "资料整理"}
                </span>
                <span style={{ color: "var(--acc)" }}>{t.fingerprint || "待分析"}</span>
              </td>
              <td style={{ color: "var(--muted)" }}>{t.note}</td>
              <td>{t.integrated ? <span className="badge ok">已集成</span> : <span className="badge todo">待集成</span>}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </>
  );
}

function AttackCard({ a }) {
  return (
    <article className="card" id={`attack-${a.id}`}>
      <h3>✔ {a.name} <span className="badge ok">已集成</span></h3>
      <div className="meta">
        类型：{a.category} ｜ 观成文章：<a href={`https://www.viewintech.com/detail?id=${a.article}`} target="_blank" rel="noreferrer">id={a.article}</a>
      </div>
      <h4>它是什么</h4>
      <p>{a.what}</p>
      <h4>为什么它是攻击</h4>
      <p>{a.why}</p>
      <h4>攻击原理</h4>
      <p>{a.how}</p>
      <h4>加密流量指纹（实验室实测）</h4>
      <ul>{a.fingerprint.map((f, i) => <li key={i}>{f}</li>)}</ul>
      <h4>检测规则</h4>
      <div className="rule">{a.rule}</div>
      <div className="charts">
        {a.charts.map((c) => (
          <div className="chart" key={c}>
            <img src={`./data/${c}`} alt={c} />
          </div>
        ))}
      </div>
    </article>
  );
}

export default function App() {
  const tools = useData();
  const [view, setView] = useState("table");
  const integrated = attacks.filter((a) => a.integrated);
  const todo = tools.filter((t) => !t.integrated);
  return (
    <>
      <header>
        <h1>🔬 TFLab — 加密流量攻击指纹实验室</h1>
        <p>
          基于观成科技技术文章的恶意工具加密流量指纹库。已集成（✔）的工具在本地容器中用<b>真实工具</b>产生流量、
          抓包验证指纹，并接入 Go 实时探针检测（不解密、纯加密流量侧信道）；其余为待集成清单。
          当前已集成 {integrated.length} 种攻击，全部通过正样本检出 + 正常流量零误报验证。
        </p>
        <nav className="nav">
          <button className={view === "table" ? "active" : ""} onClick={() => setView("table")}>工具总表</button>
          <button className={view === "attacks" ? "active" : ""} onClick={() => setView("attacks")}>攻击详解</button>
          <button className={view === "alerts" ? "active" : ""} onClick={() => setView("alerts")}>
            🚨 告警中心
          </button>
        </nav>
      </header>
      <main>
        {view === "alerts" ? (
          <AlertCenter />
        ) : (
          <>
            {view === "table" && (
              <>
                <h2>工具总表（{tools.length} 个，已集成 {integrated.length} 个）</h2>
                <ToolTable tools={tools} />
              </>
            )}

            {view === "attacks" && (
              <>
                <h2>攻击详解与可视化（已集成 {integrated.length} 种）</h2>
                {integrated.map((a) => (
                  <div key={a.id}>
                    <AttackCard a={a} />
                  </div>
                ))}

                <h2>待集成工具（{todo.length} 个）</h2>
                <div className="grid">
                  {todo.map((t) => (
                    <article className="card" key={t.id}>
                      <h3>○ {t.name} <span className="badge todo">待集成</span></h3>
                      <p>{categoryIntro[t.category] || ""}</p>
                      <p style={{ color: "var(--muted)" }}>{t.note}</p>
                    </article>
                  ))}
                </div>
              </>
            )}
          </>
        )}
      </main>
      <footer>
        图表来自 lab/out 真实抓包；重新生成：python3 frontend/generate.py（自动输出到 web/public/data）。
      </footer>
    </>
  );
}
