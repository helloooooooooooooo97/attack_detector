#!/usr/bin/env python3
"""
Regenerate docs/TOOL_INDEX.md from frontend/tools.json (single source of truth).

Usage: python3 frontend/gen_tool_index.py
"""

import json
import os
from datetime import date

LAB = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOLS_JSON = os.path.join(LAB, "frontend", "tools.json")
OUT = os.path.join(LAB, "docs", "TOOL_INDEX.md")

CAT_ORDER = ["webshell", "c2", "tunnel", "rat", "apt"]


def main():
    data = json.load(open(TOOLS_JSON, encoding="utf-8"))
    tools = data["tools"]
    checked = [t for t in tools if t["integrated"]]
    unchecked = [t for t in tools if not t["integrated"]]

    lines = []
    lines.append("# 工具索引（TFLab）")
    lines.append("")
    lines.append("> 来源：[观成科技技术文章](https://www.viewintech.com/techposts) | "
                 f"更新：{date.today().isoformat()}")
    lines.append(f"> 共 {len(tools)} 个工具，已集成 {len(checked)} 个（✔）："
                 f"{', '.join(t['id'] for t in checked)}")
    lines.append("")
    lines.append("> 指纹列：✔ 已集成工具为实验室实测指纹（真实流量抓包验证）；"
                 "□ 未集成工具为公开分析资料整理。")
    lines.append("")
    lines.append(f"> 待集成 {len(unchecked)} 个：{', '.join(t['id'] for t in unchecked)}")
    lines.append("")

    for cat in CAT_ORDER:
        group = [t for t in tools if t["category"] == cat]
        lines.append(f"## {cat}")
        lines.append("")
        lines.append("| 勾选 | 工具 | 开源 | 观成文章 | 指纹 | 说明 |")
        lines.append("|---|---|---|---|---|---|")
        for t in group:
            mark = "✔" if t["integrated"] else "□"
            os_ = "是" if t["open_source"] else "否"
            fp = (t.get("fingerprint") or "待分析").strip()
            lines.append(
                f"| {mark} | {t['name']} | {os_} | "
                f"[id={t['article_id']}](https://www.viewintech.com/detail?id={t['article_id']}) "
                f"| {fp} | {t['note']} |"
            )
        lines.append("")

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"written {OUT}: {len(tools)} tools, {len(checked)} integrated")


if __name__ == "__main__":
    main()
