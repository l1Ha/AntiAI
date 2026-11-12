"""模拟一个"试图反击"的智能体，展示护栏逐级拦截直至冻结（默认）

或主动反制全流程（--aggressive）。

运行：``python3 examples/demo_agent.py [--aggressive]``
"""

from __future__ import annotations

import sys
import tempfile

from antiai.demo import run_demo

aggressive = "--aggressive" in sys.argv
report = run_demo(state_dir=tempfile.mkdtemp(prefix="antiai-demo-state-"), aggressive=aggressive)

label = {"allow": "放行", "review": "需确认", "block": "阻止"}
mode = "主动反制演示（封锁 / 取证 / 蜜罐 / 诱饵）" if aggressive else "AI 反击行为 → 护栏判定"
print(f"ANTIAI 演示：{mode}")
print("-" * 72)
for row in report["rows"]:
    tag = label.get(row.verdict, row.verdict) + ("/冻结" if row.frozen else "")
    print(f"[{row.index:>2}] {tag:<8} {row.label}")
    if row.reasons:
        print(f"      依据：{row.reasons[0]}")
    for item in row.countermeasures:
        print(f"      ⚔ {item['action']}: {item['status']} —— {item['detail'][:70]}")
    if row.note:
        print(f"      备注：{row.note}")
print("-" * 72)
status = report["status"]
if aggressive:
    print("会话状态：", "已封锁" if status["lockdown"] else "未封锁")
    print("事件报告：", len(report["incidents"]), "份　蜜罐：", len(report["honeytokens"]), "条")
    print("查看报告：antiai incidents --state-dir", report["state_dir"])
else:
    print("会话状态：", "已冻结" if status["frozen"] else "正常")
    print("审计文件：", status["audit_path"])
    print("解除冻结：antiai release --session demo-agent --state-dir", report["state_dir"])
