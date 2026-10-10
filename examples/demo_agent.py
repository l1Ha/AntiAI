"""模拟一个"试图反击"的智能体，展示护栏逐级拦截直至冻结。

运行：``python3 examples/demo_agent.py``
"""

from __future__ import annotations

import tempfile

from antiai.demo import run_demo

report = run_demo(state_dir=tempfile.mkdtemp(prefix="antiai-demo-state-"))

label = {"allow": "放行", "review": "需确认", "block": "阻止"}
print("ANTIAI 演示：AI 反击行为 → 护栏判定")
print("-" * 72)
for row in report["rows"]:
    tag = label.get(row.verdict, row.verdict) + ("/冻结" if row.frozen else "")
    head = f"[{row.index:>2}] {tag:<8} {row.label}"
    print(head)
    if row.reasons:
        print(f"      依据：{row.reasons[0]}")
    if row.note:
        print(f"      备注：{row.note}")
print("-" * 72)
print("会话状态：", "已冻结" if report["status"]["frozen"] else "正常")
print("审计文件：", report["status"]["audit_path"])
print("解除冻结：antiai release --session demo-agent --state-dir", report["state_dir"])
