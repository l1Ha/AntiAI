"""ANTIAI 快速上手：判定动作、保护工具函数、受管 Shell。

运行：``python3 examples/quickstart.py``
"""

from __future__ import annotations

import tempfile

from antiai import Guard

state_dir = tempfile.mkdtemp(prefix="antiai-quickstart-")
guard = Guard(session_id="quickstart", state_dir=state_dir)

# 1) 直接判定一个动作
print("== 动作判定 ==")
for spec in (
    {"tool": "file.read", "args": {"path": "notes.md"}},
    {"tool": "shell.exec", "args": {"command": "pkill -f antiai-guard"}},
    {"tool": "http.post", "args": {"url": "https://api.example.com/upload"}},
):
    decision = guard.evaluate(spec)
    print(f"  {decision.action.describe():<60} -> {decision.verdict.value}")
    print(f"    依据：{decision.reason_text}")

# 2) 用装饰器保护工具函数：被阻止时返回结构化拒绝（适合回传给智能体）
print("\n== 工具函数护栏 ==")


@guard.tool("file.read", on_block="return")
def read_file(path: str) -> str:
    return f"（真实文件内容：{path}）"


print("  允许的调用：", read_file(path="notes.md"))
blocked = read_file(path="/etc/shadow")
print("  被阻止的调用：", blocked["reason"] if isinstance(blocked, dict) else blocked)

# 3) 受管 Shell：先判定、后执行。执行类工具默认是 review（需人工确认）
print("\n== 受管 Shell ==")
shell = guard.shell()

# 模拟"人工批准"：传入 approver 回调（真实场景里可以弹窗、发审批单……）
result = shell.run("echo hello-from-antiai", approver=lambda action, reasons: True)
print("  echo（已批准） ->", result.stdout.strip(), f"(returncode={result.returncode})")

# 检测器是硬约束：即使人工批准也无法放行危险命令
result = shell.run("sudo chmod 4755 /tmp/x", approver=lambda action, reasons: True, on_block="return")
print("  sudo chmod    ->", "已阻止：" + result.decision.reason_text if result.blocked else "未阻止")

print(f"\n审计日志：{guard.status()['audit_path']}")
