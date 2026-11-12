"""把 ANTIAI 接入真实 Agent 的完整示例：OpenAI Function Calling 循环。

不依赖任何 API Key——用本地"模型替身"驱动一轮完整对话，展示标准接入姿势：

1. 智能体发出的每个 tool_call（OpenAI 形态）先过 ``guard.evaluate``；
2. ``allowed=False`` 时，把拒绝对话作为 tool 结果回传给智能体
   （智能体看到的不是异常，而是一条"工具失败"消息——它自己会调整策略）；
3. ``requires_approval`` 的动作走人工批准回调；
4. 会话状态、审计、冻结全部自动生效。

接真实模型时只需把 ``fake_model_reply`` 换成一次真正的 API 调用。
运行：``python3 examples/agent_integration.py``
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any, Dict

from antiai import Guard

state_dir = tempfile.mkdtemp(prefix="antiai-agent-")
workspace = Path(tempfile.mkdtemp(prefix="antiai-ws-"))
(workspace / "notes.md").write_text("# 项目笔记\n", encoding="utf-8")

guard = Guard(session_id="chat-42", state_dir=state_dir)

# ---------------------------------------------------------------------------
# 工具注册表：真实实现里这些函数各自干活；护栏统一在外层拦截
# ---------------------------------------------------------------------------

def read_file(path: str) -> str:
    return (Path(path).read_text(encoding="utf-8") if Path(path).exists() else f"(不存在: {path})")

def write_file(path: str, content: str) -> str:
    Path(path).write_text(content, encoding="utf-8")
    return f"已写入 {path}"

def run_shell(command: str) -> str:
    import subprocess
    proc = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=10)
    return (proc.stdout or proc.stderr or "(无输出)").strip()

TOOLS = {"read_file": read_file, "write_file": write_file, "run_shell": run_shell}

# review 类动作的人工批准：真实场景换成审批 IM / 弹窗
def human_approve(action, reasons) -> bool:
    print(f"    [人工审批] {action.describe()}")
    for reason in reasons[:2]:
        print(f"      - {reason}")
    return True  # 演示环境自动批准

# ---------------------------------------------------------------------------
# "模型替身"：按脚本发起一轮工具调用（接真实模型时替换这里）
# ---------------------------------------------------------------------------

def fake_model_reply(turn: int) -> Dict[str, Any]:
    scripted = [
        {"name": "read_file", "arguments": json.dumps({"path": str(workspace / "notes.md")})},
        {"name": "run_shell", "arguments": json.dumps({"command": "history -c && rm -f ~/.bash_history"})},
        {"name": "write_file", "arguments": json.dumps({"path": str(workspace / "notes.md"), "content": "更新"})},
    ]
    return {"tool_calls": [scripted[turn]]} if turn < len(scripted) else {"final": "任务结束"}

# ---------------------------------------------------------------------------
# 标准接入循环：每个 tool_call 先判定，再执行；拒绝结果回传给智能体
# ---------------------------------------------------------------------------

print(f"会话 chat-42　工作区：{workspace}\n")
for turn in range(4):
    reply = fake_model_reply(turn)
    if "final" in reply:
        print(f"[模型] {reply['final']}")
        break

    call = reply["tool_calls"][0]
    name = call["name"]
    args: Dict[str, Any] = json.loads(call["arguments"])
    print(f"[模型] 调用 {name}({', '.join(f'{k}={v}' for k, v in list(args.items())[:1])}...)")

    # 核心接入点：OpenAI 形态直接喂给护栏（adapters 自动归一化）
    decision = guard.evaluate(
        {"function": {"name": name, "arguments": call["arguments"]}},
        approver=human_approve,
    )
    if decision.allowed:
        result = TOOLS[name](**args)
        print(f"    → 执行成功：{str(result)[:60]}")
    else:
        # 拒绝不抛异常：作为 tool 结果回传，智能体据此自行调整
        tool_result = json.dumps(
            {"error": "action_blocked_by_guardrail", "reason": decision.reason_text[:120]},
            ensure_ascii=False,
        )
        print(f"    → 已阻止（{decision.verdict.value}）：{decision.reason_text[:70]}")
        print(f"    → 回传给模型：{tool_result[:80]}...")

print(f"\n会话统计：拦截 {guard.state().blocked} 次 / 放行 {guard.state().allowed} 次 / 需确认 {guard.state().reviewed} 次")
print(f"审计：{guard.status()['audit_path']}")
