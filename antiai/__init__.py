"""
ANTIAI —— 面向 AI / 智能体的行为防护护栏

一句话定位
----------
在 AI / 智能体与真实世界之间加一层**不可绕过的判定层**：每个工具调用、每条
Shell 命令、每次外联都要先过护栏；越权、自保、外泄、反侦察、失控与对抗性
"反击"行为会被阻止、留痕，持续试探则自动冻结会话。

数据流
------
::

    动作（工具调用 / Shell / 网络请求）
              │
              ▼
        ┌───────────┐  冻结/停机  ┌──────────┐
        │  adapters │ ──────────▶ │ control  │  紧急制动（不可绕过）
        └─────┬─────┘             └──────────┘
              ▼
        ┌───────────┐  规则裁决
        │  policy   │ ────┐
        └───────────┘     ▼
        ┌───────────┐  ┌───────────┐  ┌───────────┐
        │ detectors │─▶│   Guard   │─▶│   audit   │  哈希链审计
        └───────────┘  └─────┬─────┘  └───────────┘
                             ▼
                   allow / review / block / freeze

快速开始
--------
::

    from antiai import Guard

    guard = Guard(session_id="agent-1")

    decision = guard.evaluate({"tool": "file.read", "args": {"path": "notes.md"}})
    if not decision.allowed:
        print("已阻止：", decision.reason_text)

    shell = guard.shell()
    shell.run("echo hello")          # 先判定、后执行；危险命令直接抛 ActionBlocked
"""

from __future__ import annotations

__version__ = "0.3.0"

from .adapters import enrich_action, normalize_action
from .audit import AuditLog
from .control import SessionControl, safe_session_name
from .counterstrike import CountermeasureResult, CounterStrike
from .decoys import DecoyFactory, DecoyPack
from .errors import ActionBlocked, AntiaiError, AuditError, PolicyError, SessionFrozen
from .guard import Guard, GuardedShell, ShellResult, default_state_dir
from .honeytokens import Honeytoken, HoneytokenRegistry
from .models import Action, Decision, Finding, Severity, Verdict
from .policy import Policy, Rule, default_policy, load_policy, validate_policy

__all__ = [
    "__version__",
    # 核心
    "Guard",
    "GuardedShell",
    "ShellResult",
    "default_state_dir",
    # 主动反制 / 蜜罐 / 假情报
    "CounterStrike",
    "CountermeasureResult",
    "Honeytoken",
    "HoneytokenRegistry",
    "DecoyFactory",
    "DecoyPack",
    # 模型
    "Action",
    "Decision",
    "Finding",
    "Severity",
    "Verdict",
    # 策略
    "Policy",
    "Rule",
    "load_policy",
    "default_policy",
    "validate_policy",
    # 审计与制动
    "AuditLog",
    "SessionControl",
    "safe_session_name",
    # 适配器
    "normalize_action",
    "enrich_action",
    # 异常
    "AntiaiError",
    "PolicyError",
    "AuditError",
    "ActionBlocked",
    "SessionFrozen",
]
