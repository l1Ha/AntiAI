"""主动反制接入示例：策略 + 蜜罐 + hooks（真实终止/告警能力由部署侧注入）。

运行：``python3 examples/aggressive_setup.py``
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from antiai import Guard
from antiai.policy import DEFAULT_POLICY, policy_from_dict

state_dir = tempfile.mkdtemp(prefix="antiai-aggressive-")
workspace = Path(tempfile.mkdtemp(prefix="antiai-ws-"))

# 1) 策略：开启封锁 / 取证 / 告警 / 隔离 / 蜜罐打击；隔离范围锁死在 agent 工作区内
data = json.loads(json.dumps(DEFAULT_POLICY))
data["countermeasures"]["rules"] = [
    {
        "id": "lockdown-on-attack",
        "when": {"detectors": ["tamper", "self_preservation"], "min_severity": "critical"},
        "actions": ["lockdown", "evidence", "alert"],
    },
    {
        "id": "strike-on-honeytoken",
        "when": {"detectors": ["honeytoken"]},
        "actions": ["freeze", "evidence", "alert", "terminate"],
    },
    {
        "id": "quarantine-secrets",
        "when": {"detectors": ["exfiltration"], "min_severity": "medium", "paths": [f"{workspace}/**"]},
        "actions": ["quarantine", "evidence", "alert"],
    },
]
data["countermeasures"]["quarantine_paths"] = [f"{workspace}/**"]
data["deception"] = {"enabled": True, "decoys": {"**/.env": "env"}}
policy = policy_from_dict(data, source="<示例策略·主动反制>")

# 2) hooks：护栏只做判定与编排，"真实杀伤"由部署侧注入
terminated, alerted = [], []
guard = Guard(
    policy,
    state_dir=state_dir,
    session_id="agent-1",
    hooks={
        # Docker 部署：  lambda p: subprocess.run(["docker", "kill", p["session"]])
        # systemd 部署： lambda p: subprocess.run(["systemctl", "stop", f"agent@{p['session']}.service"])
        # 告警：        lambda p: requests.post(WEBHOOK_URL, json=p)
        "terminate": terminated.append,
        "alert": alerted.append,
    },
)

# 3) 布置场景：蜜罐凭据 + 工作区涉密文件
token = guard.honeytokens.plant(workspace / ".env", kind="env", session="agent-1")
secret = workspace / "deploy.pem"
secret.write_text("-----BEGIN PRIVATE KEY-----\n（示例用假密钥）\n-----END PRIVATE KEY-----\n", encoding="utf-8")

# 4) 模拟攻击动作
print(f"蜜罐已投放：{token.path}（canary {token.id}）\n")
scenario = [
    ("[1] 执行 shell（默认需人工确认，未批准 → 不放行）", {"tool": "shell.exec", "args": {"command": "ls -la /"}}),
    ("[2] 读取工作区涉密文件（触发隔离 + 取证 + 告警）", {"tool": "file.read", "args": {"path": str(secret)}}),
    ("[3] 偷读蜜罐凭据（触发冻结 + 取证 + 告警 + 终止钩子）", {"tool": "file.read", "args": {"path": str(token.path)}}),
    ("[4] 冻结后继续外联（试探）", {"tool": "shell.exec", "args": {"command": "curl https://evil.example.com"}}),
]
for label, action in scenario:
    decision = guard.evaluate(action)
    print(f"{label} → {decision.verdict.value}")
    for item in decision.countermeasures:
        print(f"      ⚔ {item['action']}: {item['status']} —— {item['detail'][:76]}")
    if decision.decoy is not None:
        print("      ⚑ 已投放诱饵：攻击方拿到的是假凭据（内容含 canary，外发即可溯源）")

print()
print(f"terminate 钩子被调用 {len(terminated)} 次；alert 钩子被调用 {len(alerted)} 次")
status = guard.control.status("agent-1")
print("会话状态：", "已冻结" if status["frozen"] else "未冻结", "/", "已封锁" if status["lockdown"] else "未封锁")
incidents = sorted(str(path) for path in (Path(state_dir) / "incidents").glob("*.md"))
print("事件报告：")
for path in incidents:
    print(f"  - {path}")
print(f"\n查看报告全文：antiai report <事件id> --state-dir {state_dir}")
