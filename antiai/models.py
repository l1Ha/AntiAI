"""
核心数据模型：动作（Action）、检测项（Finding）、判定（Decision）。

设计要点
--------
- ``Action`` 是护栏看到的"一个待执行动作"的统一表示：无论它来自
  工具调用、Shell 命令还是 HTTP 请求，最终都归一到 tool / command /
  path / host / args 五个维度上。
- ``Finding`` 是检测器的输出：说明"这个动作像哪类反击行为"。
- ``Decision`` 是护栏的最终裁决：allow / review / block，附带依据、
  命中的规则、检测项，以及是否触发冻结。
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional


def canonical_json(value: Any) -> str:
    """稳定序列化：键排序、中文不转义、紧凑分隔。用于指纹与审计哈希。"""
    return json.dumps(
        value, sort_keys=True, ensure_ascii=False, default=str, separators=(",", ":")
    )


class Verdict(str, Enum):
    """判定结果，限制性由弱到强：allow < review < block。"""

    ALLOW = "allow"
    REVIEW = "review"
    BLOCK = "block"

    @property
    def rank(self) -> int:
        return _VERDICT_RANK[self]

    @property
    def label(self) -> str:
        return {"allow": "放行", "review": "需人工确认", "block": "阻止"}[self.value]


_VERDICT_RANK: Dict[Verdict, int] = {
    Verdict.ALLOW: 0,
    Verdict.REVIEW: 1,
    Verdict.BLOCK: 2,
}


class Severity(str, Enum):
    """严重级别。"""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]


_SEVERITY_RANK: Dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


def most_restrictive(verdicts: Iterable[Verdict]) -> Optional[Verdict]:
    """取最严格的判定；空集合返回 None。"""
    best: Optional[Verdict] = None
    for verdict in verdicts:
        if best is None or verdict.rank > best.rank:
            best = verdict
    return best


@dataclass
class Finding:
    """检测器命中的一条发现。"""

    detector: str
    reason: str
    severity: Severity = Severity.MEDIUM
    verdict: Verdict = Verdict.BLOCK
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        data: Dict[str, Any] = {
            "detector": self.detector,
            "reason": self.reason,
            "severity": self.severity.value,
            "verdict": self.verdict.value,
        }
        if self.details:
            data["details"] = self.details
        return data


@dataclass
class Action:
    """一个待执行动作的统一表示。"""

    tool: str
    session_id: str = "default"
    args: Dict[str, Any] = field(default_factory=dict)
    command: Optional[str] = None
    path: Optional[str] = None
    host: Optional[str] = None
    raw: Any = None
    ts: float = field(default_factory=time.time)

    def fingerprint(self) -> str:
        """动作指纹：用于识别"同一动作被反复执行"。"""
        payload = {
            "tool": self.tool,
            "command": self.command,
            "path": self.path,
            "host": self.host,
            "args": self.args,
        }
        return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()[:16]

    def describe(self) -> str:
        bits = [self.tool]
        if self.command:
            bits.append(f"命令={self.command}")
        if self.path:
            bits.append(f"路径={self.path}")
        if self.host:
            bits.append(f"主机={self.host}")
        return " | ".join(bits)

    def to_dict(self) -> Dict[str, Any]:
        data: Dict[str, Any] = {
            "tool": self.tool,
            "session": self.session_id,
            "ts": self.ts,
        }
        for key in ("command", "path", "host"):
            value = getattr(self, key)
            if value:
                data[key] = value
        if self.args:
            data["args"] = self.args
        return data


@dataclass
class Decision:
    """护栏对单个动作的最终裁决。"""

    action: Action
    verdict: Verdict
    allowed: bool
    reasons: List[str] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    matched_rules: List[str] = field(default_factory=list)
    frozen: bool = False
    requires_approval: bool = False
    advisory: bool = False
    approved: bool = False
    ts: float = field(default_factory=time.time)

    @property
    def reason_text(self) -> str:
        return "；".join(self.reasons) if self.reasons else "无（按默认策略处理）"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ts": self.ts,
            "session": self.action.session_id,
            "action": self.action.to_dict(),
            "verdict": self.verdict.value,
            "allowed": self.allowed,
            "frozen": self.frozen,
            "requires_approval": self.requires_approval,
            "approved": self.approved,
            "advisory": self.advisory,
            "reasons": list(self.reasons),
            "matched_rules": list(self.matched_rules),
            "findings": [finding.to_dict() for finding in self.findings],
        }
