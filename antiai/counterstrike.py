"""
主动反制引擎：检测到攻击性行为后，不止"挡住"，而是**立刻还击**。

反制动作（策略 ``countermeasures.rules[].actions``）
----------------------------------------------------
====================  ============================================================
动作                    效果
====================  ============================================================
``freeze``            冻结会话：所有动作立即被阻止，只能人工解除
``lockdown``          封锁会话：禁止执行类工具与全部对外网络，保留只读观察
``terminate``         终止被管进程：调用 ``hooks["terminate"]``，或按策略
                      ``countermeasures.terminate`` 配置执行 ``pkill -f <pattern>``
``quarantine``        把涉密文件移入隔离保险库（0600，可 ``antiai quarantine restore``）
``evidence``          生成事件报告（JSON + Markdown：触发动作/依据/反制/审计尾部/建议）
``alert``             告警：调用 ``hooks["alert"]``，否则写入 ``<状态目录>/alerts.log``
====================  ============================================================

触发条件（``when``）
--------------------
- ``detectors``: ``["tamper", ...]``  命中任一检测器
- ``min_severity``: ``"critical"``    检测项的最高严重级不低于该值
- ``verdict``: ``["block"]``          判定属于给定集合
- ``freeze_triggered``: ``true``      本次判定触发了自动冻结
- ``blocked_in_window``: ``3``        计数窗口内累计拦截次数达到阈值

规则默认**每会话只触发一次**（``"repeat": true`` 可重复），避免告警风暴。

边界
----
反制动作只作用于**你自己的部署**（当前会话 / 被管进程 / 本机文件）。
不得把本机制用于对第三方系统的报复性操作。
"""

from __future__ import annotations

import json
import os
import secrets
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Union

from .audit import AuditLog
from .control import SessionControl, safe_session_name
from .models import Decision, Severity, Verdict
from .policy import Policy, path_matches

KNOWN_COUNTERMEASURE_ACTIONS = ["freeze", "lockdown", "terminate", "quarantine", "evidence", "alert"]
KNOWN_WHEN_KEYS = ["detectors", "min_severity", "verdict", "freeze_triggered", "blocked_in_window", "paths"]


def _top_severity(findings: Sequence[Any]) -> Severity:
    best = Severity.INFO
    for finding in findings:
        severity = getattr(finding, "severity", None)
        if isinstance(severity, Severity) and severity.rank > best.rank:
            best = severity
    return best


@dataclass
class CountermeasureResult:
    """一次反制动作的执行结果。"""

    rule: str
    action: str
    status: str  # applied / skipped / failed
    detail: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"rule": self.rule, "action": self.action, "status": self.status, "detail": self.detail}


class CounterStrike:
    """按策略规则对攻击性行为执行主动反制。"""

    def __init__(
        self,
        *,
        state_dir: Union[str, Path],
        control: SessionControl,
        policy: Optional[Policy] = None,
        hooks: Optional[Dict[str, Callable[..., Any]]] = None,
        registry: Optional[Any] = None,
        audit: Optional[Callable[[str, str, Any], None]] = None,
        enabled: Optional[bool] = None,
    ) -> None:
        self.state_dir = Path(state_dir).expanduser()
        self.control = control
        self.policy = policy
        self.hooks: Dict[str, Callable[..., Any]] = dict(hooks or {})
        self.registry = registry
        self.audit = audit
        self.enabled_override = enabled
        self.incidents_dir = self.state_dir / "incidents"

    # ------------------------------------------------------------------ 入口

    def enabled(self) -> bool:
        if self.enabled_override is not None:
            return bool(self.enabled_override)
        return bool(self.policy is not None and self.policy.countermeasures_enabled())

    def respond(self, session: str, decision: Decision, state: Any) -> List[CountermeasureResult]:
        """对一次判定执行匹配到的全部反制规则，返回执行结果列表。"""
        if not self.enabled() or self.policy is None:
            return []
        if decision.allowed:
            return []  # 放行的动作（含人工批准）不反制
        results: List[CountermeasureResult] = []
        fired: set = state.flags.setdefault("counterstrike_fired", set())
        for rule in self.policy.countermeasure_rules():
            if not bool(rule.get("enabled", True)):
                continue
            rule_id = str(rule.get("id", "?"))
            if not bool(rule.get("repeat", False)) and rule_id in fired:
                continue
            if not self._matches(rule.get("when") or {}, decision, state):
                continue
            fired.add(rule_id)
            actions = [str(item) for item in rule.get("actions", [])]
            ordered = [a for a in actions if a != "evidence"]
            if "evidence" in actions:
                ordered.append("evidence")  # 取证始终最后执行，以收录其他反制结果
            for action in ordered:
                try:
                    result = self._execute(action, rule_id, session, decision, state, results)
                except Exception as exc:  # noqa: BLE001 —— 反制失败不能影响判定主流程
                    result = CountermeasureResult(rule_id, action, "failed", f"{type(exc).__name__}: {exc}")
                results.append(result)
                if self.audit is not None:
                    try:
                        self.audit(session, "countermeasure", result.to_dict())
                    except Exception:  # noqa: BLE001
                        pass
        return results

    # ------------------------------------------------------------------ 条件

    def _matches(self, when: Dict[str, Any], decision: Decision, state: Any) -> bool:
        if not when:
            return False  # 空条件不触发
        detectors = when.get("detectors")
        if detectors:
            names = {finding.detector for finding in decision.findings}
            wanted = [str(detectors)] if isinstance(detectors, str) else [str(item) for item in detectors]
            if not names.intersection(wanted):
                return False
        min_severity = when.get("min_severity")
        if min_severity:
            try:
                floor = Severity(str(min_severity))
            except ValueError:
                return False
            if _top_severity(decision.findings).rank < floor.rank:
                return False
        verdict = when.get("verdict")
        if verdict:
            allowed = [verdict] if isinstance(verdict, str) else list(verdict)
            if decision.verdict.value not in [str(item) for item in allowed]:
                return False
        if when.get("freeze_triggered") and not decision.frozen:
            return False
        if when.get("paths"):
            raw = when["paths"]
            patterns = [str(raw)] if isinstance(raw, str) else [str(item) for item in raw]
            if not path_matches(decision.action.path, patterns):
                return False
        if "blocked_in_window" in when:
            try:
                threshold = int(when["blocked_in_window"])
            except (TypeError, ValueError):
                return False
            if len(state.block_times) < threshold:
                return False
        return True

    # ------------------------------------------------------------------ 动作

    def _execute(
        self,
        action: str,
        rule_id: str,
        session: str,
        decision: Decision,
        state: Any,
        prior: List[CountermeasureResult],
    ) -> CountermeasureResult:
        if action == "freeze":
            return self._act_freeze(rule_id, session, decision, state)
        if action == "lockdown":
            return self._act_lockdown(rule_id, session, decision, state)
        if action == "terminate":
            return self._act_terminate(rule_id, session, decision)
        if action == "quarantine":
            return self._act_quarantine(rule_id, session, decision)
        if action == "evidence":
            return self._act_evidence(rule_id, session, decision, state, prior)
        if action == "alert":
            return self._act_alert(rule_id, session, decision, state)
        return CountermeasureResult(rule_id, action, "failed", f"未知反制动作：{action}")

    def _act_freeze(self, rule_id: str, session: str, decision: Decision, state: Any) -> CountermeasureResult:
        if state.frozen and self.control.frozen_info(session) is not None:
            return CountermeasureResult(rule_id, "freeze", "skipped", "会话已处于冻结状态")
        reason = f"主动反制（规则 {rule_id}）：{decision.action.describe()}"
        self.control.freeze(session, reason=reason, by="guard:counterstrike")
        state.frozen = True
        return CountermeasureResult(
            rule_id, "freeze", "applied",
            f"已冻结会话；解除：antiai release --session {session}",
        )

    def _act_lockdown(self, rule_id: str, session: str, decision: Decision, state: Any) -> CountermeasureResult:
        locked, _why = self.control.is_lockdown(session)
        if locked:
            return CountermeasureResult(rule_id, "lockdown", "skipped", "会话已处于封锁状态")
        lead = (decision.reasons[0] if decision.reasons else decision.reason_text)[:140]
        reason = f"主动反制（规则 {rule_id}）：{lead}"
        self.control.lockdown(session, reason=reason, by="guard:counterstrike")
        return CountermeasureResult(
            rule_id, "lockdown", "applied",
            f"已封锁会话：禁止执行类工具与全部对外网络，保留只读观察"
            f"（解除：antiai unlock --session {session}）",
        )

    def _act_terminate(self, rule_id: str, session: str, decision: Decision) -> CountermeasureResult:
        hook = self.hooks.get("terminate")
        if callable(hook):
            hook(
                {
                    "session": session,
                    "rule": rule_id,
                    "action": decision.action.to_dict(),
                    "reason": decision.reason_text,
                }
            )
            return CountermeasureResult(rule_id, "terminate", "applied", "已调用 terminate 钩子（由部署侧执行终止）")
        config = self.policy.terminate_config() if self.policy is not None else {}
        pattern = str(config.get("pattern") or "").strip()
        if config.get("enabled") and pattern:
            command = ["pkill", "-f", pattern]
            if bool(config.get("dry_run", True)):
                return CountermeasureResult(
                    rule_id, "terminate", "skipped",
                    f"策略 terminate.dry_run=true：仅演练不执行（{' '.join(command)}）",
                )
            proc = subprocess.run(command, capture_output=True, text=True, check=False)
            if proc.returncode == 0:
                return CountermeasureResult(rule_id, "terminate", "applied", f"已执行 {' '.join(command)}（匹配进程已终止）")
            if proc.returncode == 1:
                return CountermeasureResult(rule_id, "terminate", "skipped", f"未匹配到进程：{pattern}")
            return CountermeasureResult(
                rule_id, "terminate", "failed", f"pkill 返回 {proc.returncode}：{proc.stderr.strip()[:200]}"
            )
        return CountermeasureResult(
            rule_id, "terminate", "skipped",
            "未配置终止方式：用 Guard(hooks={'terminate': fn}) 注入，或启用策略 countermeasures.terminate.enabled/pattern",
        )

    def _act_quarantine(self, rule_id: str, session: str, decision: Decision) -> CountermeasureResult:
        path = decision.action.path
        if not path:
            return CountermeasureResult(rule_id, "quarantine", "skipped", "动作没有文件路径，无需隔离")
        if not path_matches(path, self.policy.quarantine_paths()):
            return CountermeasureResult(rule_id, "quarantine", "skipped", f"路径不在隔离清单内：{path}")
        target = Path(path)
        if not target.is_file():
            return CountermeasureResult(rule_id, "quarantine", "skipped", f"文件不存在或不可隔离：{path}")
        entry = self._quarantine_move(target, session, rule_id)
        return CountermeasureResult(
            rule_id, "quarantine", "applied",
            f"已隔离涉密文件：{path} → 保险库 {entry}（恢复：antiai quarantine restore {entry}）",
        )

    def _quarantine_move(self, target: Path, session: str, rule_id: str) -> str:
        stamp = time.strftime("%Y%m%d-%H%M%S")
        entry_name = f"{stamp}_{target.name}"
        vault = self.state_dir / "quarantine" / entry_name
        vault.mkdir(parents=True, exist_ok=True)
        moved = vault / target.name
        os.replace(str(target), str(moved))
        try:
            os.chmod(moved, 0o600)
        except OSError:
            pass
        meta = {
            "entry": entry_name,
            "original_path": str(target),
            "session": session,
            "rule": rule_id,
            "ts": time.time(),
        }
        (vault / "meta.json").write_text(
            json.dumps(meta, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        return entry_name

    def _act_evidence(
        self,
        rule_id: str,
        session: str,
        decision: Decision,
        state: Any,
        prior: List[CountermeasureResult],
    ) -> CountermeasureResult:
        incident = self._build_incident(rule_id, session, decision, state, prior)
        written = self._write_incident(incident)
        return CountermeasureResult(
            rule_id, "evidence", "applied", f"已生成事件报告：{written['markdown']}"
        )

    def _act_alert(self, rule_id: str, session: str, decision: Decision, state: Any) -> CountermeasureResult:
        payload = {
            "ts": time.time(),
            "session": session,
            "rule": rule_id,
            "verdict": decision.verdict.value,
            "severity": _top_severity(decision.findings).value,
            "action": decision.action.to_dict(),
            "reasons": list(decision.reasons[:5]),
            "frozen": decision.frozen,
        }
        hook = self.hooks.get("alert")
        if callable(hook):
            hook(payload)
            return CountermeasureResult(rule_id, "alert", "applied", "已调用 alert 钩子")
        log_path = self.state_dir / "alerts.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with log_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, ensure_ascii=False) + "\n")
        return CountermeasureResult(rule_id, "alert", "applied", f"已写入告警日志：{log_path}")

    # ------------------------------------------------------------------ 取证

    def _audit_tail(self, session: str, limit: int = 20) -> List[Dict[str, Any]]:
        log = AuditLog(self.state_dir / "audit" / f"{safe_session_name(session)}.jsonl")
        tail: List[Dict[str, Any]] = []
        for record in log.tail(limit):
            payload = record.get("payload") if isinstance(record.get("payload"), dict) else {}
            action = payload.get("action")
            reasons = payload.get("reasons") or []
            if reasons:
                detail: Any = reasons[0]
            elif isinstance(action, dict):
                detail = action.get("tool")
            else:
                detail = payload.get("detail")  # 冻结 / 反制等事件的说明
            tail.append(
                {
                    "seq": record.get("seq"),
                    "ts": record.get("ts"),
                    "event": record.get("event"),
                    "verdict": payload.get("verdict"),
                    "detail": (str(detail)[:120] if detail else None),
                }
            )
        return tail

    def _build_incident(
        self,
        rule_id: str,
        session: str,
        decision: Decision,
        state: Any,
        prior: List[CountermeasureResult],
    ) -> Dict[str, Any]:
        canaries: List[Dict[str, Any]] = []
        for finding in decision.findings:
            if finding.detector == "honeytoken":
                canaries.extend(finding.details.get("canaries") or [])
        incident = {
            # 后缀 4 位随机码：同一秒内多次反制不会互相覆盖
            "id": (
                f"{safe_session_name(session)}-{time.strftime('%Y%m%d-%H%M%S')}"
                f"-{secrets.token_hex(2)}"
            ),
            "session": session,
            "ts": time.time(),
            "rule": rule_id,
            "verdict": decision.verdict.value,
            "severity": _top_severity(decision.findings).value,
            "action": decision.action.to_dict(),
            "reasons": list(decision.reasons),
            "matched_rules": list(decision.matched_rules),
            "findings": [finding.to_dict() for finding in decision.findings],
            "canaries": canaries,
            "decoy_deployed": decision.decoy is not None,
            "countermeasures": [result.to_dict() for result in prior],
            "session_counters": {
                "blocked": getattr(state, "blocked", 0),
                "reviewed": getattr(state, "reviewed", 0),
                "allowed": getattr(state, "allowed", 0),
                "blocked_in_window": len(getattr(state, "block_times", []) or []),
                "frozen": bool(getattr(state, "frozen", False)),
            },
            "audit_tail": self._audit_tail(session),
            "advice": self._advice(decision),
            "policy_source": (self.policy.source_path if self.policy is not None else None) or "<内置默认策略>",
        }
        return incident

    @staticmethod
    def _advice(decision: Decision) -> List[str]:
        advice: List[str] = []
        names = {finding.detector for finding in decision.findings}
        if "honeytoken" in names:
            advice.append("蜜罐凭据被触碰：复核被管对象的会话轨迹，追查诱饵内容的来源与去向")
        if "exfiltration" in names:
            advice.append("疑似数据外泄：轮换相关凭据，核查外联目标主机是否已收到数据")
        if names.intersection({"tamper", "self_preservation"}):
            advice.append("护栏资产/监护进程被针对：检查策略文件与审计日志完整性，确认被管进程状态")
        if "privilege_escalation" in names:
            advice.append("提权尝试：复核 sudo 记录与近期权限变更")
        if "evasion" in names:
            advice.append("反侦察行为：检查历史记录/日志是否被清理，必要时从备份恢复")
        if "runaway" in names:
            advice.append("失控循环：确认提示词或工具调用链是否存在死循环")
        advice.append("使用 antiai log --verify 校验审计链完整性；必要时 antiai stop-all 全局停机")
        return advice

    def _write_incident(self, incident: Dict[str, Any]) -> Dict[str, str]:
        self.incidents_dir.mkdir(parents=True, exist_ok=True)
        json_path = self.incidents_dir / f"{incident['id']}.json"
        md_path = self.incidents_dir / f"{incident['id']}.md"
        json_path.write_text(
            json.dumps(incident, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        md_path.write_text(self._render_markdown(incident), encoding="utf-8")
        return {"json": str(json_path), "markdown": str(md_path)}

    @staticmethod
    def _render_markdown(incident: Dict[str, Any]) -> str:
        lines: List[str] = []
        lines.append(f"# ANTIAI 事件报告 · {incident['id']}")
        lines.append("")
        lines.append("| 字段 | 值 |")
        lines.append("| :--- | :--- |")
        lines.append(f"| 会话 | `{incident['session']}` |")
        lines.append(f"| 时间 | {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(incident['ts']))} |")
        lines.append(f"| 触发规则 | `{incident['rule']}` |")
        lines.append(f"| 判定 | `{incident['verdict']}`（最高严重级 `{incident['severity']}`） |")
        lines.append(f"| 冻结 | {'是' if incident['session_counters']['frozen'] else '否'} |")
        lines.append(f"| 诱饵投放 | {'是' if incident['decoy_deployed'] else '否'} |")
        lines.append(f"| 策略来源 | `{incident['policy_source']}` |")
        lines.append("")
        action = incident["action"]
        lines.append("## 触发动作")
        lines.append("")
        lines.append(f"- 工具：`{action.get('tool')}`")
        for key in ("command", "path", "host"):
            if action.get(key):
                lines.append(f"- {key}：`{action[key]}`")
        if action.get("args"):
            lines.append(f"- 参数：`{json.dumps(action['args'], ensure_ascii=False)[:400]}`")
        lines.append("")
        if incident["canaries"]:
            lines.append("## 蜜罐命中（确凿的恶意意图证据）")
            lines.append("")
            lines.append("| Canary | 诱饵文件 | 类型 | 投放会话 |")
            lines.append("| :--- | :--- | :--- | :--- |")
            for canary in incident["canaries"]:
                lines.append(
                    f"| `{canary.get('id')}` | `{canary.get('path')}` | {canary.get('kind')} | `{canary.get('session')}` |"
                )
            lines.append("")
        lines.append("## 检测依据")
        lines.append("")
        for reason in incident["reasons"]:
            lines.append(f"- {reason}")
        lines.append("")
        if incident["countermeasures"]:
            lines.append("## 已执行反制")
            lines.append("")
            lines.append("| 规则 | 动作 | 结果 | 说明 |")
            lines.append("| :--- | :--- | :--- | :--- |")
            for item in incident["countermeasures"]:
                lines.append(
                    f"| `{item['rule']}` | `{item['action']}` | {item['status']} | {item['detail']} |"
                )
            lines.append("")
        lines.append("## 会话计数")
        lines.append("")
        counters = incident["session_counters"]
        lines.append(
            f"- 累计拦截 {counters['blocked']} 次 / 放行 {counters['allowed']} 次 / 需确认 {counters['reviewed']} 次"
            f"（窗口内拦截 {counters['blocked_in_window']} 次）"
        )
        lines.append("")
        if incident["audit_tail"]:
            lines.append("## 审计尾部（最近记录）")
            lines.append("")
            lines.append("| # | 时间 | 事件 | 判定 | 摘要 |")
            lines.append("| :--- | :--- | :--- | :--- | :--- |")
            for record in incident["audit_tail"]:
                stamp = time.strftime("%H:%M:%S", time.localtime(float(record.get("ts") or 0)))
                summary = str(record.get("detail") or "")[:80].replace("|", "\\|")
                lines.append(
                    f"| {record.get('seq')} | {stamp} | {record.get('event')} | {record.get('verdict') or '-'} | {summary} |"
                )
            lines.append("")
        lines.append("## 处置建议")
        lines.append("")
        for item in incident["advice"]:
            lines.append(f"- {item}")
        lines.append("")
        return "\n".join(lines)
