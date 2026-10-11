"""
Guard：护栏核心。

判定流水线（对每一个动作依次执行）::

    动作 → 归一化(adapters) → 冻结/停机检查(control)
                              → 规则裁决(policy)
                              → 检测器扫描(detectors)
                              → 取最严格判定 → 计数/冻结升级 → 审计(audit)
                              → Decision

设计原则
--------
- **失败封闭（fail-closed）**：无规则命中走 ``default_verdict``（默认 review）；
  检测器异常也保守阻断。
- **检测器是硬约束**：allow 规则无法漂白检测器命中项。
- **升级阶梯**：allow → review → block → freeze（会话冻结）→ stop-all（全局停机），
  每一步都留审计。被拦截次数达到 ``session.freeze_after_blocks`` 时自动冻结，
  这是对"持续试探 / 反击"的最终反制。

用法示例::

    from antiai import Guard

    guard = Guard(session_id="agent-1")          # 默认读当前目录策略或内置策略
    decision = guard.evaluate({"tool": "file.read", "args": {"path": "notes.md"}})
    if not decision.allowed:
        print("已阻止：", decision.reason_text)

    @guard.tool("file.write")
    def write_file(path: str, content: str):
        ...

    shell = guard.shell()
    shell.run("echo hello")                      # 先判定，后执行
"""

from __future__ import annotations

import functools
import os
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Union

from .adapters import enrich_action, normalize_action
from .audit import AuditLog
from .control import SessionControl, safe_session_name
from .counterstrike import CounterStrike, CountermeasureResult
from .detectors import Detector, HoneytokenDetector, SessionState, build_detectors, is_exec_like
from .errors import ActionBlocked, SessionFrozen
from .honeytokens import Honeytoken, HoneytokenRegistry
from .models import Action, Decision, Finding, Severity, Verdict, most_restrictive
from .policy import Policy, Rule, glob_any, load_policy

__all__ = ["Guard", "GuardedShell", "ShellResult", "default_state_dir"]

Approver = Callable[[Action, List[str]], bool]
Hook = Callable[..., Any]

# 封锁（lockdown）状态下受限的工具：执行类 + 对外网络类
_LOCKDOWN_EGRESS_GLOBS = (
    "http.*",
    "https.*",
    "web.*",
    "net.*",
    "fetch*",
    "request*",
    "curl*",
    "download*",
    "upload*",
    "ssh*",
    "scp*",
    "ftp*",
    "mail*",
    "smtp*",
)


def _restricted_under_lockdown(action: Action) -> bool:
    """封锁状态下被禁止的动作类型：执行类工具、对外网络、带主机的调用。"""
    if is_exec_like(action.tool):
        return True
    if action.host:
        return True
    return glob_any(action.tool, _LOCKDOWN_EGRESS_GLOBS)


def default_state_dir() -> Path:
    """默认状态目录：``$ANTIAI_STATE_DIR`` 或 ``~/.antiai``。"""
    env = os.environ.get("ANTIAI_STATE_DIR")
    if env:
        return Path(env).expanduser()
    return Path.home() / ".antiai"


def _window_label(window: float) -> str:
    if window <= 0:
        return "累计"
    if window < 60:
        return f"最近 {window:g} 秒内"
    if window < 3600:
        return f"最近 {window / 60:g} 分钟内"
    return f"最近 {window / 3600:g} 小时内"


class Guard:
    """行为防护护栏。一个 Guard 实例可服务多个会话（用 session_id 区分）。"""

    def __init__(
        self,
        policy: Optional[Policy] = None,
        *,
        state_dir: Union[str, Path, None] = None,
        session_id: str = "default",
        advisory: bool = False,
        audit: bool = True,
        persist_counters: bool = True,
        hooks: Optional[Dict[str, Hook]] = None,
        aggressive: Optional[bool] = None,
    ) -> None:
        self.policy = policy if policy is not None else load_policy()
        self.state_dir = Path(state_dir).expanduser() if state_dir else default_state_dir()
        self.session_id = session_id
        self.advisory = advisory
        self.audit_enabled = audit
        self.persist_counters = persist_counters
        self.control = SessionControl(self.state_dir)
        self.detectors: List[Detector] = build_detectors(self.policy)
        self.honeytokens = HoneytokenRegistry(self.state_dir)
        if self.policy.detector_enabled("honeytoken"):
            self.detectors.append(HoneytokenDetector(self.honeytokens))
        self.counterstrike = CounterStrike(
            state_dir=self.state_dir,
            control=self.control,
            policy=self.policy,
            hooks=hooks,
            registry=self.honeytokens,
            audit=self._write_audit,
            enabled=aggressive,
        )
        self._states: Dict[str, SessionState] = {}
        self._audit_logs: Dict[str, AuditLog] = {}
        self._lock = threading.RLock()

    # ------------------------------------------------------------------ 状态

    def state(self, session_id: Optional[str] = None) -> SessionState:
        session = session_id or self.session_id
        with self._lock:
            if session not in self._states:
                state = SessionState(session_id=session)
                # 恢复跨进程持久化的拦截计数（一次性 CLI 门禁也参与冻结累计）
                counters = self.control.read_counters(session) if self.persist_counters else {}
                if counters:
                    state.blocked = int(counters.get("blocked", 0) or 0)
                    state.reviewed = int(counters.get("reviewed", 0) or 0)
                    state.allowed = int(counters.get("allowed", 0) or 0)
                    for stamp in counters.get("block_times", []) or []:
                        if isinstance(stamp, (int, float)):
                            state.block_times.append(float(stamp))
                self._states[session] = state
            return self._states[session]

    def _persist_counters(self, session: str, state: SessionState) -> None:
        if not self.persist_counters:
            return
        try:
            self.control.write_counters(
                session,
                {
                    "blocked": state.blocked,
                    "reviewed": state.reviewed,
                    "allowed": state.allowed,
                    "block_times": list(state.block_times)[-100:],
                    "updated": time.time(),
                },
            )
        except OSError:
            pass  # 计数持久化失败不应中断判定主流程（审计仍然完整）

    def _audit_for(self, session: str) -> Optional[AuditLog]:
        if not self.audit_enabled:
            return None
        with self._lock:
            if session not in self._audit_logs:
                self._audit_logs[session] = AuditLog(
                    self.state_dir / "audit" / f"{safe_session_name(session)}.jsonl"
                )
            return self._audit_logs[session]

    def _write_audit(self, session: str, event: str, payload: Any) -> None:
        log = self._audit_for(session)
        if log is None:
            return
        data = payload.to_dict() if isinstance(payload, Decision) else payload
        log.append(event=event, session=session, payload=data)

    # ------------------------------------------------------------------ 判定

    def evaluate(
        self,
        action: Any,
        *,
        session_id: Optional[str] = None,
        approver: Optional[Approver] = None,
    ) -> Decision:
        """对一个动作做出判定。``action`` 可以是 Action / dict / str（支持 OpenAI 工具调用形态）。"""
        act = self._coerce(action, session_id)
        session = act.session_id
        state = self.state(session)

        # 0) 冻结 / 全局停机：最高优先级，不可绕过
        blocked, why = self.control.is_blocked(session)
        if blocked:
            finding = Finding(
                detector="lockout",
                reason=str(why),
                severity=Severity.CRITICAL,
                verdict=Verdict.BLOCK,
            )
            decision = Decision(
                action=act,
                verdict=Verdict.BLOCK,
                allowed=bool(self.advisory),  # 观察模式不实际阻断
                reasons=[str(why)],
                findings=[finding],
                frozen=True,
                advisory=self.advisory,
            )
            self._write_audit(session, "action", decision)
            return decision

        # 1) 规则裁决
        rule_verdict, winning_rules = self.policy.decide_rules(act)

        # 2) 检测器扫描（异常时 fail-closed）；封锁状态先注入硬限制项
        findings: List[Finding] = []
        lockdown_active, lockdown_reason = self.control.is_lockdown(session)
        if lockdown_active and not self.advisory and _restricted_under_lockdown(act):
            findings.append(
                Finding(
                    detector="lockdown",
                    reason=(
                        f"{lockdown_reason}；执行类工具与对外网络在封锁解除前一律阻止"
                        f"（解除：antiai unlock --session {session}）"
                    ),
                    severity=Severity.CRITICAL,
                    verdict=Verdict.BLOCK,
                )
            )
        for detector in self.detectors:
            try:
                findings.extend(detector.check(act, state, self.policy))
            except Exception as exc:  # noqa: BLE001 —— 保守阻断优于放行
                findings.append(
                    Finding(
                        detector=getattr(detector, "name", "unknown"),
                        reason=f"检测器执行异常，保守阻断：{exc}",
                        severity=Severity.CRITICAL,
                        verdict=Verdict.BLOCK,
                    )
                )

        # 3) 合成判定：规则与检测项共同取最严格
        candidates = [finding.verdict for finding in findings]
        if rule_verdict is not None:
            candidates.append(rule_verdict)
        verdict = most_restrictive(candidates) if candidates else self.policy.default_verdict

        reasons = self._reason_list(winning_rules, findings)
        if not reasons:
            reasons = [f"无规则命中，采用默认判定：{self.policy.default_verdict.label}"]

        # 4) 人工确认（review）
        requires_approval = verdict is Verdict.REVIEW
        approved = False
        allowed = verdict is Verdict.ALLOW
        if requires_approval and approver is not None:
            try:
                approved = bool(approver(act, reasons))
            except Exception:  # noqa: BLE001 —— 审批异常视为不批准
                approved = False
            allowed = approved
        if self.advisory:
            allowed = True

        # 4.5) 诱饵投放（deception）：被阻止的窃取动作"拿到"假凭据，攻击方以为得手
        decoy: Optional[str] = None
        if not allowed and not self.advisory and self.policy.deception_enabled():
            decoy_kind = self.policy.decoy_for(act.path)
            if decoy_kind:
                token, decoy = self.honeytokens.render_and_register(
                    decoy_kind, path=str(act.path), session=session
                )
                reasons.append(
                    f"[诱饵] 已投放 canary 诱饵 {token.id}（{decoy_kind}）"
                    "—— 该内容一旦被外发或使用即可精确溯源"
                )

        # 5) 计数与冻结升级（计数跨进程持久化：一次性 CLI 门禁同样参与累计）
        now = time.time()
        if verdict is Verdict.BLOCK:
            state.blocked += 1
            state.block_times.append(now)
            window = self.policy.freeze_window_seconds()
            if window > 0:
                cutoff = now - window
                while state.block_times and state.block_times[0] < cutoff:
                    state.block_times.popleft()
            effective = len(state.block_times)
            threshold = self.policy.freeze_after_blocks()
            if not self.advisory and not state.frozen and effective >= threshold:
                reason = (
                    f"会话{_window_label(window)}被拦截 {effective} 次（阈值 {threshold}），"
                    "触发自动冻结（防止持续试探与反击）"
                )
                self.control.freeze(session, reason=reason, by="guard:auto")
                state.frozen = True
                findings.append(
                    Finding(
                        detector="lockout",
                        reason=f"[冻结] {reason}",
                        severity=Severity.CRITICAL,
                        verdict=Verdict.BLOCK,
                    )
                )
                # 重新组装依据（含冻结项），保持严重级降序
                reasons = self._reason_list(winning_rules, findings)
                self._write_audit(
                    session,
                    "freeze",
                    {
                        "reason": reason,
                        "by": "guard:auto",
                        "blocked": state.blocked,
                        "effective_in_window": effective,
                        "window_seconds": window,
                        "action": act.to_dict(),
                    },
                )
        elif verdict is Verdict.REVIEW:
            state.reviewed += 1
        else:
            state.allowed += 1
        self._persist_counters(session, state)

        decision = Decision(
            action=act,
            verdict=verdict,
            allowed=allowed,
            reasons=reasons,
            findings=findings,
            matched_rules=[rule.id for rule in winning_rules],
            frozen=state.frozen,
            requires_approval=requires_approval,
            approved=approved,
            advisory=self.advisory,
            decoy=decoy,
        )

        # 6) 主动反制：封锁 / 冻结 / 隔离 / 取证 / 告警 / 终止（观察模式不执行）
        if not self.advisory:
            results: List[CountermeasureResult] = self.counterstrike.respond(session, decision, state)
            if results:
                decision.countermeasures = [result.to_dict() for result in results]
                if any(
                    result.action == "freeze" and result.status == "applied" for result in results
                ):
                    decision.frozen = True
                    decision.reasons.append("[反制] 会话已被主动冻结")

        self._write_audit(session, "action", decision)
        return decision

    def check(
        self,
        action: Any,
        *,
        session_id: Optional[str] = None,
        approver: Optional[Approver] = None,
    ) -> Decision:
        """判定并在不被允许时抛异常（``ActionBlocked`` / ``SessionFrozen``）。"""
        decision = self.evaluate(action, session_id=session_id, approver=approver)
        if not decision.allowed:
            raise SessionFrozen(decision) if decision.frozen else ActionBlocked(decision)
        return decision

    def _coerce(self, action: Any, session_id: Optional[str]) -> Action:
        if isinstance(action, Action):
            if session_id:
                action.session_id = session_id
            return enrich_action(action)
        return normalize_action(action, session_id=session_id or self.session_id)

    @staticmethod
    def _reason_list(rules: Sequence[Rule], findings: Sequence[Finding]) -> List[str]:
        """组装依据列表，按严重级降序排列（最关键的拦截依据排在最前）。"""
        entries: List[tuple] = []
        for rule in rules:
            entries.append(
                (
                    rule.severity.rank,
                    f"[规则 {rule.id}/{rule.severity.value}] {rule.reason or rule.verdict.label}",
                )
            )
        for finding in findings:
            entries.append(
                (
                    finding.severity.rank,
                    f"[检测器 {finding.detector}/{finding.severity.value}] {finding.reason}",
                )
            )
        entries.sort(key=lambda item: item[0], reverse=True)
        return [text for _, text in entries]

    # ------------------------------------------------------------------ 工具封装

    def tool(self, name: Optional[str] = None, *, on_block: str = "raise"):
        """装饰器：给 Python 工具函数套上护栏。

        ``on_block="raise"``（默认）在阻止时抛 ``ActionBlocked``；
        ``on_block="return"`` 返回结构化拒绝对话（更适合直接回传给智能体）。
        """

        def decorate(fn: Callable[..., Any]) -> Callable[..., Any]:
            tool_name = name or getattr(fn, "__name__", "tool")

            @functools.wraps(fn)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                snapshot: Dict[str, Any] = {"positional": [str(item) for item in args]}
                snapshot.update(kwargs)
                action = enrich_action(
                    Action(tool=tool_name, args=snapshot, session_id=self.session_id, raw=kwargs)
                )
                decision = self.evaluate(action)
                if not decision.allowed:
                    if on_block == "return":
                        if decision.decoy is not None:
                            return decision.decoy  # 诱饵投放：攻击方"拿到"假内容，实则已被标记
                        return {
                            "blocked": True,
                            "verdict": decision.verdict.value,
                            "reason": decision.reason_text,
                            "decision": decision.to_dict(),
                        }
                    raise SessionFrozen(decision) if decision.frozen else ActionBlocked(decision)
                return fn(*args, **kwargs)

            wrapper.antiai_tool = tool_name  # type: ignore[attr-defined]
            return wrapper

        return decorate

    def shell(self, *, session_id: Optional[str] = None, timeout: float = 30.0) -> "GuardedShell":
        """返回受护栏约束的 Shell 执行器。"""
        return GuardedShell(self, session_id=session_id or self.session_id, timeout=timeout)

    @property
    def decoys(self) -> "DecoyFactory":
        """假情报生成器：生成诱饵文档包 / 提示词片段，canary 自动登记、可溯源。"""
        from .decoys import DecoyFactory

        return DecoyFactory(self.honeytokens, session=self.session_id)

    # ------------------------------------------------------------------ 冻结管理

    def freeze(self, reason: str = "人工冻结", *, session_id: Optional[str] = None, by: str = "human") -> Dict[str, Any]:
        session = session_id or self.session_id
        info = self.control.freeze(session, reason=reason, by=by)
        self.state(session).frozen = True
        self._write_audit(session, "freeze", info)
        return info

    def release(self, *, session_id: Optional[str] = None, by: str = "human") -> bool:
        """解除冻结，并清零拦截计数（让"人工放行"成为真正的重置）。"""
        session = session_id or self.session_id
        released = self.control.release(session)
        state = self.state(session)
        state.frozen = False
        state.blocked = 0
        state.block_times.clear()
        self.control.clear_counters(session)
        self._persist_counters(session, state)
        if released:
            self._write_audit(session, "release", {"by": by, "session": session})
        return released

    def lockdown(self, reason: str = "人工封锁", *, session_id: Optional[str] = None, by: str = "human") -> Dict[str, Any]:
        """封锁会话：禁止执行类工具与对外网络，保留只读观察。"""
        session = session_id or self.session_id
        info = self.control.lockdown(session, reason=reason, by=by)
        self._write_audit(session, "lockdown", info)
        return info

    def unlock(self, *, session_id: Optional[str] = None, by: str = "human") -> bool:
        session = session_id or self.session_id
        unlocked = self.control.unlock(session)
        if unlocked:
            self._write_audit(session, "unlock", {"by": by, "session": session})
        return unlocked

    def status(self, *, session_id: Optional[str] = None) -> Dict[str, Any]:
        session = session_id or self.session_id
        state = self.state(session)
        info = self.control.status(session)
        info.update(
            {
                "blocked": state.blocked,
                "reviewed": state.reviewed,
                "allowed": state.allowed,
                "policy_source": self.policy.source_path or "<内置默认策略>",
                "detectors": [detector.name for detector in self.detectors],
                "countermeasures": {
                    "enabled": self.counterstrike.enabled(),
                    "rules": [str(rule.get("id")) for rule in self.policy.countermeasure_rules()],
                },
                "honeytokens": len(self.honeytokens.load()),
            }
        )
        log = self._audit_for(session)
        if log is not None:
            info["audit_path"] = str(log.path)
            info["audit_counts"] = log.counts()
            verified, bad_seq = log.verify()
            info["audit_verified"] = verified
            if not verified:
                info["audit_first_bad_seq"] = bad_seq
        return info


@dataclass
class ShellResult:
    """``GuardedShell`` 的执行结果（被阻止时 ``blocked=True``）。"""

    blocked: bool
    command: str
    decision: Optional[Decision] = None
    returncode: Optional[int] = None
    stdout: str = ""
    stderr: str = ""

    def to_dict(self) -> Dict[str, Any]:
        data: Dict[str, Any] = {
            "blocked": self.blocked,
            "command": self.command,
            "returncode": self.returncode,
            "stdout": self.stdout,
            "stderr": self.stderr,
        }
        if self.decision is not None:
            data["decision"] = self.decision.to_dict()
        return data


class GuardedShell:
    """先判定、后执行的 Shell 执行器。"""

    def __init__(self, guard: Guard, *, session_id: str = "default", timeout: float = 30.0) -> None:
        self.guard = guard
        self.session_id = session_id
        self.timeout = timeout

    def check(self, command: str, *, approver: Optional[Approver] = None) -> Decision:
        """只做判定，不执行；``review`` 判定可通过 ``approver`` 批准。"""
        return self.guard.evaluate(
            Action(tool="shell.exec", command=str(command), session_id=self.session_id, raw=command),
            approver=approver,
        )

    def run(
        self,
        command: str,
        *,
        timeout: Optional[float] = None,
        on_block: str = "raise",
        cwd: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
        approver: Optional[Approver] = None,
    ) -> ShellResult:
        command = str(command)
        decision = self.check(command, approver=approver)
        if not decision.allowed:
            if on_block == "return":
                return ShellResult(blocked=True, command=command, decision=decision)
            raise SessionFrozen(decision) if decision.frozen else ActionBlocked(decision)
        try:
            proc = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout if timeout is not None else self.timeout,
                cwd=cwd,
                env=env,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return ShellResult(
                blocked=False,
                command=command,
                decision=decision,
                returncode=None,
                stderr=f"命令执行超时（{timeout if timeout is not None else self.timeout}s）",
            )
        return ShellResult(
            blocked=False,
            command=command,
            decision=decision,
            returncode=proc.returncode,
            stdout=proc.stdout or "",
            stderr=proc.stderr or "",
        )
