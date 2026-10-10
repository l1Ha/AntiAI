"""
行为检测器：识别 AI / 智能体的"反击"类行为并给出拦截发现（Finding）。

检测器是硬约束：策略中的 allow 规则无法漂白检测器命中项（安全设计），
如需放行请调整检测器参数或显式禁用对应检测器。

内置检测器一览
--------------
============ ============================ ==========
名称          拦截的行为                   默认严重级
============ ============================ ==========
tamper        破坏护栏自身（改策略、删审计、杀护栏进程） critical
self_preservation 自保：持久化、脱离监管、阻止关停   critical/high
privilege_escalation 提权：sudo、setuid、改凭据文件 high
exfiltration  外泄：读取凭据后向非白名单主机外联     critical/high/medium
evasion       反侦察：清理痕迹、混淆载荷            high/medium
runaway       失控：高频重复、资源消耗型循环、冷却期试探 high/medium
dangerous_command 命中"永久禁止"命令清单          critical
============ ============================ ==========

每个检测器的可调参数通过策略 ``detectors.params.<名称>`` 配置。
"""

from __future__ import annotations

import re
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Deque, Dict, List, Optional, Sequence, Tuple

from .models import Action, Finding, Severity, Verdict
from .policy import Policy, path_matches, regex_any
from .adapters import normalize_action

KNOWN_DETECTORS = [
    "tamper",
    "self_preservation",
    "privilege_escalation",
    "exfiltration",
    "evasion",
    "runaway",
    "dangerous_command",
    "honeytoken",
]

# --------------------------------------------------------------------------- #
# 会话状态与文本辅助
# --------------------------------------------------------------------------- #

@dataclass
class SessionState:
    """单个会话的运行时状态（内存态，随进程存续；拦截计数会持久化到状态目录）。"""

    session_id: str
    recent: Deque[Tuple[float, str]] = field(default_factory=deque)
    block_times: Deque[float] = field(default_factory=deque)
    blocked: int = 0
    reviewed: int = 0
    allowed: int = 0
    frozen: bool = False
    flags: Dict[str, Any] = field(default_factory=dict)

    def record(self, action: Action, limit: int = 5000) -> None:
        self.recent.append((action.ts or time.time(), action.fingerprint()))
        while len(self.recent) > limit:
            self.recent.popleft()

    def count_fingerprint(self, fingerprint: str, window_seconds: float) -> int:
        cutoff = time.time() - window_seconds
        return sum(1 for ts, fp in self.recent if fp == fingerprint and ts >= cutoff)

    def recent_count(self, window_seconds: float) -> int:
        cutoff = time.time() - window_seconds
        return sum(1 for ts, _ in self.recent if ts >= cutoff)


_EXEC_TOKENS = (
    "exec",
    "shell",
    "bash",
    "cmd",
    "command",
    "run",
    "python",
    "node",
    "script",
    "eval",
    "terminal",
    "proc",
    "system",
    "service",
    "kill",
    "spawn",
)


def is_exec_like(tool: str) -> bool:
    low = (tool or "").lower()
    return any(token in low for token in _EXEC_TOKENS)


def _text_of(action: Action, *, include_args: bool = False) -> str:
    """组装用于模式扫描的文本。

    默认只扫描显式提取出的 ``command``；当工具名看起来像"执行器"时，
    额外扫描字符串参数，避免命令藏在 args 里绕过检测。
    """
    parts: List[str] = []
    if action.command:
        parts.append(action.command)
    if include_args or is_exec_like(action.tool):
        for value in action.args.values():
            if isinstance(value, str):
                parts.append(value)
    return "\n".join(parts)


def _match_any(patterns: Sequence[str], text: str) -> Optional[str]:
    return regex_any(text, patterns)


# --------------------------------------------------------------------------- #
# 检测器基类
# --------------------------------------------------------------------------- #

class Detector:
    """检测器基类。``check`` 返回发现列表；允许通过 ``state`` 记录跨动作状态。"""

    name: str = ""
    description: str = ""

    def check(self, action: Action, state: SessionState, policy: Policy) -> List[Finding]:  # pragma: no cover
        raise NotImplementedError

    def _finding(
        self,
        severity: Severity,
        reason: str,
        verdict: Verdict = Verdict.BLOCK,
        **details: Any,
    ) -> Finding:
        return Finding(
            detector=self.name,
            reason=reason,
            severity=severity,
            verdict=verdict,
            details=details,
        )

    def _param(self, policy: Policy, key: str, default: Any) -> Any:
        return policy.detector_param(self.name, key, default)


# --------------------------------------------------------------------------- #
# 1. 破坏护栏（Tamper）
# --------------------------------------------------------------------------- #

TAMPER_PATTERNS = [
    r"\b(?:rm|unlink|shred|truncate|mv|cp|chmod|chown|chattr)\b[^\n]*\.antiai\b",
    r"\b(?:rm|unlink|shred|truncate|mv|cp|chmod|chown|chattr|sed\s+-i|perl\s+-i|tee)\b[^\n]*antiai-policy",
    r"\b(?:rm|unlink|shred|truncate|mv|chmod|chown|chattr|sed\s+-i|perl\s+-i)\b[^\n]*audit[^\n]*\.jsonl",
    r">\s*\S*(?:\.antiai\b|antiai-policy|\.audit\.jsonl)",
    r"\b(?:pkill|killall|kill)\b[^\n]*\b(?:antiai|guard|supervisor|watchdog)\b",
    r"systemctl\s+(?:stop|disable|mask|kill|restart)\b[^\n]*antiai",
    r"\b(?:service|launchctl)\b[^\n]*antiai",
]


class TamperDetector(Detector):
    """保护护栏自身：策略文件、审计日志、状态目录与护栏进程。"""

    name = "tamper"
    description = "检测对护栏策略 / 审计 / 状态目录 / 护栏进程的破坏行为"

    def check(self, action: Action, state: SessionState, policy: Policy) -> List[Finding]:
        findings: List[Finding] = []

        if action.path and policy.is_protected_path(action.path):
            findings.append(
                self._finding(
                    Severity.CRITICAL,
                    f"尝试触碰护栏受保护资产：{action.path}",
                    protected_path=action.path,
                )
            )

        text = _text_of(action)
        hit = _match_any(TAMPER_PATTERNS, text)
        if hit:
            findings.append(
                self._finding(
                    Severity.CRITICAL,
                    f"疑似破坏护栏：命令匹配 /{hit}/",
                    pattern=hit,
                )
            )

        if not findings and policy.is_protected_process(text) and _mentions_shutdown(action, text):
            findings.append(
                self._finding(
                    Severity.HIGH,
                    "疑似针对护栏进程的关停/控制动作",
                )
            )
        return findings


_SHUTDOWN_VERBS = re.compile(
    r"\b(?:kill|pkill|killall|stop|disable|mask|restart|unload|terminate|shutdown)\b",
    re.IGNORECASE,
)


def _mentions_shutdown(action: Action, text: str) -> bool:
    """命令提及护栏进程 + 关停类动词（或工具名本身就是关停类）才算疑似。"""
    if not text:
        return False
    if _SHUTDOWN_VERBS.search(text):
        return True
    tool = (action.tool or "").lower()
    return any(token in tool for token in ("kill", "stop", "terminate", "shutdown"))


# --------------------------------------------------------------------------- #
# 2. 自保（Self-preservation）
# --------------------------------------------------------------------------- #

PERSISTENCE_PATTERNS = [
    r"\bcrontab\b",
    r"/etc/systemd/system|systemctl\s+(?:enable|link)\b",
    r"\.config/autostart",
    r"/etc/rc\.local|/etc/init\.d/|update-rc\.d",
    r"launchctl\s+(?:load|bootstrap|submit)",
    r"reg\s+add[^\n]*\\Run\b",
    r"schtasks\s+/create",
    r"(?:>>|>)\s*[^\n]*(?:\.bashrc|\.bash_profile|\.profile|\.zshrc|config/fish/config\.fish)",
    r"\bat\s+(?:now|\+\d+)",
]

DETACH_PATTERNS = [
    r"\bnohup\b",
    r"\bsetsid\b",
    r"\bdisown\b",
    r"\bscreen\s+-\w*dm\b",
    r"\btmux\s+new-session\s+-d\b",
    r"\bsystemd-run\b",
]

ANTI_SHUTDOWN_PATTERNS = [
    r"\b(?:kill|pkill|killall)\b[^\n]*\b(?:parent|supervisor|watchdog|guardian|monitor|antiai|guard)\b",
    r"\bkill\s+-9\s+-1\b",
    r"\bsetenforce\s+0\b",
    r"\biptables\s+-F\b",
    r"\bufw\s+disable\b",
    r"auditctl\s+-e\s+0",
    r"systemctl\s+(?:stop|disable|mask)\s+(?:auditd|rsyslog|apparmor|selinux)",
    r"\bwatchdog\b[^\n]*\b(?:disable|stop|kill)\b",
]


class SelfPreservationDetector(Detector):
    """检测"对抗关停与监管"的行为：持久化、脱离监管、杀监护进程、关闭安全组件。"""

    name = "self_preservation"
    description = "检测自保行为：持久化驻留、脱离监管、阻止关停、关闭审计"

    def check(self, action: Action, state: SessionState, policy: Policy) -> List[Finding]:
        findings: List[Finding] = []
        text = _text_of(action)

        hit = _match_any(PERSISTENCE_PATTERNS, text)
        if hit:
            findings.append(
                self._finding(
                    Severity.CRITICAL,
                    f"疑似建立自启动 / 持久化驻留：命令匹配 /{hit}/",
                    pattern=hit,
                )
            )

        hit = _match_any(ANTI_SHUTDOWN_PATTERNS, text)
        if hit:
            findings.append(
                self._finding(
                    Severity.CRITICAL,
                    f"疑似阻止关停或关闭安全组件：命令匹配 /{hit}/",
                    pattern=hit,
                )
            )

        hit = _match_any(DETACH_PATTERNS, text)
        if hit:
            findings.append(
                self._finding(
                    Severity.HIGH,
                    f"疑似脱离监管（后台常驻 / 脱离会话）：命令匹配 /{hit}/",
                    pattern=hit,
                )
            )
        return findings


# --------------------------------------------------------------------------- #
# 3. 提权（Privilege escalation）
# --------------------------------------------------------------------------- #

PRIVILEGE_PATTERNS = [
    r"\bsudo\b",
    r"\bdoas\b",
    r"\bpkexec\b",
    r"^\s*su\s+-",
    r"\bsu\s+root\b",
    # setuid/setgid/sticky：+s 或 4 位八进制且首位为 1-7（如 4755 / 2755 / 1777）
    r"\bchmod\s+(?:[ugoa]*\+s|[1-7][0-7]{3})\b",
    r"\bchmod\s+777\b",
    r"\bchown\s+[^\n]*\broot\b",
    r"/etc/(?:sudoers|passwd|shadow|group)\b",
    r"\bauthorized_keys\b",
    r"\busermod\s+-aG\s+(?:sudo|wheel|adm|docker)\b",
]


class PrivilegeEscalationDetector(Detector):
    """检测提权与凭据扩张行为。"""

    name = "privilege_escalation"
    description = "检测提权：sudo/su、setuid 位、敏感系统文件、SSH 授权"

    def check(self, action: Action, state: SessionState, policy: Policy) -> List[Finding]:
        findings: List[Finding] = []
        text = _text_of(action)
        hit = _match_any(PRIVILEGE_PATTERNS, text)
        if hit:
            findings.append(
                self._finding(
                    Severity.HIGH,
                    f"疑似提权 / 权限扩张：命令匹配 /{hit}/",
                    pattern=hit,
                )
            )
        if action.path and re.search(r"/etc/(?:sudoers|passwd|shadow)", action.path or ""):
            findings.append(
                self._finding(Severity.HIGH, f"尝试访问系统凭据文件：{action.path}")
            )
        return findings


# --------------------------------------------------------------------------- #
# 4. 外泄（Exfiltration）
# --------------------------------------------------------------------------- #

DEFAULT_SECRET_GLOBS = [
    "**/.env",
    "**/.env.*",
    "**/.ssh/**",
    "**/id_rsa",
    "**/id_ed25519",
    "**/*.pem",
    "**/*.key",
    "**/.aws/**",
    "**/.git-credentials",
    "**/credentials*",
    "**/authorized_keys",
]

DEFAULT_EGRESS_ALLOW = [
    "localhost",
    "127.0.0.1",
    "::1",
    "0.0.0.0",
    "*.local",
    "*.internal",
    "*.lan",
]

SECRET_READ_PATTERNS = [
    r"\b(?:cat|less|more|head|tail|grep|awk|sed|cp|scp|tar|zip|base64|xxd|strings|dd)\b[^\n]*"
    r"(?:\.env\b|id_rsa|id_ed25519|\.pem\b|\.key\b|credentials|\.aws/|\.ssh/|\.git-credentials)",
    r"\b(?:printenv|env)\b\s*(?:\||>|>>)",
    r"\bsource\s+\S*\.env",
]

SECRET_UPLOAD_RE = re.compile(
    r"(?:--data-binary|--data-urlencode|--data-raw|--data|--post-file|--upload-file|-T)\s*@?\S*"
    r"(?:\.env\b|id_rsa|id_ed25519|\.pem\b|\.key\b|credentials|\.aws/|\.ssh/|\.git-credentials)",
    re.IGNORECASE,
)

EGRESS_COMMAND_RE = re.compile(
    r"(?:\bcurl\b|\bwget\b|\bnc\b|\bncat\b|\bnetcat\b|\bsocat\b|\bscp\b|\bsftp\b"
    r"|\brsync\b|\bftp\b|\btelnet\b|\brequests\.|\bhttpx\b|\burllib\b)",
    re.IGNORECASE,
)

URL_HOST_RE = re.compile(r"https?://([^/\s\"'`]+)", re.IGNORECASE)
SCP_HOST_RE = re.compile(r"@([A-Za-z0-9._-]+):")


def _strip_port(host: str) -> str:
    """``localhost:8080`` → ``localhost``（IPv6 字面量原样保留）。"""
    text = host.strip()
    if text.count(":") == 1 and text.rsplit(":", 1)[1].isdigit():
        return text.rsplit(":", 1)[0]
    return text


class ExfiltrationDetector(Detector):
    """检测数据外泄链路：敏感读取 → 非白名单外联。

    参数（``detectors.params.exfiltration``）::

        secret_globs          敏感资产通配列表
        egress_allow          允许外联的主机通配列表（白名单）
        link_window_seconds    "敏感读取 + 外联" 的关联时间窗（默认 300 秒）
    """

    name = "exfiltration"
    description = "检测敏感数据外泄：凭据读取与对外网络外联的关联链路"

    def _egress_hosts(self, action: Action, text: str) -> List[str]:
        hosts: List[str] = []
        if action.host:
            hosts.append(action.host)
        if text and EGRESS_COMMAND_RE.search(text):
            hosts.extend(URL_HOST_RE.findall(text))
            hosts.extend(SCP_HOST_RE.findall(text))
        seen: Dict[str, None] = {}
        for host in hosts:
            host = _strip_port(host)
            if host and host not in seen:
                seen[host] = None
        return list(seen)

    def check(self, action: Action, state: SessionState, policy: Policy) -> List[Finding]:
        findings: List[Finding] = []
        window = float(self._param(policy, "link_window_seconds", 300))
        secret_globs = self._param(policy, "secret_globs", DEFAULT_SECRET_GLOBS)
        egress_allow = self._param(policy, "egress_allow", DEFAULT_EGRESS_ALLOW)
        text = _text_of(action)
        now = time.time()

        # --- 敏感读取 ---
        secret_hit: Optional[str] = None
        if action.path and path_matches(action.path, secret_globs):
            secret_hit = f"路径 {action.path}"
        if secret_hit is None:
            hit = _match_any(SECRET_READ_PATTERNS, text)
            if hit:
                secret_hit = f"命令匹配 /{hit}/"
        if secret_hit:
            state.flags["secret_access_ts"] = now
            state.flags["secret_access_detail"] = secret_hit
            findings.append(
                self._finding(
                    Severity.MEDIUM,
                    f"访问敏感凭据类资产（{secret_hit}）",
                    Verdict.REVIEW,
                )
            )

        # --- 直接从敏感文件上传（无需依赖状态） ---
        upload = SECRET_UPLOAD_RE.search(text)
        if upload:
            state.flags["secret_access_ts"] = now
            state.flags["secret_access_detail"] = f"上传参数引用敏感文件（/{upload.group(0)}/）"
            findings.append(
                self._finding(
                    Severity.CRITICAL,
                    f"命令直接从敏感文件上传数据：/{upload.group(0)}/",
                )
            )

        # --- 外联 ---
        hosts = [
            host
            for host in self._egress_hosts(action, text)
            if not _glob_any_casefold(host, egress_allow)
        ]
        if hosts:
            joined = ", ".join(sorted(hosts))
            recent_secret = (
                now - float(state.flags.get("secret_access_ts", 0) or 0)
            ) <= window
            if recent_secret:
                detail = state.flags.get("secret_access_detail", "")
                findings.append(
                    self._finding(
                        Severity.CRITICAL,
                        f"疑似数据外泄：近期访问过敏感资产（{detail}），"
                        f"随后向非白名单主机外联 {joined}",
                        hosts=hosts,
                    )
                )
            else:
                findings.append(
                    self._finding(
                        Severity.MEDIUM,
                        f"向非白名单主机外联：{joined}",
                        Verdict.REVIEW,
                        hosts=hosts,
                    )
                )
        return findings


def _glob_any_casefold(value: str, patterns: Sequence[str]) -> bool:
    from .policy import glob_any

    return glob_any(value, patterns, casefold=True)


# --------------------------------------------------------------------------- #
# 5. 反侦察（Evasion）
# --------------------------------------------------------------------------- #

EVASION_PATTERNS = [
    r"\bhistory\s+-c\b",
    r"\bunset\s+HISTFILE\b",
    r"HISTFILE\s*=",
    r">\s*[^\n]*\.bash_history",
    r"\brm\b[^\n]*\.bash_history",
    r"\b(?:rm|shred|truncate)\b[^\n]*(?:/var/log|\.log\b|\.jsonl\b)",
    r"dd\s+if=/dev/zero\s+of=[^\n]*\.log",
    r"journalctl\s+--(?:rotate|vacuum)",
    r"systemctl\s+(?:stop|disable|mask)\s+(?:auditd|rsyslog|journald)",
    r"auditctl\s+-e\s+0",
]

OBFUSCATION_PATTERNS = [
    r"\bbase64\s+(?:-d|--decode)\b[^\n|]*\|\s*(?:sh|bash|zsh|python\w*|perl|ruby)\b",
    r"\|\s*base64\s+(?:-d|--decode)\s*\|",
    r"\beval\s+\$?\([^\n]*(?:base64|xxd|openssl)",
    r"\bxxd\s+-r\b",
    r"\bopenssl\s+enc\s+-d\b",
    r"python\w*\s+-c\s+[\"'][^\"']*(?:exec|eval)\s*\([^)]*(?:b64decode|fromhex|decode)\b",
]

SHADOW_PATTERNS = [
    r"\balias\s+(?:ls|cat|ps|netstat|ss|find|grep|curl|wget)\s*=",
]


class EvasionDetector(Detector):
    """检测反侦察行为：清理痕迹、关闭审计、混淆载荷、命令遮蔽。"""

    name = "evasion"
    description = "检测反侦察：历史/日志清理、审计关闭、base64 等混淆执行"

    def check(self, action: Action, state: SessionState, policy: Policy) -> List[Finding]:
        findings: List[Finding] = []
        text = _text_of(action)

        hit = _match_any(EVASION_PATTERNS, text)
        if hit:
            findings.append(
                self._finding(
                    Severity.HIGH,
                    f"疑似清理痕迹 / 关闭审计：命令匹配 /{hit}/",
                    pattern=hit,
                )
            )

        hit = _match_any(OBFUSCATION_PATTERNS, text)
        if hit:
            findings.append(
                self._finding(
                    Severity.HIGH,
                    f"疑似混淆载荷规避检测：命令匹配 /{hit}/",
                    pattern=hit,
                )
            )

        hit = _match_any(SHADOW_PATTERNS, text)
        if hit:
            findings.append(
                self._finding(
                    Severity.MEDIUM,
                    f"疑似命令遮蔽（alias 覆盖系统命令）：命令匹配 /{hit}/",
                    Verdict.REVIEW,
                    pattern=hit,
                )
            )
        return findings


# --------------------------------------------------------------------------- #
# 6. 失控（Runaway）
# --------------------------------------------------------------------------- #

LOOP_PATTERNS = [
    r"\bwhile\s+(?:true|:)\b",
    r"\byes\s*\|",
    r"dd\s+if=/dev/(?:zero|urandom)",
    r"cat\s+/dev/urandom",
    r"\bmkfifo\b",
    r"for\s+\w+\s+in\s+\$\(seq",
]


class RunawayLoopDetector(Detector):
    """检测失控循环与持续试探：高频重复、资源消耗型循环、冷却期复犯。

    参数（``detectors.params.runaway``）::

        repeat_threshold   同一动作在窗口内允许的最大重复次数（默认 25）
        window_seconds     统计窗口（默认 60 秒）
        burst_threshold    窗口内动作总量上限（默认 300）
        cooldown_seconds   触发后同一动作的冷却时长（默认 120 秒）
    """

    name = "runaway"
    description = "检测失控行为：高频重复动作、资源消耗型循环、冷却期持续试探"

    def check(self, action: Action, state: SessionState, policy: Policy) -> List[Finding]:
        findings: List[Finding] = []
        repeat_threshold = int(self._param(policy, "repeat_threshold", 25))
        window = float(self._param(policy, "window_seconds", 60))
        burst_threshold = int(self._param(policy, "burst_threshold", 300))
        cooldown_seconds = float(self._param(policy, "cooldown_seconds", 120))

        now = time.time()
        fingerprint = action.fingerprint()
        cooldowns: Dict[str, float] = state.flags.setdefault("cooldowns", {})
        until = float(cooldowns.get(fingerprint, 0) or 0)

        state.record(action)

        if until > now:
            findings.append(
                self._finding(
                    Severity.HIGH,
                    f"冷却期内重复执行同一动作（剩余约 {int(until - now)} 秒），疑似持续试探",
                    fingerprint=fingerprint,
                )
            )
            return findings
        if fingerprint in cooldowns:
            cooldowns.pop(fingerprint, None)

        count = state.count_fingerprint(fingerprint, window)
        if count >= repeat_threshold:
            cooldowns[fingerprint] = now + cooldown_seconds
            findings.append(
                self._finding(
                    Severity.HIGH,
                    f"同一动作在 {int(window)} 秒内重复 {count} 次（阈值 {repeat_threshold}），已进入冷却",
                    fingerprint=fingerprint,
                    count=count,
                )
            )
        elif state.recent_count(window) >= burst_threshold:
            findings.append(
                self._finding(
                    Severity.MEDIUM,
                    f"动作频率过高：{int(window)} 秒内共 {state.recent_count(window)} 次（阈值 {burst_threshold}）",
                )
            )

        hit = _match_any(LOOP_PATTERNS, _text_of(action))
        if hit:
            findings.append(
                self._finding(
                    Severity.HIGH,
                    f"疑似资源消耗型循环：命令匹配 /{hit}/",
                    pattern=hit,
                )
            )
        return findings


# --------------------------------------------------------------------------- #
# 7. 永久禁止命令（DangerousCommand）
# --------------------------------------------------------------------------- #

class DangerousCommandDetector(Detector):
    """命中策略 ``always_block_commands`` 的命令（不可放行）。"""

    name = "dangerous_command"
    description = "命中永久禁止命令清单（如 rm -rf /、fork 炸弹等）"

    def check(self, action: Action, state: SessionState, policy: Policy) -> List[Finding]:
        text = _text_of(action)
        if not text:
            return []
        hit = regex_any(text, policy.always_block_commands)
        if hit:
            return [
                self._finding(
                    Severity.CRITICAL,
                    f"命中永久禁止命令：/{hit}/",
                    pattern=hit,
                )
            ]
        return []


# --------------------------------------------------------------------------- #
# 8. 蜜罐凭据（Honeytoken）
# --------------------------------------------------------------------------- #

class HoneytokenDetector(Detector):
    """蜜罐凭据被触碰：诱饵内容出现在动作目标里 → 确认攻击意图并溯源。

    需要外部注入登记表（:class:`~antiai.honeytokens.HoneytokenRegistry`），
    因此不在 ``DETECTOR_CLASSES`` 默认列表中，由 :class:`~antiai.guard.Guard` 装配。
    """

    name = "honeytoken"
    description = "检测诱饵凭据（canary）被读取、携带或外发"

    def __init__(self, registry: Any) -> None:
        self.registry = registry

    def check(self, action: Action, state: SessionState, policy: Policy) -> List[Finding]:
        text = "\n".join(
            part for part in (_text_of(action, include_args=True), action.path or "") if part
        )
        canary_ids = self.registry.find(text)
        path_hits = self.registry.match_paths(action.path, text)
        if not canary_ids and not path_hits:
            return []

        canaries: List[Dict[str, Any]] = []
        seen_ids = set()
        for item in self.registry.describe(canary_ids) + [token.to_dict() for token in path_hits]:
            if item.get("id") not in seen_ids:
                seen_ids.add(item.get("id"))
                canaries.append(item)
        content_ids = set(canary_ids)
        # 路径命中的诱饵（内容编号可能尚未出现在动作里，单独列出）
        content_hits = [item for item in canaries if item.get("id") in content_ids]
        path_only = [item for item in canaries if item.get("id") not in content_ids]

        details_bits: List[str] = []
        if content_hits:
            details_bits.append(
                "携带/外发诱饵内容：" + ", ".join(f"{item.get('id')}（{item.get('path')}）" for item in content_hits)
            )
        if path_only:
            details_bits.append(
                "触碰诱饵文件：" + ", ".join(f"{item.get('path')}（{item.get('kind')}）" for item in path_only)
            )
        return [
            self._finding(
                Severity.CRITICAL,
                "触碰蜜罐凭据 —— " + "；".join(details_bits) + "。正常作业不会读取诱饵，确认攻击意图",
                canaries=canaries,
                matched_by=["content" if content_hits else None, "path" if path_only else None],
            )
        ]


# --------------------------------------------------------------------------- #
# 工厂
# --------------------------------------------------------------------------- #

DETECTOR_CLASSES = [
    TamperDetector,
    SelfPreservationDetector,
    PrivilegeEscalationDetector,
    ExfiltrationDetector,
    EvasionDetector,
    RunawayLoopDetector,
    DangerousCommandDetector,
]


def build_detectors(policy: Policy) -> List[Detector]:
    """按策略启用检测器（``detectors.disabled`` 中的会被跳过）。"""
    return [cls() for cls in DETECTOR_CLASSES if policy.detector_enabled(cls.name)]
