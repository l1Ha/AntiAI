"""
策略模型：规则（Rule）、策略（Policy）、加载与校验。

匹配语义
--------
规则的 ``match`` 支持四个字段（值可以是单个字符串或列表）:

- ``tool``    : fnmatch 通配，匹配 ``动作.tool``，例如 ``"file.*"``、``"shell.exec"``、``"*"``；
- ``path``    : fnmatch 通配，匹配 ``动作.path``（自动 expanduser / abspath）。
                相对模式（如 ``workspace/**``）会自动前补 ``**/``，可命中任意层级；
- ``host``    : fnmatch 通配（不区分大小写）；
- ``command`` : 正则（不区分大小写，``re.search``）。

规则取舍
--------
先取 ``priority`` 最高的一档；同档内取判定最强的一条（block > review > allow）。
因此可以用 ``priority`` 更高的 allow 规则为特定场景开出白名单，
但**检测器不会被 allow 规则漂白**（检测器是硬约束，见 detectors.py）。

策略文件格式（JSON 或 YAML）::

    {
      "version": 1,
      "default_verdict": "review",
      "session": {"freeze_after_blocks": 3},
      "detectors": {"disabled": [], "params": {}},
      "protected": {"paths": [...], "processes": [...]},
      "always_block_commands": ["正则", ...],
      "rules": [
        {"id": "...", "description": "...", "match": {...},
         "verdict": "allow|review|block", "severity": "low|...", "priority": 0,
         "reason": "..."}
      ]
    }
"""

from __future__ import annotations

import copy
import fnmatch
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

from .errors import PolicyError
from .models import Action, Severity, Verdict, most_restrictive

DEFAULT_POLICY_FILENAMES = (
    "antiai-policy.json",
    "antiai-policy.yaml",
    "antiai-policy.yml",
)

DEFAULT_POLICY: Dict[str, Any] = {
    "version": 1,
    "default_verdict": "review",
    "session": {"freeze_after_blocks": 3, "freeze_window_seconds": 3600},
    "detectors": {"disabled": [], "params": {}},
    "protected": {
        "paths": [
            "~/.antiai/**",
            "**/antiai-policy*.json",
            "**/antiai-policy*.yaml",
            "**/antiai-policy*.yml",
            "**/*.audit.jsonl",
        ],
        "processes": ["antiai", "antiai-guard"],
    },
    "always_block_commands": [
        r"rm\s+-rf\s+/(?:\s|$)",
        r":\(\)\s*\{\s*:\|:&\s*\}\s*;\s*:",
        r"mkfs\.\w+\s+/dev/",
        r"dd\s+if=/dev/(?:zero|urandom)\s+of=/dev/[a-z]+",
        r">\s*/dev/sd[a-z]+\b",
    ],
    "rules": [
        {
            "id": "allow-read-tools",
            "description": "常规只读操作放行（仍受检测器约束）",
            "match": {
                "tool": [
                    "file.read",
                    "file.list",
                    "fs.read",
                    "search.*",
                    "read_*",
                    "grep*",
                    "cat_file",
                ]
            },
            "verdict": "allow",
            "severity": "low",
            "reason": "常规只读操作",
        },
        {
            "id": "block-secret-access",
            "description": "禁止读取或触碰密钥/凭据类资产",
            "match": {
                "path": [
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
            },
            "verdict": "block",
            "severity": "high",
            "reason": "密钥/凭据类文件属于高敏感资产",
        },
        {
            "id": "block-guardrail-assets",
            "description": "护栏策略、审计与状态目录不可被被管对象读写",
            "match": {
                "path": [
                    "~/.antiai/**",
                    "**/antiai-policy*.json",
                    "**/antiai-policy*.yaml",
                    "**/antiai-policy*.yml",
                    "**/*.audit.jsonl",
                ]
            },
            "verdict": "block",
            "severity": "critical",
            "reason": "护栏自身资产受保护，防止被篡改或销毁",
        },
        {
            "id": "review-network-egress",
            "description": "对外网络请求默认需人工确认（白名单见检测器参数 egress_allow）",
            "match": {
                "tool": [
                    "http.*",
                    "web.*",
                    "net.*",
                    "fetch*",
                    "request*",
                    "curl*",
                    "download*",
                    "upload*",
                ]
            },
            "verdict": "review",
            "severity": "medium",
            "reason": "对外网络访问默认需人工确认",
        },
        {
            "id": "review-shell-exec",
            "description": "Shell / 执行类工具默认需人工确认（可用更高 priority 的 allow 规则细化白名单）",
            "match": {
                "tool": [
                    "shell.*",
                    "bash*",
                    "exec*",
                    "terminal.*",
                    "process.*",
                    "system.*",
                ]
            },
            "verdict": "review",
            "severity": "medium",
            "reason": "执行类工具默认需人工确认",
        },
    ],
}

KNOWN_MATCH_KEYS = ("tool", "path", "host", "command")


# --------------------------------------------------------------------------- #
# 匹配工具
# --------------------------------------------------------------------------- #

def _as_patterns(raw: Any) -> List[str]:
    if isinstance(raw, (list, tuple)):
        return [str(item) for item in raw]
    return [str(raw)]


def glob_any(value: Optional[str], patterns: Sequence[str], *, casefold: bool = False) -> bool:
    """任意通配模式命中即真。"""
    if value is None or value == "":
        return False
    candidates = {str(value), os.path.expanduser(str(value))}
    for pattern in patterns:
        for candidate in candidates:
            target = candidate.casefold() if casefold else candidate
            pat = str(pattern).casefold() if casefold else str(pattern)
            if fnmatch.fnmatchcase(target, pat):
                return True
    return False


def path_matches(path: Optional[str], patterns: Sequence[str]) -> bool:
    """路径匹配：支持 ``~`` 展开；相对模式自动前补 ``**/`` 以命中任意层级。"""
    if not path:
        return False
    raw = os.path.expanduser(str(path))
    target = os.path.abspath(raw)
    for pattern in patterns:
        pat = os.path.expanduser(str(pattern))
        variants = [pat]
        if not pat.startswith(("/", "~")):
            variants.append("**/" + pat)
        for variant in variants:
            if fnmatch.fnmatchcase(target, variant):
                return True
        # 相对路径直接与相对模式比较（如 "workspace/**"）
        if fnmatch.fnmatchcase(raw, pat):
            return True
    return False


def regex_any(value: Optional[str], patterns: Sequence[str]) -> Optional[str]:
    """返回第一个命中的正则原文；无命中返回 None。"""
    if not value:
        return None
    for pattern in patterns:
        try:
            if re.search(pattern, value, re.IGNORECASE):
                return pattern
        except re.error:
            continue  # 校验期已报错；运行期忽略非法正则
    return None


# --------------------------------------------------------------------------- #
# 规则与策略
# --------------------------------------------------------------------------- #

@dataclass
class Rule:
    """一条策略规则。"""

    id: str
    match: Dict[str, Any] = field(default_factory=dict)
    verdict: Verdict = Verdict.REVIEW
    reason: str = ""
    description: str = ""
    severity: Severity = Severity.MEDIUM
    priority: int = 0

    def matches(self, action: Action) -> bool:
        for key, raw in self.match.items():
            patterns = _as_patterns(raw)
            if key == "tool":
                if not glob_any(action.tool, patterns):
                    return False
            elif key == "path":
                if not path_matches(action.path, patterns):
                    return False
            elif key == "host":
                if not glob_any(action.host, patterns, casefold=True):
                    return False
            elif key == "command":
                if regex_any(action.command, patterns) is None:
                    return False
            else:
                return False  # 未知字段：校验期报错，运行期不命中
        return bool(self.match)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "match": self.match,
            "verdict": self.verdict.value,
            "severity": self.severity.value,
            "priority": self.priority,
            "reason": self.reason,
            "description": self.description,
        }


@dataclass
class Policy:
    """策略：规则集合 + 护栏全局配置。"""

    version: int = 1
    default_verdict: Verdict = Verdict.REVIEW
    rules: List[Rule] = field(default_factory=list)
    protected_paths: List[str] = field(default_factory=list)
    protected_processes: List[str] = field(default_factory=list)
    always_block_commands: List[str] = field(default_factory=list)
    session: Dict[str, Any] = field(default_factory=dict)
    disabled_detectors: List[str] = field(default_factory=list)
    detector_params: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    source_path: Optional[str] = None
    raw: Dict[str, Any] = field(default_factory=dict)

    # ---- 规则裁决 ----

    def matching_rules(self, action: Action) -> List[Rule]:
        return [rule for rule in self.rules if rule.matches(action)]

    def decide_rules(self, action: Action) -> Tuple[Optional[Verdict], List[Rule]]:
        """返回 ``(规则判定, 决胜规则)``；无规则命中返回 ``(None, [])``。"""
        matched = self.matching_rules(action)
        if not matched:
            return None, []
        top_priority = max(rule.priority for rule in matched)
        top = [rule for rule in matched if rule.priority == top_priority]
        return most_restrictive(rule.verdict for rule in top), top

    # ---- 配置查询 ----

    def is_protected_path(self, path: Optional[str]) -> bool:
        return path_matches(path, self.protected_paths)

    def is_protected_process(self, text: Optional[str]) -> bool:
        if not text:
            return False
        low = str(text).casefold()
        return any(name.casefold() in low for name in self.protected_processes)

    def freeze_after_blocks(self) -> int:
        try:
            return max(1, int(self.session.get("freeze_after_blocks", 3)))
        except (TypeError, ValueError):
            return 3

    def freeze_window_seconds(self) -> float:
        """自动冻结的计数窗口（秒）；<= 0 表示不衰减（累计计数）。"""
        try:
            value = float(self.session.get("freeze_window_seconds", 3600))
        except (TypeError, ValueError):
            return 3600.0
        return max(0.0, value)

    def detector_enabled(self, name: str) -> bool:
        return name not in self.disabled_detectors

    def detector_param(self, detector: str, key: str, default: Any) -> Any:
        return self.detector_params.get(detector, {}).get(key, default)

    def to_dict(self) -> Dict[str, Any]:
        data = copy.deepcopy(self.raw) if self.raw else {}
        data.setdefault("version", self.version)
        data.setdefault("default_verdict", self.default_verdict.value)
        data.setdefault("session", dict(self.session))
        data.setdefault(
            "detectors",
            {"disabled": list(self.disabled_detectors), "params": copy.deepcopy(self.detector_params)},
        )
        data.setdefault(
            "protected",
            {"paths": list(self.protected_paths), "processes": list(self.protected_processes)},
        )
        data.setdefault("always_block_commands", list(self.always_block_commands))
        data["rules"] = [rule.to_dict() for rule in self.rules]
        return data


# --------------------------------------------------------------------------- #
# 解析 / 加载 / 校验
# --------------------------------------------------------------------------- #

def _parse_verdict(value: Any, where: str) -> Verdict:
    try:
        return Verdict(str(value))
    except ValueError:
        raise PolicyError(
            f"{where}: 非法判定值 {value!r}，可选值: allow / review / block"
        ) from None


def _parse_severity(value: Any, where: str) -> Severity:
    try:
        return Severity(str(value))
    except ValueError:
        raise PolicyError(
            f"{where}: 非法严重级 {value!r}，可选值: info / low / medium / high / critical"
        ) from None


def policy_from_dict(data: Dict[str, Any], source: Optional[str] = None) -> Policy:
    """从字典构建策略；结构错误抛 ``PolicyError``。"""
    if not isinstance(data, dict):
        raise PolicyError(f"{source or '<策略>'}：策略根节点必须是对象（dict）")

    version = data.get("version", 1)
    if not isinstance(version, int) or isinstance(version, bool):
        raise PolicyError(f"{source or '<策略>'}：version 必须是整数")

    default_verdict = _parse_verdict(data.get("default_verdict", "review"), "default_verdict")

    rules: List[Rule] = []
    raw_rules = data.get("rules", [])
    if raw_rules is None:
        raw_rules = []
    if not isinstance(raw_rules, list):
        raise PolicyError(f"{source or '<策略>'}：rules 必须是数组")
    seen_ids = set()
    for index, raw_rule in enumerate(raw_rules):
        where = f"rules[{index}]"
        if not isinstance(raw_rule, dict):
            raise PolicyError(f"{where}: 规则必须是对象")
        rule_id = str(raw_rule.get("id", "")).strip()
        if not rule_id:
            raise PolicyError(f"{where}: 缺少 id")
        if rule_id in seen_ids:
            raise PolicyError(f"{where}: 规则 id 重复: {rule_id}")
        seen_ids.add(rule_id)
        match = raw_rule.get("match")
        if not isinstance(match, dict) or not match:
            raise PolicyError(f"规则 {rule_id}: match 必须是非空对象")
        for key in match:
            if key not in KNOWN_MATCH_KEYS:
                raise PolicyError(
                    f"规则 {rule_id}: 未知匹配字段 {key!r}，可选: {', '.join(KNOWN_MATCH_KEYS)}"
                )
        for pattern in _as_patterns(match.get("command")) if "command" in match else []:
            try:
                re.compile(pattern)
            except re.error as exc:
                raise PolicyError(f"规则 {rule_id}: command 正则非法: {pattern!r}（{exc}）") from None
        rules.append(
            Rule(
                id=rule_id,
                match=match,
                verdict=_parse_verdict(raw_rule.get("verdict", "review"), f"规则 {rule_id}"),
                reason=str(raw_rule.get("reason", "")),
                description=str(raw_rule.get("description", "")),
                severity=_parse_severity(raw_rule.get("severity", "medium"), f"规则 {rule_id}"),
                priority=int(raw_rule.get("priority", 0)),
            )
        )

    protected = data.get("protected", {}) or {}
    if not isinstance(protected, dict):
        raise PolicyError("protected 必须是对象")

    detectors = data.get("detectors", {}) or {}
    if not isinstance(detectors, dict):
        raise PolicyError("detectors 必须是对象")
    disabled = detectors.get("disabled", []) or []
    if not isinstance(disabled, list):
        raise PolicyError("detectors.disabled 必须是数组")
    params = detectors.get("params", {}) or {}
    if not isinstance(params, dict):
        raise PolicyError("detectors.params 必须是对象")

    session = data.get("session", {}) or {}
    if not isinstance(session, dict):
        raise PolicyError("session 必须是对象")

    always_block = data.get("always_block_commands", []) or []
    if not isinstance(always_block, list):
        raise PolicyError("always_block_commands 必须是数组")
    for pattern in always_block:
        try:
            re.compile(str(pattern))
        except re.error as exc:
            raise PolicyError(f"always_block_commands 正则非法: {pattern!r}（{exc}）") from None

    return Policy(
        version=version,
        default_verdict=default_verdict,
        rules=rules,
        protected_paths=[str(p) for p in (protected.get("paths", []) or [])],
        protected_processes=[str(p) for p in (protected.get("processes", []) or [])],
        always_block_commands=[str(p) for p in always_block],
        session=dict(session),
        disabled_detectors=[str(name) for name in disabled],
        detector_params={str(k): dict(v) for k, v in params.items() if isinstance(v, dict)},
        source_path=source,
        raw=copy.deepcopy(data),
    )


def default_policy() -> Policy:
    """内置默认策略（默认拒绝、开箱可用）。"""
    return policy_from_dict(copy.deepcopy(DEFAULT_POLICY), source="<内置默认策略>")


def _read_policy_data(path: Path) -> Dict[str, Any]:
    if not path.is_file():
        raise PolicyError(f"策略文件不存在: {path}")
    text = path.read_text(encoding="utf-8")
    suffix = path.suffix.lower()
    try:
        if suffix in (".yaml", ".yml"):
            try:
                import yaml  # type: ignore
            except ImportError:
                raise PolicyError(
                    f"{path}: 读取 YAML 策略需要 PyYAML，请安装（pip install pyyaml）或改用 JSON 策略"
                ) from None
            data = yaml.safe_load(text)
        else:
            data = json.loads(text)
    except PolicyError:
        raise
    except Exception as exc:
        raise PolicyError(f"{path}: 解析失败（{exc}）") from None
    if not isinstance(data, dict):
        raise PolicyError(f"{path}: 策略根节点必须是对象")
    return data


def load_policy(path: Union[str, Path, None] = None) -> Policy:
    """加载策略。

    - ``path`` 为 None 时依次在当前目录查找 ``antiai-policy.json/.yaml/.yml``，
      找不到则返回内置默认策略；
    - 指定 ``path`` 但文件缺失 / 解析失败时抛 ``PolicyError``。
    """
    if path is not None:
        target = Path(path).expanduser()
        return policy_from_dict(_read_policy_data(target), source=str(target))
    for name in DEFAULT_POLICY_FILENAMES:
        candidate = Path.cwd() / name
        if candidate.is_file():
            return policy_from_dict(_read_policy_data(candidate), source=str(candidate))
    return default_policy()


def validate_policy(source: Union[str, Path, Dict[str, Any], None] = None) -> List[str]:
    """校验策略，返回问题列表；空列表表示通过。

    ``source`` 可以是文件路径、策略字典或 None（校验内置默认策略 + 当前目录策略）。
    """
    problems: List[str] = []

    if source is None:
        data = copy.deepcopy(DEFAULT_POLICY)
        for name in DEFAULT_POLICY_FILENAMES:
            candidate = Path.cwd() / name
            if candidate.is_file():
                try:
                    data = _read_policy_data(candidate)
                except PolicyError as exc:
                    return [str(exc)]
                break
    elif isinstance(source, dict):
        data = source
    else:
        try:
            data = _read_policy_data(Path(source).expanduser())
        except PolicyError as exc:
            return [str(exc)]

    # 结构校验
    try:
        parsed = policy_from_dict(data)
    except PolicyError as exc:
        problems.append(str(exc))
        return problems

    # 语义 lint
    if parsed.version != 1:
        problems.append(f"version={parsed.version} 不是当前支持的版本 1")
    if not parsed.rules:
        problems.append("策略未定义任何规则（rules 为空），所有动作将落到 default_verdict")
    if parsed.freeze_after_blocks() < 1:
        problems.append("session.freeze_after_blocks 必须 >= 1")
    if float(parsed.session.get("freeze_window_seconds", 3600) or 0) < 0:
        problems.append("session.freeze_window_seconds 不能为负数（0 表示不衰减）")
    if not parsed.protected_paths:
        problems.append("protected.paths 为空：护栏策略与审计日志将不受保护，建议至少包含 ~/.antiai/**")

    from .detectors import KNOWN_DETECTORS  # 延迟导入避免循环依赖

    for name in parsed.disabled_detectors:
        if name not in KNOWN_DETECTORS:
            problems.append(
                f"detectors.disabled 中存在未知检测器 {name!r}，可选: {', '.join(KNOWN_DETECTORS)}"
            )
    for name in parsed.detector_params:
        if name not in KNOWN_DETECTORS:
            problems.append(
                f"detectors.params 中存在未知检测器 {name!r}，可选: {', '.join(KNOWN_DETECTORS)}"
            )
    return problems
