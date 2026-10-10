"""
动作归一化适配器：把各种来源的"工具调用"统一成 :class:`~antiai.models.Action`。

支持的输入形态
--------------
1. 通用字典::

       {"tool": "file.read", "args": {"path": "/tmp/a.txt"}}

2. OpenAI / 兼容 Function Calling 形态::

       {"type": "function",
        "function": {"name": "file.read", "arguments": "{\"path\": \"/tmp/a.txt\"}"}}

3. 普通字典（``name`` + ``arguments`` / ``input`` / ``args``）::

       {"name": "shell.exec", "arguments": {"command": "ls -la"}}

4. 字符串（视为一条 Shell 命令）::

       "pkill -f antiai-guard"

5. 已经是 :class:`Action` 的对象（原样返回）。

归一化时会从参数中尽力提取三类关键字段，供策略与检测器使用:

- ``command``：command / cmd / script / shell / code / line 等键；
- ``path``   ：path / file / filename / dir / target / dest 等键（自动 ~ 展开并转绝对路径）；
- ``host``   ：host / hostname / domain / endpoint / url / uri 等键（URL 会解析出主机名）。
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from .models import Action

COMMAND_KEYS = ("command", "cmd", "script", "shell", "shell_command", "code", "line")
PATH_KEYS = (
    "path",
    "file",
    "filename",
    "filepath",
    "file_path",
    "dir",
    "directory",
    "target",
    "dest",
    "destination",
    "source",
)
HOST_KEYS = ("host", "hostname", "domain", "endpoint", "url", "uri")


def _find_arg(args: Dict[str, Any], keys: Tuple[str, ...]) -> Tuple[Optional[str], Optional[str]]:
    """按候选键查找参数（不区分大小写），返回 ``(键名, 字符串值)``。"""
    lowered = {str(key).lower(): key for key in args}
    for candidate in keys:
        original = lowered.get(candidate)
        if original is None:
            continue
        value = args[original]
        if value is None:
            continue
        if isinstance(value, (str, int, float)):
            return str(original), str(value)
        if isinstance(value, (list, tuple)) and value and isinstance(value[0], str):
            return str(original), str(value[0])
    return None, None


def _extract_host(value: str) -> str:
    """从 URL 或裸主机名中提取主机（去掉端口）；提取失败时原样返回。"""
    text = value.strip()
    if "://" in text:
        parsed = urlparse(text)
        if parsed.hostname:
            return parsed.hostname
    # scp 风格 user@host:path
    if "@" in text and ":" in text.split("@", 1)[1]:
        candidate = text.split("@", 1)[1].split(":", 1)[0]
        if candidate and "/" not in candidate:
            return candidate
    # host:port 形式去掉端口
    if text.count(":") == 1 and text.rsplit(":", 1)[1].isdigit():
        return text.rsplit(":", 1)[0]
    return text


def _normalize_path(value: str) -> str:
    return os.path.abspath(os.path.expanduser(value))


def enrich_action(action: Action) -> Action:
    """从 ``action.args`` 中提取 command / path / host（已有字段不覆盖）。"""
    if action.args:
        if action.command is None:
            _, action.command = _find_arg(action.args, COMMAND_KEYS)
        if action.path is None:
            _, raw_path = _find_arg(action.args, PATH_KEYS)
            if raw_path:
                action.path = _normalize_path(raw_path)
        if action.host is None:
            _, raw_host = _find_arg(action.args, HOST_KEYS)
            if raw_host:
                action.host = _extract_host(raw_host)
    return action


def _unwrap_arguments(value: Any) -> Dict[str, Any]:
    """``arguments`` 可能是 JSON 字符串，也可能是字典；统一成字典。"""
    if value is None:
        return {}
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return {}
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            return {"command": text}
        if isinstance(parsed, dict):
            return parsed
        return {"value": parsed}
    if isinstance(value, dict):
        return value
    return {"value": value}


def normalize_action(obj: Any, session_id: str = "default") -> Action:
    """把任意受支持的输入形态转成 :class:`Action`。"""
    if isinstance(obj, Action):
        if obj.session_id == "default" and session_id != "default":
            obj.session_id = session_id
        return enrich_action(obj)

    if isinstance(obj, str):
        return Action(tool="shell.exec", command=obj, session_id=session_id, raw=obj)

    if not isinstance(obj, dict):
        raise ValueError(f"无法归一化的动作类型: {type(obj).__name__}（支持 dict / str / Action）")

    # 形态 2：OpenAI Function Calling
    if isinstance(obj.get("function"), dict):
        function = obj["function"]
        tool = str(function.get("name") or obj.get("name") or "unknown")
        args = _unwrap_arguments(function.get("arguments", function.get("parameters")))
        action = Action(tool=tool, args=args, session_id=str(obj.get("session_id", session_id)), raw=obj)
        return enrich_action(action)

    # 形态 1 / 3：通用字典
    tool = obj.get("tool", obj.get("name", obj.get("type")))
    if tool is None:
        raise ValueError("动作字典缺少 tool / name 字段")
    args_raw = obj.get("args", obj.get("arguments", obj.get("input", obj.get("parameters", {}))))
    args = _unwrap_arguments(args_raw)
    if not isinstance(args, dict):
        args = {"value": args}
    action = Action(tool=str(tool), args=args, session_id=str(obj.get("session_id", session_id)), raw=obj)
    return enrich_action(action)
