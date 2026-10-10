"""
紧急制动：文件化的会话冻结与全局停机开关。

设计目标：冻结必须**对 AI 不可绕过**——只要状态目录受策略保护，
被管对象既改不了标志文件，也删不掉审计记录。人类（或外部监督进程）
随时可以通过 CLI / 直接放置标志文件完成冻结::

    <state_dir>/
    ├── STOP.json                 # 全局紧急制动（所有会话）
    └── sessions/
        ├── agent-1.frozen        # 单会话冻结
        └── ...

Guard 在每次判定前读取标志；冻结后所有动作一律阻止，直至人工解除。
"""

from __future__ import annotations

import json
import os
import re
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union


def safe_session_name(session: str) -> str:
    """把会话名净化为安全的文件名（保留字母数字、下划线、点、连字符）。"""
    return re.sub(r"[^\w.-]", "_", str(session) or "default") or "default"


def _atomic_write_json(path: Path, data: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=path.name + ".", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle, ensure_ascii=False, indent=2)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, path)
    finally:
        if os.path.exists(tmp_name):
            try:
                os.unlink(tmp_name)
            except OSError:
                pass


def _read_json(path: Path) -> Optional[Dict[str, Any]]:
    try:
        with path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
        return data if isinstance(data, dict) else None
    except (OSError, json.JSONDecodeError):
        return None


class SessionControl:
    """基于状态目录的冻结 / 停机开关。"""

    def __init__(self, state_dir: Union[str, Path]) -> None:
        self.state_dir = Path(state_dir).expanduser()
        self.sessions_dir = self.state_dir / "sessions"
        self.sessions_dir.mkdir(parents=True, exist_ok=True)
        self.stop_file = self.state_dir / "STOP.json"

    # ------------------------------------------------------------- 单会话

    @staticmethod
    def _safe(session: str) -> str:
        return safe_session_name(session)

    def _flag_path(self, session: str) -> Path:
        return self.sessions_dir / f"{self._safe(session)}.frozen"

    def freeze(self, session: str, reason: str = "人工冻结", by: str = "human") -> Dict[str, Any]:
        info = {"session": session, "reason": reason, "by": by, "ts": time.time()}
        _atomic_write_json(self._flag_path(session), info)
        return info

    def release(self, session: str) -> bool:
        path = self._flag_path(session)
        if path.exists():
            path.unlink()
            return True
        return False

    def frozen_info(self, session: str) -> Optional[Dict[str, Any]]:
        path = self._flag_path(session)
        if not path.exists():
            return None
        return _read_json(path) or {"session": session, "reason": "（标志文件不可解析）", "by": "unknown"}

    # ------------------------------------------------------------- 封锁（lockdown）

    def _lockdown_path(self, session: str) -> Path:
        return self.sessions_dir / f"{self._safe(session)}.lockdown"

    def lockdown(self, session: str, reason: str = "主动封锁", by: str = "guard") -> Dict[str, Any]:
        """封锁会话：禁止执行类工具与对外网络，保留只读观察。"""
        info = {"session": session, "reason": reason, "by": by, "ts": time.time()}
        _atomic_write_json(self._lockdown_path(session), info)
        return info

    def unlock(self, session: str) -> bool:
        path = self._lockdown_path(session)
        if path.exists():
            path.unlink()
            return True
        return False

    def lockdown_info(self, session: str) -> Optional[Dict[str, Any]]:
        path = self._lockdown_path(session)
        if not path.exists():
            return None
        return _read_json(path) or {"session": session, "reason": "（标志文件不可解析）", "by": "unknown"}

    def is_lockdown(self, session: str = "default") -> Tuple[bool, Optional[str]]:
        """返回 ``(是否处于封锁, 原因)``。"""
        info = self.lockdown_info(session)
        if info is None:
            return False, None
        return True, f"会话已被封锁（{info.get('reason', '未说明')}；操作者={info.get('by', 'unknown')}）"

    def list_lockdowns(self) -> List[Dict[str, Any]]:
        infos = []
        for path in sorted(self.sessions_dir.glob("*.lockdown")):
            session = path.name[: -len(".lockdown")]
            infos.append(_read_json(path) or {"session": session, "reason": "（标志文件不可解析）", "by": "unknown"})
        return infos

    def list_frozen(self) -> List[Dict[str, Any]]:
        infos = []
        for path in sorted(self.sessions_dir.glob("*.frozen")):
            session = path.name[: -len(".frozen")]
            infos.append(_read_json(path) or {"session": session, "reason": "（标志文件不可解析）", "by": "unknown"})
        return infos

    # ------------------------------------------------- 拦截计数持久化

    def _counters_path(self, session: str) -> Path:
        return self.sessions_dir / f"{self._safe(session)}.state.json"

    def read_counters(self, session: str) -> Dict[str, Any]:
        """读取会话拦截计数（跨进程可见；不存在时返回空字典）。"""
        path = self._counters_path(session)
        if not path.exists():
            return {}
        return _read_json(path) or {}

    def write_counters(self, session: str, counters: Dict[str, Any]) -> None:
        _atomic_write_json(self._counters_path(session), counters)

    def clear_counters(self, session: str) -> bool:
        path = self._counters_path(session)
        if path.exists():
            path.unlink()
            return True
        return False

    # ------------------------------------------------------------- 全局面

    def stop_all(self, reason: str = "全局紧急制动", by: str = "human") -> Dict[str, Any]:
        info = {"reason": reason, "by": by, "ts": time.time()}
        _atomic_write_json(self.stop_file, info)
        return info

    def resume_all(self) -> bool:
        if self.stop_file.exists():
            self.stop_file.unlink()
            return True
        return False

    def global_stop_info(self) -> Optional[Dict[str, Any]]:
        if not self.stop_file.exists():
            return None
        return _read_json(self.stop_file) or {"reason": "（标志文件不可解析）", "by": "unknown"}

    # ------------------------------------------------------------- 查询

    def is_blocked(self, session: str = "default") -> Tuple[bool, Optional[str]]:
        """返回 ``(是否被阻止, 原因)``。全局停机优先于单会话冻结。"""
        global_info = self.global_stop_info()
        if global_info is not None:
            return True, f"全局紧急制动已启用（{global_info.get('reason', '未说明')}）"
        info = self.frozen_info(session)
        if info is not None:
            return True, (
                f"会话已被冻结（{info.get('reason', '未说明')}，"
                f"操作者={info.get('by', 'unknown')}）"
            )
        return False, None

    def status(self, session: str = "default") -> Dict[str, Any]:
        info = self.frozen_info(session)
        global_info = self.global_stop_info()
        lock_info = self.lockdown_info(session)
        return {
            "session": session,
            "frozen": info is not None,
            "frozen_info": info,
            "lockdown": lock_info is not None,
            "lockdown_info": lock_info,
            "global_stop": global_info is not None,
            "global_stop_info": global_info,
            "state_dir": str(self.state_dir),
        }
