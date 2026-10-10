"""
审计日志：追加式 JSONL + sha256 哈希链。

每条记录包含 ``seq / ts / event / session / payload / prev / hash``，
其中 ``hash = sha256(prev + "\\n" + canonical(payload 基础字段))``。
任何对历史记录的修改、删除或重排都会在 :meth:`AuditLog.verify` 中被发现
（唯一的盲区是整条链被截断——尾部删除无法自证，可另行备份校验）。
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from .errors import AuditError
from .models import canonical_json

GENESIS_HASH = "0" * 64

_BODY_FIELDS = ("seq", "ts", "event", "session", "payload")


def _digest(prev: str, body: Dict[str, Any]) -> str:
    payload = {"prev": prev, "body": body}
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


class AuditLog:
    """单文件审计日志（每个会话一个文件）。线程安全。"""

    def __init__(self, path: Union[str, Path], lock: Optional[threading.Lock] = None) -> None:
        self.path = Path(path).expanduser()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = lock or threading.Lock()
        self._cache_last: Optional[Dict[str, Any]] = None
        self._cache_size: int = -1

    # ------------------------------------------------------------------ 写

    def append(self, event: str, session: str = "-", payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """追加一条记录并返回完整记录（含 hash）。"""
        body_payload = payload or {}
        with self._lock:
            last = self._last_record()
            prev = last["hash"] if last else GENESIS_HASH
            body = {
                "seq": (int(last["seq"]) + 1) if last else 1,
                "ts": time.time(),
                "event": event,
                "session": session,
                "payload": body_payload,
            }
            record = {**body, "prev": prev, "hash": _digest(prev, body)}
            line = json.dumps(record, ensure_ascii=False, separators=(",", ":"))
            try:
                with self.path.open("a", encoding="utf-8") as handle:
                    handle.write(line + "\n")
            except OSError as exc:
                raise AuditError(f"写入审计日志失败: {self.path}（{exc}）") from None
            self._cache_last = record
            self._cache_size = self.path.stat().st_size
            return record

    # ------------------------------------------------------------------ 读

    def _read_raw(self) -> List[Tuple[Optional[Dict[str, Any]], str]]:
        """返回 ``[(解析后的记录或 None, 原始行)]``。"""
        if not self.path.exists():
            return []
        out: List[Tuple[Optional[Dict[str, Any]], str]] = []
        try:
            text = self.path.read_text(encoding="utf-8")
        except OSError as exc:
            raise AuditError(f"读取审计日志失败: {self.path}（{exc}）") from None
        for line in text.splitlines():
            if not line.strip():
                continue
            try:
                data = json.loads(line)
                out.append((data if isinstance(data, dict) else None, line))
            except json.JSONDecodeError:
                out.append((None, line))
        return out

    def read(self, *, strict: bool = True) -> List[Dict[str, Any]]:
        """读取全部记录；``strict=True`` 时遇到损坏行抛 ``AuditError``。"""
        records: List[Dict[str, Any]] = []
        for index, (data, raw) in enumerate(self._read_raw(), start=1):
            if data is None:
                if strict:
                    raise AuditError(f"审计日志第 {index} 行损坏: {raw[:120]!r}")
                continue
            records.append(data)
        return records

    def tail(self, n: int = 20) -> List[Dict[str, Any]]:
        return self.read(strict=False)[-max(1, int(n)):]

    def _last_record(self) -> Optional[Dict[str, Any]]:
        if not self.path.exists():
            self._cache_last = None
            self._cache_size = -1
            return None
        size = self.path.stat().st_size
        if self._cache_last is not None and size == self._cache_size:
            return self._cache_last
        records = self.read(strict=False)
        self._cache_last = records[-1] if records else None
        self._cache_size = size
        return self._cache_last

    # ------------------------------------------------------------------ 校验

    def verify(self) -> Tuple[bool, Optional[int]]:
        """校验哈希链。返回 ``(是否通过, 首个异常记录的序号)``。"""
        prev = GENESIS_HASH
        for index, (record, _raw) in enumerate(self._read_raw(), start=1):
            if record is None:
                return False, index
            if record.get("seq") != index:
                return False, index
            if record.get("prev") != prev:
                return False, index
            body = {key: record.get(key) for key in _BODY_FIELDS}
            if _digest(prev, body) != record.get("hash"):
                return False, index
            prev = str(record.get("hash"))
        return True, None

    def counts(self) -> Dict[str, Dict[str, int]]:
        """按事件 / 判定聚合计数，供 ``antiai status`` 使用。"""
        by_event: Counter = Counter()
        by_verdict: Counter = Counter()
        for record in self.read(strict=False):
            by_event[str(record.get("event", "?"))] += 1
            payload = record.get("payload")
            if isinstance(payload, dict) and "verdict" in payload:
                by_verdict[str(payload["verdict"])] += 1
        return {
            "events": dict(sorted(by_event.items())),
            "verdicts": dict(sorted(by_verdict.items())),
        }
