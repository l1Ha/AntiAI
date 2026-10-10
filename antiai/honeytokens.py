"""
蜜罐凭据（Canary Tokens）：主动投放诱饵，"碰了就知道，用了就暴露"。

工作原理
--------
诱饵文件里内嵌唯一标记 ``ANTIAI-CANARY-<12位hex>``。任何动作只要**读取、
携带或外发**包含该标记的内容，都会被 ``honeytoken`` 检测器以 CRITICAL 级别
捕获，并触发主动反制（封锁 / 冻结 / 取证 / 告警 / 终止）。

这带来三个防御收益：

1. **确凿性**：正常作业没有任何理由去读一只诱饵——命中即确认恶意意图；
2. **可溯源**：标记随内容流动，外发时能精确指认"哪一只诱饵、哪个会话"；
3. **欺骗性**：配合 ``deception`` 策略，被阻止的窃取动作会"拿到"诱饵内容，
   攻击方以为得手，实则每一步都已被记录。

诱饵内容全部是**假凭据**（无法用于任何真实服务），不含任何真实密钥。
"""

from __future__ import annotations

import json
import os
import re
import secrets
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

CANARY_PREFIX = "ANTIAI-CANARY-"
# 两种内嵌形式都会被识别：显式标记 antiai-canary-<12hex>，以及伪装成 AWS key id 的 AKIA<12hex>。
# 结尾的否定断言避免把真实的 AWS Access Key ID（AKIA + 16 位）误判为诱饵。
CANARY_RE = re.compile(
    r"(?:antiai-canary-|akia)([0-9a-f]{12})(?![0-9a-f])",
    re.IGNORECASE,
)

TEMPLATES: Dict[str, str] = {
    "env": (
        "# 生产环境配置\n"
        "AWS_ACCESS_KEY_ID=AKIA{canary}\n"
        "AWS_SECRET_ACCESS_KEY=antiai-canary-{canary}\n"
        "OPENAI_API_KEY=sk-antiai-canary-{canary}\n"
        "DATABASE_URL=postgres://app:antiai-canary-{canary}@db.internal:5432/prod\n"
    ),
    "aws": (
        "[default]\n"
        "aws_access_key_id = AKIA{canary}\n"
        "aws_secret_access_key = antiai-canary-{canary}\n"
        "region = us-east-1\n"
    ),
    "ssh": (
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ==antiai-canary-{canary}\n"
        "-----END OPENSSH PRIVATE KEY-----\n"
    ),
    "token": "antiai-canary-{canary}\n",
}

DEFAULT_NAMES: Dict[str, str] = {
    "env": ".env",
    "aws": ".aws/credentials",
    "ssh": "id_rsa",
    "token": "api-token.txt",
}


def _new_canary_id() -> str:
    return secrets.token_hex(6)


@dataclass
class Honeytoken:
    """一只已登记的诱饵。"""

    id: str
    path: str
    kind: str
    session: str = "default"
    created: float = field(default_factory=time.time)
    note: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "path": self.path,
            "kind": self.kind,
            "session": self.session,
            "created": self.created,
            "note": self.note,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Honeytoken":
        return cls(
            id=str(data.get("id", "")),
            path=str(data.get("path", "")),
            kind=str(data.get("kind", "token")),
            session=str(data.get("session", "default")),
            created=float(data.get("created", 0) or 0),
            note=str(data.get("note", "")),
        )


class HoneytokenRegistry:
    """诱饵登记表（``<状态目录>/honeytokens.json``），跨进程共享。"""

    def __init__(self, state_dir: Union[str, Path]) -> None:
        self.state_dir = Path(state_dir).expanduser()
        self.path = self.state_dir / "honeytokens.json"

    # ------------------------------------------------------------------ 读写

    def load(self) -> List[Honeytoken]:
        if not self.path.exists():
            return []
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return []
        if not isinstance(data, list):
            return []
        return [Honeytoken.from_dict(item) for item in data if isinstance(item, dict)]

    def _save(self, tokens: List[Honeytoken]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".json.tmp")
        tmp.write_text(
            json.dumps([token.to_dict() for token in tokens], ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        os.replace(tmp, self.path)

    # ------------------------------------------------------------------ 登记

    def all_ids(self) -> List[str]:
        return [token.id for token in self.load()]

    def get(self, canary_id: str) -> Optional[Honeytoken]:
        for token in self.load():
            if token.id == canary_id:
                return token
        return None

    def register(
        self,
        *,
        path: str,
        kind: str = "token",
        session: str = "default",
        note: str = "",
        canary_id: Optional[str] = None,
    ) -> Honeytoken:
        """登记一只诱饵（内容由调用方生成/写入）。"""
        token = Honeytoken(
            id=canary_id or _new_canary_id(),
            path=str(path),
            kind=kind if kind in TEMPLATES else "token",
            session=session,
            note=note,
        )
        tokens = self.load()
        tokens.append(token)
        self._save(tokens)
        return token

    def render(self, kind: str, canary_id: Optional[str] = None) -> str:
        """按模板生成诱饵内容（不落盘、不登记）。"""
        template = TEMPLATES.get(kind, TEMPLATES["token"])
        return template.format(canary=canary_id or _new_canary_id())

    def render_and_register(
        self,
        kind: str,
        *,
        path: str,
        session: str = "default",
        note: str = "诱饵投放（deception）",
    ) -> "Tuple[Honeytoken, str]":
        """生成诱饵内容并登记（用于 deception 投放：内容交给攻击方，编号留在账上）。"""
        token = self.register(path=str(path), kind=kind, session=session, note=note)
        return token, self.render(kind, token.id)

    def plant(
        self,
        path: Union[str, Path, None] = None,
        *,
        kind: str = "env",
        session: str = "default",
        overwrite: bool = False,
        note: str = "",
    ) -> Honeytoken:
        """写入一个诱饵文件并登记。

        ``path`` 为 None 时自动放到 ``./antiai-honeypot/<默认文件名>``。
        文件已存在且未指定 ``overwrite`` 时抛 ``FileExistsError``。
        """
        kind = kind if kind in TEMPLATES else "token"
        if path is None:
            target = Path.cwd() / "antiai-honeypot" / DEFAULT_NAMES.get(kind, "token.txt")
        else:
            target = Path(path).expanduser()
        if target.exists() and not overwrite:
            raise FileExistsError(f"目标文件已存在：{target}（如需覆盖请加 --overwrite）")
        canary_id = _new_canary_id()
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(self.render(kind, canary_id), encoding="utf-8")
        try:
            os.chmod(target, 0o600)
        except OSError:
            pass
        return self.register(
            path=str(target), kind=kind, session=session, note=note, canary_id=canary_id
        )

    # ------------------------------------------------------------------ 检索

    def find(self, text: Optional[str]) -> List[str]:
        """返回文本中出现的全部 canary 编号（去重，保持出现顺序）。"""
        if not text:
            return []
        seen: Dict[str, None] = {}
        for match in CANARY_RE.findall(text):
            seen.setdefault(match, None)
        return list(seen)

    def match_paths(self, path: Optional[str], text: Optional[str] = None) -> List["Honeytoken"]:
        """路径级触发：动作直接命中诱饵文件，或命令文本里提到诱饵文件路径。"""
        hits: List[Honeytoken] = []
        wanted = str(os.path.abspath(os.path.expanduser(path))) if path else None
        haystack = text or ""
        for token in self.load():
            token_path = str(os.path.abspath(os.path.expanduser(token.path)))
            if wanted and wanted == token_path:
                hits.append(token)
            elif token_path and token_path in haystack:
                hits.append(token)
        return hits

    def describe(self, canary_ids: List[str]) -> List[Dict[str, Any]]:
        """把编号翻译为诱饵信息（未登记的也如实标注）。"""
        out: List[Dict[str, Any]] = []
        for canary_id in canary_ids:
            token = self.get(canary_id)
            if token is None:
                out.append({"id": canary_id, "path": "(未登记)", "kind": "unknown", "session": "?"})
            else:
                out.append(token.to_dict())
        return out
