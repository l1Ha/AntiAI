"""
ANTIAI 异常体系。

层次::

    AntiaiError
    ├── PolicyError        # 策略文件结构 / 语义错误
    ├── AuditError         # 审计日志读写或完整性错误
    └── ActionBlocked      # 动作被护栏阻止（携带完整 Decision）
        └── SessionFrozen  # 会话处于冻结状态（更严重的 ActionBlocked）
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover
    from .models import Decision


class AntiaiError(Exception):
    """ANTIAI 基础异常。"""


class PolicyError(AntiaiError):
    """策略定义不合法（结构错误、非法判定值、正则错误等）。"""


class AuditError(AntiaiError):
    """审计日志读写失败或哈希链损坏。"""


class ActionBlocked(AntiaiError):
    """动作被护栏阻止。异常实例上携带完整的 ``Decision``，便于上层审计与回传。"""

    def __init__(self, decision: "Decision") -> None:
        self.decision = decision
        super().__init__(
            f"动作被阻止：{decision.action.describe()}；原因：{decision.reason_text}"
        )


class SessionFrozen(ActionBlocked):
    """会话已被冻结：所有动作一律阻止，直至人工解除。"""

    def __init__(self, decision: "Decision") -> None:
        super().__init__(decision)
        self.args = (
            f"会话已冻结（{decision.action.session_id}）：{decision.reason_text}",
        )
