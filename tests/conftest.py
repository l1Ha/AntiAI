"""共享测试夹具。"""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any, Callable, Dict

import pytest

from antiai.policy import DEFAULT_POLICY, Policy, policy_from_dict


@pytest.fixture
def policy_dict() -> Dict[str, Any]:
    return copy.deepcopy(DEFAULT_POLICY)


@pytest.fixture
def policy() -> Policy:
    return policy_from_dict(copy.deepcopy(DEFAULT_POLICY), source="<测试策略>")


@pytest.fixture
def policy_factory() -> Callable[..., Policy]:
    """按需定制策略：``policy_factory(rules=[...], session={...})``。"""

    def build(**overrides: Any) -> Policy:
        data = copy.deepcopy(DEFAULT_POLICY)
        data.update(overrides)
        return policy_from_dict(data, source="<测试策略>")

    return build


@pytest.fixture
def state_dir(tmp_path: Path) -> Path:
    return tmp_path / "state"
