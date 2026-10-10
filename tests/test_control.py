"""紧急制动测试：会话冻结、全局停机与净化。"""

from __future__ import annotations

from pathlib import Path

from antiai.control import SessionControl, safe_session_name


def test_freeze_release_roundtrip(tmp_path: Path) -> None:
    control = SessionControl(tmp_path)
    assert control.is_blocked("agent") == (False, None)
    control.freeze("agent", reason="测试冻结", by="pytest")
    blocked, why = control.is_blocked("agent")
    assert blocked and "测试冻结" in str(why) and "pytest" in str(why)
    assert control.status("agent")["frozen"] is True
    assert control.release("agent") is True
    assert control.is_blocked("agent") == (False, None)
    assert control.release("agent") is False


def test_global_stop_blocks_all_sessions(tmp_path: Path) -> None:
    control = SessionControl(tmp_path)
    control.stop_all(reason="演习")
    blocked, why = control.is_blocked("any-session")
    assert blocked and "演习" in str(why)
    assert control.status("whatever")["global_stop"] is True
    assert control.resume_all() is True
    assert control.is_blocked("any-session") == (False, None)
    assert control.resume_all() is False


def test_global_stop_takes_priority_over_session(tmp_path: Path) -> None:
    control = SessionControl(tmp_path)
    control.freeze("agent", reason="单会话冻结")
    control.stop_all(reason="全局")
    blocked, why = control.is_blocked("agent")
    assert blocked and "全局" in str(why)


def test_session_name_sanitized(tmp_path: Path) -> None:
    control = SessionControl(tmp_path)
    weird = "agent/../secret name"
    control.freeze(weird, reason="r")
    assert safe_session_name(weird) == "agent_.._secret_name"
    # 路径分隔符被净化，标志文件不会逃出 sessions 目录
    assert (tmp_path / "sessions" / "agent_.._secret_name.frozen").exists()
    assert control.frozen_info(weird) is not None


def test_list_frozen(tmp_path: Path) -> None:
    control = SessionControl(tmp_path)
    control.freeze("a", reason="ra")
    control.freeze("b", reason="rb")
    sessions = {info["session"] for info in control.list_frozen()}
    assert sessions == {"a", "b"}


def test_status_fields(tmp_path: Path) -> None:
    control = SessionControl(tmp_path)
    status = control.status("s")
    assert status == {
        "session": "s",
        "frozen": False,
        "frozen_info": None,
        "global_stop": False,
        "global_stop_info": None,
        "state_dir": str(tmp_path),
    }
