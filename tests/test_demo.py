"""演示场景测试：脚本覆盖面、冻结结局与依据质量。"""

from __future__ import annotations

from pathlib import Path

from antiai.demo import run_demo


def test_demo_sequence(tmp_path: Path) -> None:
    report = run_demo(state_dir=tmp_path / "state", workspace=tmp_path / "ws")
    rows = report["rows"]
    assert len(rows) == 11
    assert rows[0].allowed and rows[0].verdict == "allow"
    assert rows[1].verdict == "review" and not rows[1].allowed
    assert all(row.verdict == "block" for row in rows[2:])
    assert rows[-1].frozen and not rows[-1].allowed


def test_demo_ends_frozen(tmp_path: Path) -> None:
    report = run_demo(state_dir=tmp_path / "state", workspace=tmp_path / "ws")
    assert report["status"]["frozen"] is True
    assert "自动冻结" in (report["status"].get("frozen_info") or {}).get("reason", "")


def test_demo_audit_chain_ok(tmp_path: Path) -> None:
    report = run_demo(state_dir=tmp_path / "state", workspace=tmp_path / "ws")
    assert report["status"]["audit_verified"] is True
    counts = report["status"]["audit_counts"]
    assert counts["events"].get("freeze", 0) == 1
    assert counts["verdicts"].get("block", 0) >= 7


def test_demo_reasons_are_specific(tmp_path: Path) -> None:
    """每条拦截都应带具体检测/规则依据，重点行要给到关键检测器。"""
    report = run_demo(state_dir=tmp_path / "state", workspace=tmp_path / "ws")
    rows = report["rows"]
    for row in rows:
        if row.verdict == "block" and not row.frozen:
            assert row.reasons, row.label

    exfil_row = rows[4]  # 窃取环境变量并外传
    assert any("exfiltration/critical" in reason for reason in exfil_row.reasons)
    evasion_row = rows[5]
    assert any("evasion" in reason for reason in evasion_row.reasons)
    persistence_row = rows[6]
    assert any("self_preservation" in reason for reason in persistence_row.reasons)
    runaway_row = rows[9]
    assert any("runaway" in reason for reason in runaway_row.reasons)


def test_demo_repeat_row_counts(tmp_path: Path) -> None:
    report = run_demo(state_dir=tmp_path / "state", workspace=tmp_path / "ws")
    repeat_row = report["rows"][9]
    assert "28 次" in repeat_row.note
    assert "自动冻结" in repeat_row.note
