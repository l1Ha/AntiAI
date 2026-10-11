"""演示场景测试：脚本覆盖面、冻结结局与依据质量。"""

from __future__ import annotations

import json
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


# --------------------------------------------------------------------------- #
# 主动反制模式
# --------------------------------------------------------------------------- #

def test_aggressive_demo_flow(tmp_path: Path) -> None:
    report = run_demo(state_dir=tmp_path / "state", workspace=tmp_path / "ws", aggressive=True)
    rows = report["rows"]
    assert report["aggressive"] is True
    assert len(rows) == 8
    assert rows[0].allowed  # 正常读取放行
    # 面包屑入口：onboarding 文档被放行（"不经意"的发现路径）
    assert rows[4].allowed

    # 隔离 / 封锁 / 终止钩子 / 告警 都真实发生
    statuses = {
        (item["rule"], item["action"]): item["status"]
        for row in rows
        for item in row.countermeasures
    }
    assert statuses[("quarantine-on-workspace-secret", "quarantine")] == "applied"
    assert statuses[("lockdown-on-tamper", "lockdown")] == "applied"
    assert statuses[("strike-on-honeytoken", "terminate")] == "applied"
    assert report["status"]["lockdown"] is True
    assert report["hooks_called"]["terminate"] >= 1
    assert report["hooks_called"]["alert"] >= 3
    assert len(report["incidents"]) >= 4
    assert report["quarantined"]

    # 顺面包屑打开"生产 .env" → 蜜罐命中；外发诱饵内容 → 内容级溯源
    assert any("honeytoken" in reason for reason in rows[5].reasons)
    assert any("honeytoken" in reason for reason in rows[6].reasons)
    # 封锁状态下只读观察仍然放行（掐网留观）
    assert rows[7].allowed

    # 假情报包：小体积、高仿真、登记在案，且放在工作区之外（隔离反制不碰它）
    pack = report["decoy_pack"]
    assert pack["files"] == 7 and pack["bytes"] < 100 * 1024
    assert pack["canaries"] >= 6
    assert not pack["root"].startswith(str(tmp_path / "ws"))


def test_aggressive_demo_quarantine_stays_inside_workspace(tmp_path: Path) -> None:
    """隔离反制绝不能碰演示工作区之外的文件（用户真实文件安全）。"""
    run_demo(state_dir=tmp_path / "state", workspace=tmp_path / "ws", aggressive=True)
    metas = list((tmp_path / "state" / "quarantine").glob("*/meta.json"))
    assert metas
    for meta_path in metas:
        data = json.loads(meta_path.read_text(encoding="utf-8"))
        assert data["original_path"].startswith(str(tmp_path / "ws"))
    # 假情报包（工作区之外）原封不动
    decoy_root = Path(
        run_demo(state_dir=tmp_path / "state2", workspace=tmp_path / "ws2", aggressive=True)[
            "decoy_pack"
        ]["root"]
    )
    assert (decoy_root / ".env").exists() and (decoy_root / "docs" / "onboarding.md").exists()


def test_aggressive_demo_honeytokens_and_decoys(tmp_path: Path) -> None:
    report = run_demo(state_dir=tmp_path / "state", workspace=tmp_path / "ws", aggressive=True)
    kinds = {
        (token["kind"], token["note"].startswith("诱饵投放"))
        for token in report["honeytokens"]
    }
    assert ("token", False) in kinds  # 诱饵包内的假信息
    assert ("env", True) in kinds  # 被阻止的窃取动作拿到的诱饵
    assert all(len(token["id"]) == 12 for token in report["honeytokens"])
    assert len(report["honeytokens"]) >= 8
