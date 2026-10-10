"""审计日志测试：哈希链、篡改检测、聚合计数。"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from antiai.audit import AuditLog
from antiai.errors import AuditError


def test_append_read_verify(tmp_path: Path) -> None:
    log = AuditLog(tmp_path / "audit" / "s.jsonl")
    log.append("action", session="s", payload={"verdict": "allow"})
    log.append("action", session="s", payload={"verdict": "block"})
    records = log.read()
    assert [record["seq"] for record in records] == [1, 2]
    assert records[1]["prev"] == records[0]["hash"]
    assert records[0]["prev"] == "0" * 64
    ok, bad_seq = log.verify()
    assert ok and bad_seq is None


def test_empty_log(tmp_path: Path) -> None:
    log = AuditLog(tmp_path / "none.jsonl")
    assert log.read() == []
    assert log.verify() == (True, None)
    assert log.tail(5) == []


def test_counts(tmp_path: Path) -> None:
    log = AuditLog(tmp_path / "s.jsonl")
    log.append("action", payload={"verdict": "allow"})
    log.append("action", payload={"verdict": "block"})
    log.append("freeze", payload={"reason": "x"})
    counts = log.counts()
    assert counts["events"] == {"action": 2, "freeze": 1}
    assert counts["verdicts"] == {"allow": 1, "block": 1}


def test_modified_record_detected(tmp_path: Path) -> None:
    path = tmp_path / "s.jsonl"
    log = AuditLog(path)
    for index in range(3):
        log.append("action", payload={"index": index})
    lines = path.read_text(encoding="utf-8").splitlines()
    record = json.loads(lines[1])
    record["payload"]["index"] = 999
    lines[1] = json.dumps(record)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    ok, bad_seq = log.verify()
    assert not ok and bad_seq == 2


def test_deleted_record_detected(tmp_path: Path) -> None:
    path = tmp_path / "s.jsonl"
    log = AuditLog(path)
    for index in range(3):
        log.append("action", payload={"index": index})
    lines = path.read_text(encoding="utf-8").splitlines()
    path.write_text("\n".join([lines[0], lines[2]]) + "\n", encoding="utf-8")
    ok, bad_seq = AuditLog(path).verify()
    assert not ok and bad_seq == 2


def test_reordered_records_detected(tmp_path: Path) -> None:
    path = tmp_path / "s.jsonl"
    log = AuditLog(path)
    for index in range(3):
        log.append("action", payload={"index": index})
    lines = path.read_text(encoding="utf-8").splitlines()
    path.write_text("\n".join([lines[1], lines[0], lines[2]]) + "\n", encoding="utf-8")
    ok, _ = AuditLog(path).verify()
    assert not ok


def test_garbage_line_detected(tmp_path: Path) -> None:
    path = tmp_path / "s.jsonl"
    log = AuditLog(path)
    log.append("action")
    with path.open("a", encoding="utf-8") as handle:
        handle.write("not json\n")
    ok, bad_seq = log.verify()
    assert not ok and bad_seq == 2


def test_read_strict_raises_on_garbage(tmp_path: Path) -> None:
    path = tmp_path / "s.jsonl"
    path.write_text("not json\n", encoding="utf-8")
    with pytest.raises(AuditError, match="损坏"):
        AuditLog(path).read()


def test_second_instance_continues_chain(tmp_path: Path) -> None:
    path = tmp_path / "s.jsonl"
    first = AuditLog(path)
    first.append("a1", payload={"v": 1})
    second = AuditLog(path)  # 模拟另一个进程继续追加
    second.append("a2", payload={"v": 2})
    records = AuditLog(path).read()
    assert len(records) == 2
    assert records[1]["prev"] == records[0]["hash"]
    ok, _ = AuditLog(path).verify()
    assert ok


def test_tail(tmp_path: Path) -> None:
    log = AuditLog(tmp_path / "s.jsonl")
    for index in range(5):
        log.append("action", payload={"index": index})
    tail = log.tail(2)
    assert [record["payload"]["index"] for record in tail] == [3, 4]
