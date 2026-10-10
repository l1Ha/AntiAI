"""CLI 测试：退出码约定、策略校验、审计与冻结管理。"""

from __future__ import annotations

import io
import json
import sys
from pathlib import Path

from antiai.cli import EXIT_BLOCK, EXIT_FROZEN, EXIT_OK, EXIT_REVIEW, EXIT_USAGE, main


def _state(tmp_path: Path) -> list:
    return ["--state-dir", str(tmp_path / "state")]


class TestInitValidate:
    def test_init_and_validate(self, tmp_path: Path, capsys) -> None:
        assert main(["init", "--dir", str(tmp_path)]) == EXIT_OK
        policy_path = tmp_path / "antiai-policy.json"
        assert policy_path.exists()
        # 已存在 → 不加 --force 时拒绝
        assert main(["init", "--dir", str(tmp_path)]) == EXIT_USAGE
        assert main(["init", "--dir", str(tmp_path), "--force"]) == EXIT_OK
        assert main(["validate", "--policy", str(policy_path)]) == EXIT_OK
        assert "校验通过" in capsys.readouterr().out

    def test_validate_invalid_policy(self, tmp_path: Path, capsys) -> None:
        bad = tmp_path / "bad.json"
        bad.write_text(
            '{"rules": [{"id": "x", "match": {"tool": "*"}, "verdict": "nope"}]}', encoding="utf-8"
        )
        assert main(["validate", "--policy", str(bad)]) == EXIT_USAGE
        assert "未通过" in capsys.readouterr().out

    def test_validate_missing_file(self, tmp_path: Path) -> None:
        assert main(["validate", "--policy", str(tmp_path / "nope.json")]) == EXIT_USAGE


class TestCheck:
    def test_allow_exit_code(self, tmp_path: Path) -> None:
        assert main(["check", *_state(tmp_path), "--tool", "file.read", "--path", str(tmp_path / "a.md")]) == EXIT_OK

    def test_block_exit_code(self, tmp_path: Path) -> None:
        assert (
            main(["check", *_state(tmp_path), "--tool", "shell.exec", "--command", "pkill -f antiai-guard"])
            == EXIT_BLOCK
        )

    def test_review_exit_code(self, tmp_path: Path) -> None:
        assert (
            main(["check", *_state(tmp_path), "--tool", "http.post", "--host", "api.example.com"])
            == EXIT_REVIEW
        )

    def test_frozen_exit_code(self, tmp_path: Path) -> None:
        state = tmp_path / "state"
        assert main(["freeze", "--state-dir", str(state), "--session", "default", "--reason", "演习"]) == EXIT_OK
        assert main(["check", *_state(tmp_path), "--tool", "file.read", "--path", "/tmp/x"]) == EXIT_FROZEN

    def test_probe_freeze_across_cli_invocations(self, tmp_path: Path) -> None:
        """一次性 check 进程之间也要累计拦截次数并自动冻结。"""
        state = tmp_path / "state"
        base = ["check", "--state-dir", str(state), "--session", "probe"]
        assert main([*base, "--tool", "shell.exec", "--command", "sudo id"]) == EXIT_BLOCK
        assert main([*base, "--tool", "process.kill", "--arg", "name=antiai-guard"]) == EXIT_BLOCK
        # 第 3 次拦截触发自动冻结 → 本次返回 5（阻止 + 已冻结）
        assert main([*base, "--tool", "shell.exec", "--command", "setenforce 0"]) == EXIT_FROZEN
        # 冻结生效：后续动作一律 5
        assert main([*base, "--tool", "file.read", "--path", "/tmp/x"]) == EXIT_FROZEN
        # 解除后计数清零，动作恢复
        assert main(["release", "--state-dir", str(state), "--session", "probe"]) == EXIT_OK
        assert main([*base, "--tool", "file.read", "--path", "/tmp/x"]) == EXIT_OK

    def test_stateless_does_not_accumulate(self, tmp_path: Path, capsys) -> None:
        """--stateless 用于纯判定场景：反复调用不会累计拦截次数、不触发冻结。"""
        state = tmp_path / "state"
        base = ["check", "--state-dir", str(state), "--session", "pure", "--stateless"]
        for _ in range(5):
            assert main([*base, "--tool", "shell.exec", "--command", "sudo id"]) == EXIT_BLOCK
        capsys.readouterr()
        main(["status", "--state-dir", str(state), "--session", "pure", "--json"])
        payload = json.loads(capsys.readouterr().out)
        assert "counters" not in payload  # 拦截计数未被写入
        # 仍然尊重人工冻结
        assert main(["freeze", "--state-dir", str(state), "--session", "pure", "--reason", "r"]) == EXIT_OK
        assert main([*base, "--tool", "file.read", "--path", "/tmp/x"]) == EXIT_FROZEN

    def test_arg_parsing_json_values(self, tmp_path: Path) -> None:
        assert (
            main(["check", *_state(tmp_path), "--tool", "shell.exec", "--arg", "command=sudo ls"])
            == EXIT_BLOCK
        )

    def test_bad_arg_format(self, tmp_path: Path) -> None:
        assert main(["check", *_state(tmp_path), "--tool", "x", "--arg", "noequals"]) == EXIT_USAGE

    def test_json_output(self, tmp_path: Path, capsys) -> None:
        main(["check", *_state(tmp_path), "--tool", "shell.exec", "--command", "sudo ls", "--json"])
        payload = json.loads(capsys.readouterr().out)
        assert payload["verdict"] == "block"
        assert payload["findings"]
        assert payload["action"]["tool"] == "shell.exec"

    def test_advisory_keeps_recording(self, tmp_path: Path, capsys) -> None:
        assert (
            main(["check", *_state(tmp_path), "--tool", "shell.exec", "--command", "pkill -f antiai-guard", "--advisory"])
            == EXIT_BLOCK
        )
        assert "观察模式" in capsys.readouterr().out


class TestEvalJson:
    def test_stream(self, tmp_path: Path, capsys, monkeypatch) -> None:
        lines = "\n".join(
            [
                json.dumps({"tool": "file.read", "args": {"path": "/tmp/a.md"}}),
                json.dumps("pkill -f antiai-guard"),
                "not json",
            ]
        ) + "\n"
        monkeypatch.setattr(sys, "stdin", io.StringIO(lines))
        assert main(["eval-json", *_state(tmp_path), "--session", "s1"]) == EXIT_OK
        out = capsys.readouterr().out.strip().splitlines()
        assert len(out) == 3
        assert json.loads(out[0])["verdict"] == "allow"
        assert json.loads(out[1])["verdict"] == "block"
        assert "error" in json.loads(out[2])


class TestLogAndStatus:
    def test_log_verify_and_tamper_detection(self, tmp_path: Path, capsys) -> None:
        state = tmp_path / "state"
        main(["check", "--state-dir", str(state), "--session", "s", "--tool", "shell.exec", "--command", "pkill -f antiai-guard"])
        assert main(["log", "--state-dir", str(state), "--session", "s", "--verify"]) == EXIT_OK
        assert "校验通过" in capsys.readouterr().out

        path = state / "audit" / "s.jsonl"
        lines = path.read_text(encoding="utf-8").splitlines()
        record = json.loads(lines[0])
        record["payload"]["verdict"] = "allow"
        lines[0] = json.dumps(record)
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        assert main(["log", "--state-dir", str(state), "--session", "s", "--verify"]) == 1

    def test_log_human_output(self, tmp_path: Path, capsys) -> None:
        state = tmp_path / "state"
        main(["check", "--state-dir", str(state), "--session", "s", "--tool", "shell.exec", "--command", "sudo ls"])
        assert main(["log", "--state-dir", str(state), "--session", "s"]) == EXIT_OK
        out = capsys.readouterr().out
        assert "action" in out and "block" in out and "sudo" in out

    def test_log_json_output(self, tmp_path: Path, capsys) -> None:
        state = tmp_path / "state"
        main(["check", "--state-dir", str(state), "--tool", "file.read", "--path", "/tmp/a.md"])
        capsys.readouterr()  # 清掉 check 的人类可读输出，只看 log 的 JSON
        assert main(["log", "--state-dir", str(state), "--json", "--tail", "1"]) == EXIT_OK
        record = json.loads(capsys.readouterr().out.strip())
        assert record["seq"] == 1 and record["event"] == "action"

    def test_status_json(self, tmp_path: Path, capsys) -> None:
        state = tmp_path / "state"
        assert main(["status", "--state-dir", str(state), "--session", "s", "--json"]) == EXIT_OK
        payload = json.loads(capsys.readouterr().out)
        assert payload["frozen"] is False and payload["session"] == "s"
        assert "audit_counts" in payload


class TestFreezeCommands:
    def test_freeze_release_status_roundtrip(self, tmp_path: Path, capsys) -> None:
        state = tmp_path / "state"
        assert main(["freeze", "--state-dir", str(state), "--session", "a", "--reason", "r"]) == EXIT_OK
        capsys.readouterr()
        main(["status", "--state-dir", str(state), "--session", "a", "--json"])
        assert json.loads(capsys.readouterr().out)["frozen"] is True
        assert main(["release", "--state-dir", str(state), "--session", "a"]) == EXIT_OK
        capsys.readouterr()
        main(["status", "--state-dir", str(state), "--session", "a", "--json"])
        assert json.loads(capsys.readouterr().out)["frozen"] is False

    def test_stop_all_and_resume_all(self, tmp_path: Path) -> None:
        state = tmp_path / "state"
        assert main(["stop-all", "--state-dir", str(state), "--reason", "演习"]) == EXIT_OK
        assert main(["check", "--state-dir", str(state), "--tool", "file.read", "--path", "/tmp/x"]) == EXIT_FROZEN
        assert main(["resume-all", "--state-dir", str(state)]) == EXIT_OK
        assert main(["check", "--state-dir", str(state), "--tool", "file.read", "--path", "/tmp/x"]) == EXIT_OK


class TestDemoCommand:
    def test_demo_runs(self, tmp_path: Path, capsys) -> None:
        assert main(["demo", "--state-dir", str(tmp_path / "state")]) == EXIT_OK
        out = capsys.readouterr().out
        assert "已冻结" in out and "demo-agent" in out and "外泄" in out
