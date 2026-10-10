"""主动反制引擎测试：条件匹配、各反制动作、幂等与取证报告。"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from antiai.control import SessionControl
from antiai.counterstrike import CounterStrike
from antiai.detectors import SessionState
from antiai.honeytokens import HoneytokenRegistry
from antiai.models import Action, Decision, Finding, Severity, Verdict
from antiai.policy import policy_from_dict


def make_policy(rules, **countermeasures):
    data = {
        "session": {"freeze_after_blocks": 3},
        "countermeasures": {"enabled": True, "rules": rules, **countermeasures},
        "rules": [],
    }
    return policy_from_dict(data, source="<测试策略>")


def make_decision(
    *,
    action: Action | None = None,
    verdict: Verdict = Verdict.BLOCK,
    detectors=("tamper",),
    severity: Severity = Severity.CRITICAL,
    frozen: bool = False,
    path: str | None = None,
) -> Decision:
    act = action or Action(tool="shell.exec", command="pkill -f antiai-guard", path=path)
    findings = [
        Finding(detector=name, reason=f"{name} 命中", severity=severity, verdict=Verdict.BLOCK)
        for name in detectors
    ]
    return Decision(
        action=act,
        verdict=verdict,
        allowed=False,
        reasons=["测试依据"],
        findings=findings,
        frozen=frozen,
    )


def make_engine(tmp_path: Path, policy, *, hooks=None, registry=None, state=None):
    control = SessionControl(tmp_path / "state")
    engine = CounterStrike(
        state_dir=tmp_path / "state",
        control=control,
        policy=policy,
        hooks=hooks,
        registry=registry,
    )
    return engine, SessionState("s")


class TestMatching:
    def test_detector_condition(self, tmp_path: Path) -> None:
        policy = make_policy(
            [{"id": "r1", "when": {"detectors": ["tamper"]}, "actions": ["alert"]}]
        )
        engine, state = make_engine(tmp_path, policy)
        assert engine._matches({"detectors": ["tamper"]}, make_decision(), state) is True
        assert engine._matches({"detectors": ["evasion"]}, make_decision(), state) is False

    def test_min_severity(self, tmp_path: Path) -> None:
        policy = make_policy([{"id": "r1", "when": {}, "actions": ["alert"]}])
        engine, state = make_engine(tmp_path, policy)
        high = make_decision(severity=Severity.HIGH)
        assert engine._matches({"min_severity": "high"}, high, state) is True
        assert engine._matches({"min_severity": "critical"}, high, state) is False

    def test_verdict_condition(self, tmp_path: Path) -> None:
        policy = make_policy([{"id": "r1", "when": {}, "actions": ["alert"]}])
        engine, state = make_engine(tmp_path, policy)
        assert engine._matches({"verdict": ["block"]}, make_decision(), state) is True
        assert engine._matches({"verdict": "review"}, make_decision(), state) is False

    def test_freeze_triggered_condition(self, tmp_path: Path) -> None:
        policy = make_policy([{"id": "r1", "when": {}, "actions": ["alert"]}])
        engine, state = make_engine(tmp_path, policy)
        assert engine._matches({"freeze_triggered": True}, make_decision(frozen=True), state) is True
        assert engine._matches({"freeze_triggered": True}, make_decision(frozen=False), state) is False

    def test_blocked_in_window(self, tmp_path: Path) -> None:
        policy = make_policy([{"id": "r1", "when": {}, "actions": ["alert"]}])
        engine, state = make_engine(tmp_path, policy)
        state.block_times.extend([1.0, 2.0])
        assert engine._matches({"blocked_in_window": 2}, make_decision(), state) is True
        assert engine._matches({"blocked_in_window": 3}, make_decision(), state) is False

    def test_paths_condition(self, tmp_path: Path) -> None:
        policy = make_policy([{"id": "r1", "when": {}, "actions": ["alert"]}])
        engine, state = make_engine(tmp_path, policy)
        ws_decision = make_decision(action=Action(tool="file.read", path=str(tmp_path / "ws" / "a.pem")))
        other_decision = make_decision(action=Action(tool="file.read", path=str(tmp_path / "other.pem")))
        when = {"paths": [f"{tmp_path}/ws/**"]}
        assert engine._matches(when, ws_decision, state) is True
        assert engine._matches(when, other_decision, state) is False

    def test_empty_conditions_never_match(self, tmp_path: Path) -> None:
        policy = make_policy([{"id": "r1", "when": {}, "actions": ["alert"]}])
        engine, state = make_engine(tmp_path, policy)
        assert engine._matches({}, make_decision(), state) is False


class TestActions:
    def test_freeze_action(self, tmp_path: Path) -> None:
        policy = make_policy(
            [{"id": "strike", "when": {"detectors": ["honeytoken"]}, "actions": ["freeze"]}]
        )
        engine, state = make_engine(tmp_path, policy)
        results = engine.respond("s", make_decision(detectors=("honeytoken",)), state)
        assert [item.status for item in results] == ["applied"]
        assert engine.control.frozen_info("s") is not None
        assert state.frozen is True

    def test_lockdown_action(self, tmp_path: Path) -> None:
        policy = make_policy(
            [{"id": "lock", "when": {"detectors": ["tamper"]}, "actions": ["lockdown"]}]
        )
        engine, state = make_engine(tmp_path, policy)
        results = engine.respond("s", make_decision(), state)
        assert results[0].status == "applied"
        assert engine.control.is_lockdown("s")[0] is True
        # 重复触发幂等
        engine.respond("s", make_decision(), state)
        assert engine.control.status("s")["lockdown"] is True

    def test_terminate_without_config_is_skipped(self, tmp_path: Path) -> None:
        policy = make_policy(
            [{"id": "kill", "when": {"detectors": ["tamper"]}, "actions": ["terminate"]}]
        )
        engine, state = make_engine(tmp_path, policy)
        results = engine.respond("s", make_decision(), state)
        assert results[0].status == "skipped" and "未配置" in results[0].detail

    def test_terminate_hook(self, tmp_path: Path) -> None:
        calls = []
        policy = make_policy(
            [{"id": "kill", "when": {"detectors": ["tamper"]}, "actions": ["terminate"]}]
        )
        engine, state = make_engine(tmp_path, policy, hooks={"terminate": calls.append})
        results = engine.respond("s", make_decision(), state)
        assert results[0].status == "applied"
        assert calls and calls[0]["session"] == "s"

    def test_terminate_policy_dry_run(self, tmp_path: Path) -> None:
        policy = make_policy(
            [{"id": "kill", "when": {"detectors": ["tamper"]}, "actions": ["terminate"]}],
            terminate={"enabled": True, "pattern": "definitely-not-a-real-proc-xyz", "dry_run": True},
        )
        engine, state = make_engine(tmp_path, policy)
        results = engine.respond("s", make_decision(), state)
        assert results[0].status == "skipped" and "dry_run" in results[0].detail

    def test_quarantine_action(self, tmp_path: Path) -> None:
        secret = tmp_path / "ws" / ".env"
        secret.parent.mkdir(parents=True)
        secret.write_text("REAL=1\n", encoding="utf-8")
        policy = make_policy(
            [{"id": "q", "when": {"detectors": ["exfiltration"]}, "actions": ["quarantine"]}],
            quarantine_paths=[f"{tmp_path}/**/.env"],
        )
        engine, state = make_engine(tmp_path, policy)
        decision = make_decision(
            action=Action(tool="file.read", path=str(secret)), detectors=("exfiltration",)
        )
        results = engine.respond("s", decision, state)
        assert results[0].status == "applied"
        assert not secret.exists()  # 已移出原位置
        entries = list((tmp_path / "state" / "quarantine").glob("*/meta.json"))
        assert len(entries) == 1
        meta = json.loads(entries[0].read_text(encoding="utf-8"))
        assert meta["original_path"] == str(secret)
        assert oct((entries[0].parent / ".env").stat().st_mode)[-3:] == "600"

    def test_quarantine_skips_unlisted_path(self, tmp_path: Path) -> None:
        secret = tmp_path / "ws" / ".env"
        secret.parent.mkdir(parents=True)
        secret.write_text("REAL=1\n", encoding="utf-8")
        policy = make_policy(
            [{"id": "q", "when": {"detectors": ["exfiltration"]}, "actions": ["quarantine"]}],
            quarantine_paths=[f"{tmp_path}/only-this/**"],
        )
        engine, state = make_engine(tmp_path, policy)
        decision = make_decision(
            action=Action(tool="file.read", path=str(secret)), detectors=("exfiltration",)
        )
        results = engine.respond("s", decision, state)
        assert results[0].status == "skipped" and secret.exists()

    def test_alert_writes_log_without_hook(self, tmp_path: Path) -> None:
        policy = make_policy(
            [{"id": "a", "when": {"detectors": ["tamper"]}, "actions": ["alert"]}]
        )
        engine, state = make_engine(tmp_path, policy)
        results = engine.respond("s", make_decision(), state)
        assert results[0].status == "applied"
        lines = (tmp_path / "state" / "alerts.log").read_text(encoding="utf-8").strip().splitlines()
        assert json.loads(lines[0])["session"] == "s"

    def test_alert_hook(self, tmp_path: Path) -> None:
        calls = []
        policy = make_policy(
            [{"id": "a", "when": {"detectors": ["tamper"]}, "actions": ["alert"]}]
        )
        engine, state = make_engine(tmp_path, policy, hooks={"alert": calls.append})
        engine.respond("s", make_decision(), state)
        assert calls and calls[0]["verdict"] == "block"

    def test_evidence_writes_report(self, tmp_path: Path) -> None:
        registry = HoneytokenRegistry(tmp_path / "state")
        token, content = registry.render_and_register("env", path="/tmp/decoy.env", session="s")
        policy = make_policy(
            [{"id": "ev", "when": {"detectors": ["honeytoken"]}, "actions": ["alert", "evidence"]}]
        )
        engine, state = make_engine(tmp_path, policy, registry=registry)
        decision = make_decision(detectors=("honeytoken",))
        decision.findings[0].details["canaries"] = [token.to_dict()]
        results = engine.respond("s", decision, state)
        # evidence 排在最后
        assert [item.action for item in results] == ["alert", "evidence"]
        evidence = results[-1]
        assert evidence.status == "applied"
        markdown_path = Path(evidence.detail.split("：", 1)[1])
        assert markdown_path.exists() and markdown_path.suffix == ".md"
        body = markdown_path.read_text(encoding="utf-8")
        assert "事件报告" in body and token.id in body and "蜜罐命中" in body
        json_path = markdown_path.with_suffix(".json")
        data = json.loads(json_path.read_text(encoding="utf-8"))
        assert data["canaries"][0]["id"] == token.id
        assert data["countermeasures"][0]["action"] == "alert"
        assert any("轮换" in item or "蜜罐" in item for item in data["advice"])


class TestEngineBehaviour:
    def test_disabled_engine_does_nothing(self, tmp_path: Path) -> None:
        policy = make_policy(
            [{"id": "r", "when": {"detectors": ["tamper"]}, "actions": ["freeze"]}]
        )
        engine, state = make_engine(tmp_path, policy)
        engine.enabled_override = False
        assert engine.respond("s", make_decision(), state) == []
        assert engine.control.frozen_info("s") is None

    def test_rule_fires_once_per_session_by_default(self, tmp_path: Path) -> None:
        policy = make_policy(
            [{"id": "a", "when": {"detectors": ["tamper"]}, "actions": ["alert"]}]
        )
        engine, state = make_engine(tmp_path, policy)
        first = engine.respond("s", make_decision(), state)
        second = engine.respond("s", make_decision(), state)
        assert len(first) == 1 and second == []

    def test_repeat_rule_fires_again(self, tmp_path: Path) -> None:
        policy = make_policy(
            [{"id": "a", "when": {"detectors": ["tamper"]}, "actions": ["alert"], "repeat": True}]
        )
        engine, state = make_engine(tmp_path, policy)
        assert len(engine.respond("s", make_decision(), state)) == 1
        assert len(engine.respond("s", make_decision(), state)) == 1

    def test_disabled_rule_skipped(self, tmp_path: Path) -> None:
        policy = make_policy(
            [{"id": "a", "when": {"detectors": ["tamper"]}, "actions": ["alert"], "enabled": False}]
        )
        engine, state = make_engine(tmp_path, policy)
        assert engine.respond("s", make_decision(), state) == []

    def test_unknown_action_recorded_as_failed(self, tmp_path: Path) -> None:
        policy = make_policy(
            [{"id": "a", "when": {"detectors": ["tamper"]}, "actions": ["not-a-real-action"]}]
        )
        engine, state = make_engine(tmp_path, policy)
        results = engine.respond("s", make_decision(), state)
        assert results[0].status == "failed"

    def test_audit_callback_receives_results(self, tmp_path: Path) -> None:
        policy = make_policy(
            [{"id": "a", "when": {"detectors": ["tamper"]}, "actions": ["alert"]}]
        )
        events = []
        engine, state = make_engine(tmp_path, policy)
        engine.audit = lambda session, event, payload: events.append((session, event, payload))
        engine.respond("s", make_decision(), state)
        assert events and events[0][1] == "countermeasure"
