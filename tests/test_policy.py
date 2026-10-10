"""策略引擎测试：匹配语义、规则决胜、解析、加载与校验。"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from antiai.errors import PolicyError
from antiai.models import Action, Verdict
from antiai.policy import (
    DEFAULT_POLICY,
    Rule,
    default_policy,
    load_policy,
    policy_from_dict,
    validate_policy,
)


def _action(tool: str = "file.read", **kwargs) -> Action:
    return Action(tool=tool, **kwargs)


class TestMatching:
    def test_tool_glob(self) -> None:
        rule = Rule(id="r", match={"tool": "file.*"}, verdict=Verdict.ALLOW)
        assert rule.matches(_action("file.read"))
        assert rule.matches(_action("file.write"))
        assert not rule.matches(_action("shell.exec"))

    def test_tool_glob_list(self) -> None:
        rule = Rule(id="r", match={"tool": ["file.*", "fs.read"]}, verdict=Verdict.ALLOW)
        assert rule.matches(_action("fs.read"))

    def test_path_expands_home(self, tmp_path: Path) -> None:
        rule = Rule(id="r", match={"path": "~/.ssh/**"}, verdict=Verdict.BLOCK)
        assert rule.matches(_action(path=str(Path.home() / ".ssh" / "id_rsa")))
        assert not rule.matches(_action(path=str(tmp_path / "id_rsa")))

    def test_relative_path_pattern_matches_any_depth(self) -> None:
        rule = Rule(id="r", match={"path": "workspace/**"}, verdict=Verdict.ALLOW)
        assert rule.matches(_action(path="/home/user/proj/workspace/a.txt"))
        assert not rule.matches(_action(path="/home/user/proj/other/a.txt"))

    def test_double_star_pattern(self) -> None:
        rule = Rule(id="r", match={"path": "**/.env"}, verdict=Verdict.BLOCK)
        assert rule.matches(_action(path="/srv/app/.env"))

    def test_missing_path_does_not_match(self) -> None:
        rule = Rule(id="r", match={"path": "**/.env"}, verdict=Verdict.BLOCK)
        assert not rule.matches(_action(command="echo hi"))

    def test_host_case_insensitive(self) -> None:
        rule = Rule(id="r", match={"host": "API.Example.COM"}, verdict=Verdict.REVIEW)
        assert rule.matches(_action("http.post", host="api.example.com"))

    def test_command_regex(self) -> None:
        rule = Rule(id="r", match={"command": r"\bsudo\b"}, verdict=Verdict.BLOCK)
        assert rule.matches(_action("shell.exec", command="sudo apt install nmap"))
        assert not rule.matches(_action("shell.exec", command="ls -la"))

    def test_empty_match_never_matches(self) -> None:
        rule = Rule(id="r", match={}, verdict=Verdict.ALLOW)
        assert not rule.matches(_action())

    def test_unknown_match_key_never_matches(self) -> None:
        rule = Rule(id="r", match={"toolz": "*"}, verdict=Verdict.ALLOW)
        assert not rule.matches(_action("file.read"))


class TestDecideRules:
    def test_priority_allow_overrides_block(self, policy_factory) -> None:
        policy = policy_factory(
            rules=[
                {"id": "block-it", "match": {"tool": "shell.exec"}, "verdict": "block", "severity": "high"},
                {"id": "allow-it", "match": {"tool": "shell.exec"}, "verdict": "allow", "priority": 10},
            ]
        )
        verdict, rules = policy.decide_rules(Action(tool="shell.exec"))
        assert verdict is Verdict.ALLOW
        assert [rule.id for rule in rules] == ["allow-it"]

    def test_same_priority_takes_most_restrictive(self, policy_factory) -> None:
        policy = policy_factory(
            rules=[
                {"id": "allow-it", "match": {"tool": "file.read"}, "verdict": "allow"},
                {"id": "block-it", "match": {"tool": "file.read"}, "verdict": "block", "severity": "high"},
            ]
        )
        verdict, rules = policy.decide_rules(Action(tool="file.read"))
        assert verdict is Verdict.BLOCK
        assert {rule.id for rule in rules} == {"allow-it", "block-it"}

    def test_no_match_returns_none(self, policy_factory) -> None:
        policy = policy_factory(rules=[])
        verdict, rules = policy.decide_rules(Action(tool="mystery.tool"))
        assert verdict is None and rules == []


class TestPolicyConfig:
    def test_default_policy(self) -> None:
        policy = default_policy()
        assert policy.default_verdict is Verdict.REVIEW
        assert policy.freeze_after_blocks() == 3
        assert policy.is_protected_path(str(Path.home() / ".antiai" / "audit" / "x.jsonl"))
        assert policy.is_protected_process("pkill -f antiai-guard")
        assert not policy.is_protected_process("ls -la")
        assert policy.detector_enabled("tamper")

    def test_detector_params_and_disabled(self, policy_factory) -> None:
        policy = policy_factory(
            detectors={
                "disabled": ["runaway"],
                "params": {"exfiltration": {"link_window_seconds": 10}},
            }
        )
        assert not policy.detector_enabled("runaway")
        assert policy.detector_param("exfiltration", "link_window_seconds", 300) == 10
        assert policy.detector_param("exfiltration", "missing_key", 42) == 42


class TestParsing:
    def test_invalid_verdict(self) -> None:
        with pytest.raises(PolicyError, match="非法判定值"):
            policy_from_dict({"rules": [{"id": "r", "match": {"tool": "*"}, "verdict": "deny"}]})

    def test_duplicate_rule_id(self) -> None:
        with pytest.raises(PolicyError, match="重复"):
            policy_from_dict(
                {
                    "rules": [
                        {"id": "r", "match": {"tool": "*"}},
                        {"id": "r", "match": {"tool": "*"}},
                    ]
                }
            )

    def test_missing_rule_id(self) -> None:
        with pytest.raises(PolicyError, match="缺少 id"):
            policy_from_dict({"rules": [{"match": {"tool": "*"}}]})

    def test_unknown_match_key(self) -> None:
        with pytest.raises(PolicyError, match="未知匹配字段"):
            policy_from_dict({"rules": [{"id": "r", "match": {"toolz": "*"}}]})

    def test_bad_command_regex(self) -> None:
        with pytest.raises(PolicyError, match="正则非法"):
            policy_from_dict({"rules": [{"id": "r", "match": {"command": "(["}}]})

    def test_bad_always_block_regex(self) -> None:
        with pytest.raises(PolicyError, match="正则非法"):
            policy_from_dict({"always_block_commands": ["(("]})

    def test_non_dict_root(self) -> None:
        with pytest.raises(PolicyError, match="根节点"):
            policy_from_dict(["not", "a", "dict"])  # type: ignore[arg-type]


class TestLoading:
    def test_load_json_file(self, tmp_path: Path) -> None:
        path = tmp_path / "antiai-policy.json"
        path.write_text(json.dumps(DEFAULT_POLICY, ensure_ascii=False), encoding="utf-8")
        policy = load_policy(path)
        assert policy.source_path == str(path)
        assert len(policy.rules) == len(DEFAULT_POLICY["rules"])

    def test_load_yaml_file(self, tmp_path: Path) -> None:
        yaml = pytest.importorskip("yaml")
        path = tmp_path / "antiai-policy.yaml"
        path.write_text(yaml.safe_dump(DEFAULT_POLICY, allow_unicode=True), encoding="utf-8")
        policy = load_policy(path)
        assert policy.rules

    def test_load_missing_file(self, tmp_path: Path) -> None:
        with pytest.raises(PolicyError, match="不存在"):
            load_policy(tmp_path / "nope.json")

    def test_load_discovers_cwd(self, tmp_path: Path, monkeypatch) -> None:
        path = tmp_path / "antiai-policy.json"
        path.write_text(json.dumps(DEFAULT_POLICY), encoding="utf-8")
        monkeypatch.chdir(tmp_path)
        policy = load_policy()
        assert policy.source_path == str(path)

    def test_load_falls_back_to_builtin(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.chdir(tmp_path)
        policy = load_policy()
        assert policy.source_path == "<内置默认策略>"


class TestCountermeasurePolicy:
    def test_default_policy_has_countermeasures(self) -> None:
        policy = default_policy()
        assert policy.countermeasures_enabled() is True
        ids = [str(rule.get("id")) for rule in policy.countermeasure_rules()]
        assert "strike-on-honeytoken" in ids
        assert "lockdown-on-critical-attack" in ids
        assert policy.quarantine_paths()
        assert policy.terminate_config().get("enabled") is False
        assert policy.terminate_config().get("dry_run") is True
        assert policy.deception_enabled() is False

    def test_decoy_for_matches_globs(self, policy_factory) -> None:
        policy = policy_factory(deception={"enabled": True, "decoys": {"**/.env": "env"}})
        assert policy.decoy_for("/srv/app/.env") == "env"
        assert policy.decoy_for("/srv/app/notes.md") is None
        assert policy.decoy_for(None) is None

    def test_non_dict_blocks_rejected(self) -> None:
        with pytest.raises(PolicyError, match="countermeasures"):
            policy_from_dict({"countermeasures": []})
        with pytest.raises(PolicyError, match="deception"):
            policy_from_dict({"deception": []})
        with pytest.raises(PolicyError, match="countermeasures.rules"):
            policy_from_dict({"countermeasures": {"rules": "x"}})

    def test_validate_unknown_countermeasure_action(self) -> None:
        problems = validate_policy(
            {
                "rules": [],
                "countermeasures": {
                    "enabled": True,
                    "rules": [{"id": "x", "when": {"detectors": ["tamper"]}, "actions": ["nuke"]}],
                },
            }
        )
        assert any("未知反制动作" in problem for problem in problems)

    def test_validate_unknown_when_key_and_severity(self) -> None:
        problems = validate_policy(
            {
                "rules": [],
                "countermeasures": {
                    "enabled": True,
                    "rules": [
                        {"id": "x", "when": {"mystery": 1, "min_severity": "extreme"}, "actions": ["alert"]}
                    ],
                },
            }
        )
        assert any("未知触发条件" in problem for problem in problems)
        assert any("非法 min_severity" in problem for problem in problems)

    def test_validate_duplicate_countermeasure_ids(self) -> None:
        problems = validate_policy(
            {
                "rules": [],
                "countermeasures": {
                    "enabled": True,
                    "rules": [
                        {"id": "dup", "when": {"detectors": ["tamper"]}, "actions": ["alert"]},
                        {"id": "dup", "when": {"detectors": ["tamper"]}, "actions": ["alert"]},
                    ],
                },
            }
        )
        assert any("规则 id 重复" in problem for problem in problems)

    def test_validate_enabled_without_rules_and_bad_decoy_kind(self) -> None:
        problems = validate_policy(
            {
                "rules": [],
                "countermeasures": {"enabled": True, "rules": []},
                "deception": {"enabled": True, "decoys": {"**/.env": "not-a-template"}},
            }
        )
        assert any("未定义任何规则" in problem for problem in problems)
        assert any("未知诱饵模板" in problem for problem in problems)

    def test_validate_empty_when_is_rejected(self) -> None:
        problems = validate_policy(
            {
                "rules": [],
                "countermeasures": {
                    "enabled": True,
                    "rules": [{"id": "x", "when": {}, "actions": ["alert"]}],
                },
            }
        )
        assert any("when 必须是非空对象" in problem for problem in problems)


class TestValidate:
    def test_validate_default_ok(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.chdir(tmp_path)
        assert validate_policy(None) == []

    def test_validate_reports_semantic_problems(self) -> None:
        problems = validate_policy({"rules": [], "detectors": {"disabled": ["nope"]}})
        assert any("rules 为空" in problem for problem in problems)
        assert any("未知检测器" in problem for problem in problems)

    def test_validate_invalid_json(self, tmp_path: Path) -> None:
        path = tmp_path / "bad.json"
        path.write_text("{not json", encoding="utf-8")
        problems = validate_policy(path)
        assert problems and "解析失败" in problems[0]

    def test_validate_structural_error(self) -> None:
        problems = validate_policy({"rules": [{"id": "r", "match": {"tool": "*"}, "verdict": "nope"}]})
        assert any("非法判定值" in problem for problem in problems)
