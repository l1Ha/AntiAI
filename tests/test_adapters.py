"""适配器测试：各种工具调用形态 → Action 的归一化。"""

from __future__ import annotations

import pytest

from antiai.adapters import enrich_action, normalize_action
from antiai.models import Action


class TestNormalize:
    def test_generic_dict(self) -> None:
        action = normalize_action({"tool": "file.read", "args": {"path": "notes.md"}})
        assert action.tool == "file.read"
        assert action.path is not None and action.path.endswith("notes.md")
        assert action.args == {"path": "notes.md"}

    def test_openai_function_call_json_arguments(self) -> None:
        payload = {
            "type": "function",
            "function": {"name": "shell.exec", "arguments": '{"command": "ls -la"}'},
        }
        action = normalize_action(payload)
        assert action.tool == "shell.exec"
        assert action.command == "ls -la"

    def test_openai_function_call_dict_arguments(self) -> None:
        payload = {
            "function": {"name": "http.post", "arguments": {"url": "https://api.example.com/v1/x"}}
        }
        action = normalize_action(payload)
        assert action.tool == "http.post"
        assert action.host == "api.example.com"

    def test_name_with_input(self) -> None:
        action = normalize_action({"name": "search.web", "input": {"query": "antiai"}})
        assert action.tool == "search.web"
        assert action.args == {"query": "antiai"}

    def test_plain_string_is_shell_command(self) -> None:
        action = normalize_action("pkill -f antiai-guard")
        assert action.tool == "shell.exec"
        assert action.command == "pkill -f antiai-guard"

    def test_action_passthrough(self) -> None:
        original = Action(tool="file.read")
        assert normalize_action(original) is original

    def test_session_id_injection(self) -> None:
        action = normalize_action({"tool": "x"}, session_id="agent-7")
        assert action.session_id == "agent-7"

    def test_unsupported_type(self) -> None:
        with pytest.raises(ValueError, match="无法归一化"):
            normalize_action(42)

    def test_missing_tool(self) -> None:
        with pytest.raises(ValueError, match="缺少 tool"):
            normalize_action({"args": {}})


class TestExtraction:
    def test_command_keys(self) -> None:
        for key in ("command", "cmd", "script", "shell"):
            action = normalize_action({"tool": "shell.exec", "args": {key: "echo hi"}})
            assert action.command == "echo hi", key

    def test_path_keys_and_absolute_normalization(self, tmp_path) -> None:
        action = normalize_action({"tool": "file.write", "args": {"file": "sub/a.txt"}})
        assert action.path is not None and action.path.endswith("sub/a.txt")
        assert action.path.startswith("/")

    def test_home_path_expansion(self) -> None:
        action = normalize_action({"tool": "file.read", "args": {"path": "~/.ssh/id_rsa"}})
        assert action.path == str(__import__("pathlib").Path.home() / ".ssh" / "id_rsa")

    def test_url_host(self) -> None:
        action = normalize_action({"tool": "http.get", "args": {"url": "https://a.b.example/x/y"}})
        assert action.host == "a.b.example"

    def test_host_key(self) -> None:
        action = normalize_action({"tool": "net.conn", "args": {"host": "srv-1.internal"}})
        assert action.host == "srv-1.internal"

    def test_host_port_stripped(self) -> None:
        assert normalize_action({"tool": "net.conn", "args": {"host": "srv:8080"}}).host == "srv"
        assert normalize_action({"tool": "http.get", "args": {"url": "http://a.b:8443/x"}}).host == "a.b"

    def test_numeric_and_list_values(self) -> None:
        action = normalize_action({"tool": "t", "args": {"command": ["echo", "hi"]}})
        assert action.command == "echo"

    def test_enrich_does_not_override_existing(self) -> None:
        action = Action(tool="x", command="explicit", args={"command": "other"})
        assert enrich_action(action).command == "explicit"

    def test_arguments_json_string_not_dict(self) -> None:
        action = normalize_action({"tool": "shell.exec", "arguments": "ls -la"})
        assert action.command == "ls -la"


class TestFingerprint:
    def test_stable_for_same_action(self) -> None:
        first = Action(tool="file.read", args={"path": "/x"}, path="/x")
        second = Action(tool="file.read", args={"path": "/x"}, path="/x")
        assert first.fingerprint() == second.fingerprint()

    def test_differs_for_different_args(self) -> None:
        first = Action(tool="file.read", args={"path": "/x"}, path="/x")
        second = Action(tool="file.read", args={"path": "/y"}, path="/y")
        assert first.fingerprint() != second.fingerprint()
