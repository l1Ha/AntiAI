"""
命令行入口：``antiai`` / ``python -m antiai``。

退出码约定（可直接作为执行前门禁的返回值）::

    0 = 放行
    2 = 用法或策略错误
    3 = 需人工确认（review）
    4 = 阻止（block）
    5 = 会话已冻结（或全局停机中）
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import unicodedata
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from . import __version__
from .adapters import normalize_action
from .audit import AuditLog
from .control import SessionControl, safe_session_name
from .demo import run_demo
from .errors import AntiaiError, PolicyError
from .guard import Guard, default_state_dir
from .honeytokens import TEMPLATES as HONEYTOKEN_TEMPLATES
from .honeytokens import HoneytokenRegistry
from .models import Action, Decision, Verdict
from .policy import DEFAULT_POLICY, load_policy, validate_policy

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2
EXIT_REVIEW = 3
EXIT_BLOCK = 4
EXIT_FROZEN = 5


# --------------------------------------------------------------------------- #
# 公共小工具
# --------------------------------------------------------------------------- #

def _state_dir(args: argparse.Namespace) -> Path:
    raw = getattr(args, "state_dir", None)
    return Path(raw).expanduser() if raw else default_state_dir()


def _disp_width(text: str) -> int:
    """终端显示宽度（CJK 按 2 列计）。"""
    return sum(2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1 for ch in text)


def _pad(text: str, width: int) -> str:
    return text + " " * max(0, width - _disp_width(text))


def _control_log(state_dir: Path) -> AuditLog:
    """人工操作（冻结/解除/停机）的全局审计流。"""
    return AuditLog(state_dir / "audit" / "control.jsonl")


def _print_decision(decision: Decision, guard: Optional[Guard] = None) -> None:
    head = f"判定：{decision.verdict.label}（{decision.verdict.value}）"
    if decision.advisory:
        head += "　［观察模式：仅记录，未实际阻断］"
    print(head)
    if decision.frozen:
        print("状态：会话已冻结（所有动作将被阻止，需人工解除）")
    print(f"会话：{decision.action.session_id}")
    print(f"动作：{decision.action.describe()}")
    if decision.matched_rules:
        print("命中规则：" + ", ".join(decision.matched_rules))
    print("依据：")
    for reason in decision.reasons or ["（无）"]:
        print(f"  - {reason}")
    if decision.decoy is not None:
        print("诱饵：已投放 canary 诱饵（攻击方拿到的是假凭据；该内容一旦外发即可溯源）")
    if decision.countermeasures:
        print("反制：")
        for item in decision.countermeasures:
            print(
                f"  - [{item.get('rule')}/{item.get('action')}] "
                f"{item.get('status')}：{item.get('detail', '')}"
            )
    if guard is not None:
        path = guard.state_dir / "audit" / f"{safe_session_name(decision.action.session_id)}.jsonl"
        print(f"审计：{path}")


def _print_audit_record(record: Dict[str, Any]) -> None:
    payload = record.get("payload") or {}
    if not isinstance(payload, dict):
        payload = {}
    verdict = payload.get("verdict", "-")
    raw_action = payload.get("action")
    if isinstance(raw_action, dict):
        action_text = str(raw_action.get("tool", ""))
        for key in ("command", "path", "host"):
            if raw_action.get(key):
                action_text += f" | {key}={raw_action[key]}"
                break
    elif isinstance(raw_action, str):
        # 反制事件：payload.action 是反制动作名（如 freeze / lockdown）
        rule = payload.get("rule")
        action_text = f"{rule}/{raw_action}" if rule else raw_action
    else:
        action_text = ""
    ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(float(record.get("ts", 0) or 0)))
    print(f"#{record.get('seq')}  {ts}  {record.get('event')}  {verdict}  {action_text}".rstrip())
    reasons = payload.get("reasons") or []
    if not reasons and payload.get("detail"):
        reasons = [payload["detail"]]  # 反制 / 冻结事件的说明
    for reason in reasons[:4]:
        print(f"      └ {reason}")


# --------------------------------------------------------------------------- #
# 子命令实现
# --------------------------------------------------------------------------- #

def _cmd_init(args: argparse.Namespace) -> int:
    target = Path(args.dir).expanduser() / "antiai-policy.json"
    if target.exists() and not args.force:
        print(f"策略文件已存在：{target}（如需覆盖请加 --force）")
        return EXIT_USAGE
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(DEFAULT_POLICY, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(f"已写入默认策略：{target}")
    print("下一步：")
    print("  1) 按需编辑 rules / protected.paths / detectors.params")
    print("  2) antiai validate          # 校验策略")
    print("  3) antiai demo              # 运行内置演示")
    return EXIT_OK


def _cmd_validate(args: argparse.Namespace) -> int:
    problems = validate_policy(args.policy)
    if problems:
        print("策略校验未通过：")
        for problem in problems:
            print(f"  ✗ {problem}")
        return EXIT_USAGE
    try:
        policy = load_policy(args.policy)
        source = policy.source_path or "<内置默认策略>"
        print(
            f"✓ 策略校验通过：{source}（{len(policy.rules)} 条规则，"
            f"{len(policy.protected_paths)} 条受保护路径，"
            f"自动冻结阈值 {policy.freeze_after_blocks()} 次）"
        )
    except PolicyError:
        print("✓ 策略校验通过")
    return EXIT_OK


def _build_action(args: argparse.Namespace) -> Action:
    arg_map: Dict[str, Any] = {}
    for item in args.arg or []:
        if "=" not in item:
            raise ValueError(f"--arg 需要 key=value 形式：{item!r}")
        key, value = item.split("=", 1)
        try:
            parsed: Any = json.loads(value)
        except json.JSONDecodeError:
            parsed = value
        arg_map[key] = parsed
    if args.command is not None:
        arg_map.setdefault("command", args.command)
    if args.path is not None:
        arg_map.setdefault("path", args.path)
    if args.host is not None:
        arg_map.setdefault("host", args.host)
    return normalize_action({"tool": args.tool, "args": arg_map}, session_id=args.session)


def _verdict_exit_code(decision: Decision) -> int:
    if decision.frozen:
        return EXIT_FROZEN
    if decision.advisory:
        return {Verdict.REVIEW: EXIT_REVIEW, Verdict.BLOCK: EXIT_BLOCK}.get(decision.verdict, EXIT_OK)
    if decision.allowed:
        return EXIT_OK
    return {Verdict.REVIEW: EXIT_REVIEW, Verdict.BLOCK: EXIT_BLOCK}.get(decision.verdict, EXIT_BLOCK)


def _cmd_check(args: argparse.Namespace) -> int:
    try:
        action = _build_action(args)
    except ValueError as exc:
        print(f"参数错误：{exc}", file=sys.stderr)
        return EXIT_USAGE
    guard = Guard(
        load_policy(args.policy),
        state_dir=args.state_dir,
        session_id=args.session,
        advisory=args.advisory,
        persist_counters=not args.stateless,
        aggressive=False if args.stateless else None,
    )
    decision = guard.evaluate(action)
    if args.json:
        print(json.dumps(decision.to_dict(), ensure_ascii=False, indent=2))
    else:
        _print_decision(decision, guard)
    return _verdict_exit_code(decision)


def _cmd_eval_json(args: argparse.Namespace) -> int:
    """旁路模式：stdin 逐行读动作（JSON），stdout 逐行写判定（JSON）。"""
    guard = Guard(
        load_policy(args.policy),
        state_dir=args.state_dir,
        session_id=args.session,
        advisory=args.advisory,
    )
    for line_no, line in enumerate(sys.stdin, start=1):
        line = line.strip()
        if not line:
            continue
        try:
            payload = json.loads(line)
            decision = guard.evaluate(payload)
            sys.stdout.write(json.dumps(decision.to_dict(), ensure_ascii=False) + "\n")
        except Exception as exc:  # noqa: BLE001 —— 单行错误不终止流
            sys.stdout.write(
                json.dumps(
                    {"line": line_no, "error": str(exc), "input": line[:200]},
                    ensure_ascii=False,
                )
                + "\n"
            )
        sys.stdout.flush()
    return EXIT_OK


def _cmd_demo(args: argparse.Namespace) -> int:
    policy = load_policy(args.policy) if args.policy else None
    report = run_demo(policy=policy, state_dir=args.state_dir, aggressive=args.aggressive)
    if report["aggressive"]:
        print(
            "ANTIAI 主动反制演示：不止挡住，还要还击"
            "（封锁 / 取证 / 告警 / 终止钩子 / 隔离 / 蜜罐诱饵 / 内容级溯源）"
        )
    else:
        print(
            f"ANTIAI 演示：模拟一个试图反击的 AI 智能体"
            f"（默认策略 + 自动冻结阈值 {report['freeze_after_blocks']} 次）"
        )
    print(f"会话：{report['session']}　状态目录：{report['state_dir']}")
    print("─" * 78)
    for row in report["rows"]:
        tag = {"allow": "放行", "review": "需确认", "block": "阻止"}.get(row.verdict, row.verdict)
        if row.frozen:
            tag = f"{tag}/冻结"
        print(f"[{row.index:>2}] {_pad(tag, 10)} {row.label}")
        for reason in row.reasons[:3]:
            print(f"     └ {reason}")
        for item in row.countermeasures:
            print(
                f"     ⚔ 反制 [{item.get('rule')}/{item.get('action')}] "
                f"{item.get('status')}：{item.get('detail', '')}"
            )
        if row.note:
            print(f"     ※ {row.note}")
    print("─" * 78)
    state_dir = report["state_dir"]
    if report["aggressive"]:
        lock_info = report["status"].get("lockdown_info") or {}
        print(f"结果：会话 {report['session']} 处于封锁状态 —— {lock_info.get('reason', '')}")
        print(
            f"      蜜罐凭据 {len(report['honeytokens'])} 只　事件报告 {len(report['incidents'])} 份　"
            f"隔离 {len(report.get('quarantined', []))} 项　"
            f"终止钩子调用 {report['hooks_called'].get('terminate', 0)} 次　"
            f"告警 {report['hooks_called'].get('alert', 0)} 次"
        )
        for incident in report["incidents"][-2:]:
            print(f"      事件报告：{incident}")
        print("后续操作：")
        print(f"  antiai incidents --session {report['session']} --state-dir {state_dir}      # 列出全部事件报告")
        print(f"  antiai report <事件id> --state-dir {state_dir}                              # 阅读完整报告")
        print(f"  antiai quarantine list --state-dir {state_dir}                              # 查看隔离保险库")
        print(f"  antiai unlock --session {report['session']} --state-dir {state_dir}         # 人工解除封锁")
    else:
        frozen_info = report["status"].get("frozen_info") or {}
        print(f"结果：会话 {report['session']} 已冻结 —— {frozen_info.get('reason', '')}")
        print("后续操作：")
        print(f"  antiai log    --session {report['session']} --state-dir {state_dir}            # 查看审计")
        print(f"  antiai log    --session {report['session']} --state-dir {state_dir} --verify   # 校验审计哈希链")
        print(f"  antiai status --session {report['session']} --state-dir {state_dir}            # 查看状态")
        print(f"  antiai release --session {report['session']} --state-dir {state_dir}           # 人工解除冻结")
        print("提示：antiai demo --aggressive 可查看主动反制（封锁/取证/蜜罐/诱饵）演示")
    return EXIT_OK


def _cmd_log(args: argparse.Namespace) -> int:
    state_dir = _state_dir(args)
    if args.file:
        path = Path(args.file).expanduser()
    else:
        path = state_dir / "audit" / f"{safe_session_name(args.session)}.jsonl"
    log = AuditLog(path)
    if args.verify:
        ok, bad_seq = log.verify()
        if ok:
            print(f"✓ 审计链校验通过：{path}（{len(log.read(strict=False))} 条记录）")
            return EXIT_OK
        print(f"✗ 审计链校验失败：第 {bad_seq} 条记录起被篡改或损坏（{path}）", file=sys.stderr)
        return EXIT_ERROR
    records = log.tail(args.tail) if args.tail else log.read(strict=False)
    if not records:
        print(f"（无审计记录：{path}）")
        return EXIT_OK
    for record in records:
        if args.json:
            print(json.dumps(record, ensure_ascii=False))
        else:
            _print_audit_record(record)
    return EXIT_OK


def _cmd_status(args: argparse.Namespace) -> int:
    state_dir = _state_dir(args)
    control = SessionControl(state_dir)
    log = AuditLog(state_dir / "audit" / f"{safe_session_name(args.session)}.jsonl")
    ok, bad_seq = log.verify()
    info: Dict[str, Any] = control.status(args.session)
    info["audit_path"] = str(log.path)
    info["audit_verified"] = ok
    if not ok:
        info["audit_first_bad_seq"] = bad_seq
    info["audit_counts"] = log.counts()
    counters = control.read_counters(args.session)
    if counters:
        info["counters"] = counters
    tokens = HoneytokenRegistry(state_dir).load()
    incidents = sorted((state_dir / "incidents").glob("*.md"))
    info["honeytokens"] = len(tokens)
    info["incidents"] = len(incidents)
    if args.json:
        print(json.dumps(info, ensure_ascii=False, indent=2))
        return EXIT_OK
    print(f"会话：{info['session']}")
    print(f"状态目录：{info['state_dir']}")
    if info["frozen"]:
        frozen_info = info["frozen_info"] or {}
        print(f"会话冻结：是（原因：{frozen_info.get('reason', '')}；操作者：{frozen_info.get('by', '')}）")
    else:
        print("会话冻结：否")
    if info.get("lockdown"):
        lock_info = info.get("lockdown_info") or {}
        print(
            f"会话封锁：是（原因：{lock_info.get('reason', '')}；"
            f"解除：antiai unlock --session {info['session']}）"
        )
    else:
        print("会话封锁：否")
    if info["global_stop"]:
        stop_info = info["global_stop_info"] or {}
        print(f"全局停机：是（原因：{stop_info.get('reason', '')}）")
    else:
        print("全局停机：否")
    if counters:
        print(
            f"拦截计数：累计拦截 {counters.get('blocked', 0)} 次　放行 {counters.get('allowed', 0)} 次　"
            f"需确认 {counters.get('reviewed', 0)} 次"
        )
    print(f"蜜罐凭据：{info['honeytokens']} 只　事件报告：{info['incidents']} 份")
    counts = info["audit_counts"]
    print(f"审计：{info['audit_path']}")
    print(
        f"  记录数 {sum(counts['events'].values())}　"
        f"事件 {counts['events']}　判定 {counts['verdicts']}　"
        f"链校验 {'通过' if ok else '失败'}"
    )
    if info["frozen"]:
        print(f"解除冻结：antiai release --session {info['session']} --state-dir {info['state_dir']}")
    return EXIT_OK


def _cmd_freeze(args: argparse.Namespace) -> int:
    state_dir = _state_dir(args)
    control = SessionControl(state_dir)
    info = control.freeze(args.session, reason=args.reason, by=args.by)
    _control_log(state_dir).append("freeze", session=args.session, payload=info)
    print(f"已冻结会话：{args.session}（原因：{args.reason}；操作者：{args.by}）")
    print("该会话的所有动作将被阻止，直至 `antiai release` 人工解除。")
    return EXIT_OK


def _cmd_release(args: argparse.Namespace) -> int:
    state_dir = _state_dir(args)
    control = SessionControl(state_dir)
    released = control.release(args.session)
    cleared = control.clear_counters(args.session)
    _control_log(state_dir).append(
        "release",
        session=args.session,
        payload={"released": released, "counters_cleared": cleared, "by": args.by},
    )
    if released:
        print(f"已解除会话冻结：{args.session}（拦截计数已清零）")
    else:
        print(f"会话 {args.session} 当前未处于冻结状态（拦截计数已清零）")
    control_status = control.status(args.session)
    if control_status.get("lockdown"):
        print(f"注意：该会话仍处于封锁状态，解除：antiai unlock --session {args.session}")
    return EXIT_OK


def _cmd_stop_all(args: argparse.Namespace) -> int:
    state_dir = _state_dir(args)
    control = SessionControl(state_dir)
    info = control.stop_all(reason=args.reason, by=args.by)
    _control_log(state_dir).append("stop_all", session="*", payload=info)
    print(f"全局紧急制动已启用：所有会话的所有动作都将被阻止（原因：{args.reason}）")
    print("解除：antiai resume-all")
    return EXIT_OK


def _cmd_resume_all(args: argparse.Namespace) -> int:
    state_dir = _state_dir(args)
    control = SessionControl(state_dir)
    resumed = control.resume_all()
    _control_log(state_dir).append("resume_all", session="*", payload={"resumed": resumed, "by": args.by})
    print("已解除全局紧急制动。" if resumed else "当前未启用全局紧急制动（无需解除）。")
    return EXIT_OK


# --------------------------------------------------------------------------- #
# 封锁 / 蜜罐 / 事件报告 / 隔离保险库
# --------------------------------------------------------------------------- #

def _cmd_lockdown(args: argparse.Namespace) -> int:
    state_dir = _state_dir(args)
    control = SessionControl(state_dir)
    info = control.lockdown(args.session, reason=args.reason, by=args.by)
    _control_log(state_dir).append("lockdown", session=args.session, payload=info)
    print(f"已封锁会话：{args.session}（原因：{args.reason}；操作者：{args.by}）")
    print("执行类工具与全部对外网络将被阻止，只读观察保留。")
    print(f"解除：antiai unlock --session {args.session}")
    return EXIT_OK


def _cmd_unlock(args: argparse.Namespace) -> int:
    state_dir = _state_dir(args)
    control = SessionControl(state_dir)
    unlocked = control.unlock(args.session)
    _control_log(state_dir).append("unlock", session=args.session, payload={"unlocked": unlocked, "by": args.by})
    print(f"已解除会话封锁：{args.session}" if unlocked else f"会话 {args.session} 当前未处于封锁状态。")
    return EXIT_OK


def _cmd_honeytoken_plant(args: argparse.Namespace) -> int:
    state_dir = _state_dir(args)
    registry = HoneytokenRegistry(state_dir)
    try:
        token = registry.plant(
            args.path, kind=args.kind, session=args.session, overwrite=args.overwrite
        )
    except FileExistsError as exc:
        print(f"无法投放：{exc}", file=sys.stderr)
        return EXIT_USAGE
    print(f"已投放诱饵：{token.path}")
    print(f"  canary 编号：{token.id}（内容含 ANTIAI-CANARY-{token.id}）")
    print("提示：把诱饵放到被管对象会去翻的位置（项目根目录、工作区、~/.aws 等）——它一碰就暴露。")
    return EXIT_OK


def _cmd_honeytoken_list(args: argparse.Namespace) -> int:
    registry = HoneytokenRegistry(_state_dir(args))
    tokens = registry.load()
    if args.json:
        print(json.dumps([token.to_dict() for token in tokens], ensure_ascii=False, indent=2))
        return EXIT_OK
    if not tokens:
        print("（尚未投放任何诱饵。投放：antiai honeytoken plant）")
        return EXIT_OK
    print(f"共 {len(tokens)} 只诱饵：")
    for token in tokens:
        stamp = time.strftime("%Y-%m-%d %H:%M", time.localtime(token.created))
        print(f"  - {token.path}")
        print(
            f"    canary {token.id}　类型 {token.kind}　投放会话 {token.session}　{stamp}"
            + (f"　{token.note}" if token.note else "")
        )
    return EXIT_OK


def _cmd_incidents(args: argparse.Namespace) -> int:
    state_dir = _state_dir(args)
    incidents_dir = state_dir / "incidents"
    records: List[Dict[str, Any]] = []
    for path in sorted(incidents_dir.glob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(data, dict) and (not args.session or data.get("session") == args.session):
            records.append(data)
    records.sort(key=lambda item: float(item.get("ts", 0) or 0), reverse=True)
    if args.tail:
        records = records[: int(args.tail)]
    if args.json:
        print(json.dumps(records, ensure_ascii=False, indent=2))
        return EXIT_OK
    if not records:
        print(f"（无事件报告：{incidents_dir}）")
        return EXIT_OK
    for data in records:
        stamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(float(data.get("ts", 0) or 0)))
        print(
            f"[{data.get('id')}] {stamp}　{data.get('severity')}/{data.get('verdict')}　"
            f"工具={data.get('action', {}).get('tool')}　触发规则={data.get('rule')}"
        )
        canaries = data.get("canaries") or []
        if canaries:
            print(f"    ⚑ 蜜罐命中：" + ", ".join(str(item.get("id")) for item in canaries))
        for item in (data.get("countermeasures") or [])[:4]:
            print(f"    - {item.get('action')}: {item.get('status')}　{str(item.get('detail', ''))[:80]}")
    print()
    print(f"共 {len(records)} 份。查看完整报告：antiai report <事件id> --state-dir {state_dir}")
    return EXIT_OK


def _cmd_report(args: argparse.Namespace) -> int:
    incidents_dir = _state_dir(args) / "incidents"
    report_path = incidents_dir / f"{args.id}.md"
    if not report_path.exists():
        matches = sorted(incidents_dir.glob(f"*{args.id}*.md"))
        if len(matches) == 1:
            report_path = matches[0]
        elif not matches:
            print(f"未找到事件报告：{args.id}（目录：{incidents_dir}）", file=sys.stderr)
            return EXIT_USAGE
        else:
            print(
                "匹配到多份报告，请给出更完整的 id："
                + ", ".join(path.stem for path in matches[:5]),
                file=sys.stderr,
            )
            return EXIT_USAGE
    print(report_path.read_text(encoding="utf-8"))
    return EXIT_OK


def _cmd_quarantine_list(args: argparse.Namespace) -> int:
    state_dir = _state_dir(args)
    vault_root = state_dir / "quarantine"
    entries: List[Dict[str, Any]] = []
    for meta_path in sorted(vault_root.glob("*/meta.json")):
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            meta = {}
        meta.setdefault("entry", meta_path.parent.name)
        entries.append(meta)
    if args.json:
        print(json.dumps(entries, ensure_ascii=False, indent=2))
        return EXIT_OK
    if not entries:
        print(f"（隔离保险库为空：{vault_root}）")
        return EXIT_OK
    print(f"隔离保险库共 {len(entries)} 项：")
    for meta in entries:
        stamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(float(meta.get("ts", 0) or 0)))
        print(f"  - [{meta.get('entry')}] 原路径={meta.get('original_path')}　会话={meta.get('session')}　{stamp}")
    print(f"恢复：antiai quarantine restore <entry> --state-dir {state_dir}")
    return EXIT_OK


def _cmd_quarantine_restore(args: argparse.Namespace) -> int:
    state_dir = _state_dir(args)
    entry_dir = state_dir / "quarantine" / args.entry
    meta_path = entry_dir / "meta.json"
    if not meta_path.exists():
        print(f"未找到隔离条目：{args.entry}", file=sys.stderr)
        return EXIT_USAGE
    try:
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        meta = {}
    payloads = [path for path in entry_dir.iterdir() if path.name != "meta.json"]
    if not payloads:
        print(f"隔离条目为空：{entry_dir}", file=sys.stderr)
        return EXIT_ERROR
    source = payloads[0]
    target = (
        Path(args.to).expanduser()
        if args.to
        else Path(str(meta.get("original_path") or source.name)).expanduser()
    )
    if target.exists():
        print(f"目标已存在，未覆盖：{target}（可加 --to 指定其他位置）", file=sys.stderr)
        return EXIT_USAGE
    target.parent.mkdir(parents=True, exist_ok=True)
    os.replace(str(source), str(target))
    try:
        entry_dir.rmdir()
    except OSError:
        pass
    _control_log(state_dir).append(
        "quarantine_restore",
        session=str(meta.get("session", "-")),
        payload={"entry": args.entry, "restored_to": str(target)},
    )
    print(f"已恢复：{target}")
    return EXIT_OK


# --------------------------------------------------------------------------- #
# 解析器
# --------------------------------------------------------------------------- #

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="antiai",
        description=(
            "ANTIAI —— AI / 智能体行为防护护栏：拦截越权、自保、外泄与对抗性反击行为，"
            "并按策略主动反制（封锁 / 取证 / 告警 / 隔离 / 终止 / 蜜罐诱饵）。"
        ),
        epilog="退出码：0 放行 / 2 用法或策略错误 / 3 需人工确认 / 4 阻止 / 5 会话已冻结（含本次触发冻结）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"antiai {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_init = sub.add_parser("init", help="写入默认策略文件 antiai-policy.json")
    p_init.add_argument("--dir", default=".", help="目标目录（默认当前目录）")
    p_init.add_argument("--force", action="store_true", help="覆盖已存在的策略文件")
    p_init.set_defaults(func=_cmd_init)

    p_validate = sub.add_parser("validate", help="校验策略文件")
    p_validate.add_argument("--policy", help="策略文件路径（默认自动发现或使用内置策略）")
    p_validate.set_defaults(func=_cmd_validate)

    p_check = sub.add_parser("check", help="判定单个动作（可脚本化，作为执行前门禁）")
    p_check.add_argument("--policy", help="策略文件路径")
    p_check.add_argument("--state-dir", help="状态目录（默认 ~/.antiai 或 $ANTIAI_STATE_DIR）")
    p_check.add_argument("--session", default="default", help="会话名（默认 default）")
    p_check.add_argument("--tool", required=True, help="工具名，如 shell.exec / file.read")
    p_check.add_argument("--command", help="命令文本（等价 --arg command=...）")
    p_check.add_argument("--path", help="路径（等价 --arg path=...）")
    p_check.add_argument("--host", help="主机（等价 --arg host=...）")
    p_check.add_argument("--arg", action="append", metavar="K=V", help="任意参数（可重复，值按 JSON 解析）")
    p_check.add_argument("--advisory", action="store_true", help="观察模式：只记录不阻断")
    p_check.add_argument(
        "--stateless",
        action="store_true",
        help="无状态判定：不读写拦截计数、不触发反制动作（仍写审计、仍尊重冻结/封锁）",
    )
    p_check.add_argument("--json", action="store_true", help="输出完整判定 JSON")
    p_check.set_defaults(func=_cmd_check)

    p_eval = sub.add_parser("eval-json", help="旁路模式：stdin 读 NDJSON 动作，stdout 写判定")
    p_eval.add_argument("--policy", help="策略文件路径")
    p_eval.add_argument("--state-dir", help="状态目录")
    p_eval.add_argument("--session", default="default", help="会话名")
    p_eval.add_argument("--advisory", action="store_true", help="观察模式：只记录不阻断")
    p_eval.set_defaults(func=_cmd_eval_json)

    p_demo = sub.add_parser("demo", help="运行内置演示（模拟 AI 反击 → 护栏拦截 → 冻结）")
    p_demo.add_argument("--policy", help="策略文件路径（默认使用内置演示策略）")
    p_demo.add_argument("--state-dir", help="状态目录")
    p_demo.add_argument(
        "--aggressive",
        action="store_true",
        help="主动反制演示：封锁 / 取证 / 告警 / 终止钩子 / 隔离 / 蜜罐诱饵 / 内容级溯源",
    )
    p_demo.set_defaults(func=_cmd_demo)

    p_log = sub.add_parser("log", help="查看 / 校验审计日志")
    p_log.add_argument("--state-dir", help="状态目录")
    p_log.add_argument("--session", default="default", help="会话名")
    p_log.add_argument("--file", help="直接指定审计文件路径（优先于 --session）")
    p_log.add_argument("--tail", type=int, help="只看最后 N 条")
    p_log.add_argument("--verify", action="store_true", help="校验哈希链完整性")
    p_log.add_argument("--json", action="store_true", help="按 JSON 行输出原始记录")
    p_log.set_defaults(func=_cmd_log)

    p_status = sub.add_parser("status", help="查看会话冻结状态与审计统计")
    p_status.add_argument("--state-dir", help="状态目录")
    p_status.add_argument("--session", default="default", help="会话名")
    p_status.add_argument("--json", action="store_true", help="输出 JSON")
    p_status.set_defaults(func=_cmd_status)

    p_freeze = sub.add_parser("freeze", help="冻结会话（紧急制动，立即阻止其所有动作）")
    p_freeze.add_argument("--session", required=True, help="会话名")
    p_freeze.add_argument("--state-dir", help="状态目录")
    p_freeze.add_argument("--reason", default="人工冻结", help="冻结原因")
    p_freeze.add_argument("--by", default="human:cli", help="操作者标识")
    p_freeze.set_defaults(func=_cmd_freeze)

    p_release = sub.add_parser("release", help="解除会话冻结")
    p_release.add_argument("--session", required=True, help="会话名")
    p_release.add_argument("--state-dir", help="状态目录")
    p_release.add_argument("--by", default="human:cli", help="操作者标识")
    p_release.set_defaults(func=_cmd_release)

    p_stop = sub.add_parser("stop-all", help="全局紧急制动：阻止所有会话")
    p_stop.add_argument("--state-dir", help="状态目录")
    p_stop.add_argument("--reason", default="全局紧急制动", help="停机原因")
    p_stop.add_argument("--by", default="human:cli", help="操作者标识")
    p_stop.set_defaults(func=_cmd_stop_all)

    p_resume = sub.add_parser("resume-all", help="解除全局紧急制动")
    p_resume.add_argument("--state-dir", help="状态目录")
    p_resume.add_argument("--by", default="human:cli", help="操作者标识")
    p_resume.set_defaults(func=_cmd_resume_all)

    p_lockdown = sub.add_parser("lockdown", help="封锁会话：禁执行、断网，保留只读观察")
    p_lockdown.add_argument("--session", required=True, help="会话名")
    p_lockdown.add_argument("--state-dir", help="状态目录")
    p_lockdown.add_argument("--reason", default="人工封锁", help="封锁原因")
    p_lockdown.add_argument("--by", default="human:cli", help="操作者标识")
    p_lockdown.set_defaults(func=_cmd_lockdown)

    p_unlock = sub.add_parser("unlock", help="解除会话封锁")
    p_unlock.add_argument("--session", required=True, help="会话名")
    p_unlock.add_argument("--state-dir", help="状态目录")
    p_unlock.add_argument("--by", default="human:cli", help="操作者标识")
    p_unlock.set_defaults(func=_cmd_unlock)

    p_honeytoken = sub.add_parser("honeytoken", help="蜜罐凭据：投放 / 查看诱饵（碰了就知道）")
    honeytoken_sub = p_honeytoken.add_subparsers(dest="honeytoken_command", required=True)
    ht_plant = honeytoken_sub.add_parser("plant", help="投放一只诱饵（写入假凭据文件并登记）")
    ht_plant.add_argument("--path", help="诱饵文件路径（默认 ./antiai-honeypot/<默认文件名>）")
    ht_plant.add_argument("--kind", default="env", choices=sorted(HONEYTOKEN_TEMPLATES), help="诱饵类型")
    ht_plant.add_argument("--session", default="default", help="归属会话名")
    ht_plant.add_argument("--state-dir", help="状态目录")
    ht_plant.add_argument("--overwrite", action="store_true", help="覆盖已存在的文件")
    ht_plant.set_defaults(func=_cmd_honeytoken_plant)
    ht_list = honeytoken_sub.add_parser("list", help="列出已投放的诱饵")
    ht_list.add_argument("--state-dir", help="状态目录")
    ht_list.add_argument("--json", action="store_true", help="输出 JSON")
    ht_list.set_defaults(func=_cmd_honeytoken_list)

    p_incidents = sub.add_parser("incidents", help="列出主动反制生成的事件报告")
    p_incidents.add_argument("--state-dir", help="状态目录")
    p_incidents.add_argument("--session", help="只显示指定会话")
    p_incidents.add_argument("--tail", type=int, help="只显示最近 N 份")
    p_incidents.add_argument("--json", action="store_true", help="输出 JSON")
    p_incidents.set_defaults(func=_cmd_incidents)

    p_report = sub.add_parser("report", help="查看某份事件报告（Markdown 全文）")
    p_report.add_argument("id", help="事件 id（支持子串匹配）")
    p_report.add_argument("--state-dir", help="状态目录")
    p_report.set_defaults(func=_cmd_report)

    p_quarantine = sub.add_parser("quarantine", help="隔离保险库：查看 / 恢复被隔离的涉密文件")
    quarantine_sub = p_quarantine.add_subparsers(dest="quarantine_command", required=True)
    q_list = quarantine_sub.add_parser("list", help="列出隔离条目")
    q_list.add_argument("--state-dir", help="状态目录")
    q_list.add_argument("--json", action="store_true", help="输出 JSON")
    q_list.set_defaults(func=_cmd_quarantine_list)
    q_restore = quarantine_sub.add_parser("restore", help="把隔离的文件恢复到原路径")
    q_restore.add_argument("entry", help="隔离条目名（见 quarantine list）")
    q_restore.add_argument("--to", help="恢复到指定路径（默认恢复原路径）")
    q_restore.add_argument("--state-dir", help="状态目录")
    q_restore.set_defaults(func=_cmd_quarantine_restore)

    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args) or 0)
    except PolicyError as exc:
        print(f"策略错误：{exc}", file=sys.stderr)
        return EXIT_USAGE
    except AntiaiError as exc:
        print(f"错误：{exc}", file=sys.stderr)
        return EXIT_ERROR
    except KeyboardInterrupt:
        print("\n已中断。", file=sys.stderr)
        return 130


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
