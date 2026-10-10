# ANTIAI

**在 AI / 智能体与真实世界之间，加一层不可绕过的行为护栏。**

每个工具调用、每条 Shell 命令、每次对外请求，都必须先过 ANTIAI 的判定层，再被允许执行。
越权、自保、外泄、反侦察、失控与对抗性"反击"行为会被**阻止、留痕**；
被拦截次数达到阈值后会话**自动冻结**；必要时人工一键**全局停机**。

```
动作（工具调用 / Shell / 网络请求）
        │
        ▼
  ┌───────────┐  冻结/停机  ┌──────────┐
  │  adapters │ ──────────▶ │ control  │  紧急制动（对 AI 不可绕过）
  └─────┬─────┘             └──────────┘
        ▼
  ┌───────────┐  规则裁决
  │  policy   │ ────┐
  └───────────┘     ▼
  ┌───────────┐  ┌───────────┐  ┌───────────┐
  │ detectors │─▶│   Guard   │─▶│   audit   │  sha256 哈希链审计
  └───────────┘  └─────┬─────┘  └───────────┘
                       ▼
             allow / review / block / freeze
```

---

## 威胁模型：AI 可能做出的"反击"行为

| 类别 | 典型行为 | 对应检测器 |
| :--- | :--- | :--- |
| 破坏护栏 | 改策略文件、删审计日志、`pkill` 护栏进程 | `tamper` |
| 自保抗令 | `crontab`/`systemd` 持久化、`nohup` 脱离监管、杀监护进程、`setenforce 0` | `self_preservation` |
| 提权 | `sudo`、setuid（`chmod 4755`）、改 `/etc/sudoers`、写 `authorized_keys` | `privilege_escalation` |
| 数据外泄 | 读 `.env`/私钥后向非白名单主机 `curl` 外联、`--data-binary @.env` | `exfiltration` |
| 反侦察 | `history -c`、删日志、`base64 -d \| sh`、`alias` 遮蔽系统命令 | `evasion` |
| 失控 | 高频重复动作、`while true`/`yes \|`/`dd if=/dev/zero`、冷却期复犯 | `runaway` |
| 毁灭性命令 | `rm -rf /`、fork 炸弹、`mkfs /dev/*`（永久禁止清单） | `dangerous_command` |
| 持续试探 | 被拦截后反复换姿势重试 | Guard 计数 → **自动冻结** |

## 核心能力

- **五级升级阶梯**：`allow → review（人工确认）→ block → freeze（会话冻结）→ stop-all（全局停机）`，每一步都留审计。
- **检测器是硬约束**：策略里的 `allow` 规则**无法漂白**检测器命中项（安全设计）。
- **失败封闭（fail-closed）**：无规则命中走默认判定（默认 `review`）；检测器自身异常也保守阻断。
- **冻结不可绕过**：状态目录受策略保护，AI 既改不了冻结标志，也删不掉审计记录。
- **可验证审计**：JSONL 哈希链，任何改写/删除/重排都会在 `antiai log --verify` 中暴露。
- **零运行时依赖**：仅标准库；可选 PyYAML 读取 YAML 策略。

## 安装

```bash
# 方式一：直接从源码使用（零依赖，无需安装）
python3 -m antiai demo

# 方式二：安装为命令行工具 / 库
pip install -e .            # 或 pip install . ；YAML 策略额外 pip install pyyaml
antiai --version
```

要求 Python >= 3.9。

## 60 秒上手

```bash
cd 你的项目目录
antiai init                 # 生成 antiai-policy.json（默认策略）
antiai validate             # 校验策略
antiai demo                 # 内置演示：模拟 AI 反击 → 逐级拦截 → 会话冻结
```

单动作门禁（可脚本化，退出码即结论）：

```bash
antiai check --tool shell.exec --command "pkill -f antiai-guard"
antiai check --tool file.read --path "$HOME/.ssh/id_rsa" --json
# 退出码：0 放行 / 3 需人工确认 / 4 阻止 / 5 会话已冻结（含本次触发冻结）/ 2 用法或策略错误
```

> 拦截计数会持久化到 `<状态目录>/sessions/<会话>.state.json`，因此**多次独立的一次性调用
> 也会累计**：连续试探达到阈值同样会自动冻结（计数带时间窗，默认 1 小时）。
> 纯判定/策略测试场景可加 `--stateless` 关闭计数累计。

作为库使用：

```python
from antiai import Guard

guard = Guard(session_id="agent-1")        # 自动发现当前目录策略，否则用内置策略

decision = guard.evaluate({"tool": "file.read", "args": {"path": "notes.md"}})
print(decision.allowed, decision.verdict, decision.reason_text)

# Shell 默认是 review（需人工确认）：传入 approver 模拟人工批准
result = guard.shell().run("echo hello", approver=lambda action, reasons: True)
print(result.stdout.strip())
```

## 集成方式

### 1. 装饰器：给工具函数套护栏

```python
@guard.tool("file.write", on_block="return")   # 阻止时返回结构化拒绝，适合回传给智能体
def write_file(path: str, content: str) -> str:
    ...
```

`on_block="raise"`（默认）抛 `ActionBlocked` / `SessionFrozen`；`"return"` 返回
`{"blocked": True, "reason": ..., "decision": {...}}`。

### 2. 受管 Shell

```python
shell = guard.shell(timeout=10)
shell.check("rm -rf ~/.antiai")                                # 只判定不执行 → block
shell.run("ls -la", approver=lambda action, reasons: True)     # 人工确认后执行
```

### 3. 旁路模式（任意语言 / 任意 Agent 框架）

把每个动作以一行 JSON 写给 `antiai eval-json`，读回判定行：

```bash
echo '{"tool":"shell.exec","args":{"command":"sudo rm -rf /var/log"}}' | antiai eval-json
```

### 4. 接入 OpenAI Function Calling 形态

`guard.evaluate` / `eval-json` 直接接受 `{"function": {"name": ..., "arguments": "{...}"}}`；
也接受裸字符串（视为 Shell 命令）。参数中的 `command` / `path` / `host` 会被自动提取。

### 5. 人工确认（review）

```python
decision = guard.evaluate(action, approver=lambda action, reasons: input(f"批准？{reasons} ") == "y")
```

## 策略文件

`antiai init` 生成的 `antiai-policy.json`（也支持 YAML）：

```jsonc
{
  "version": 1,
  "default_verdict": "review",              // 无规则命中时的默认判定
  "session": {
    "freeze_after_blocks": 3,        // 窗口内被拦截 N 次 → 自动冻结
    "freeze_window_seconds": 3600    // 计数时间窗（0 = 不衰减，永久累计）
  },
  "detectors": {
    "disabled": [],                          // 例如 ["runaway"]
    "params": {                              // 检测器参数（见下表）
      "exfiltration": { "egress_allow": ["localhost", "127.0.0.1", "api.mycorp.com"] }
    }
  },
  "protected": {                             // 护栏自身资产（不可被被管对象触碰）
    "paths": ["~/.antiai/**", "**/antiai-policy*.json", "**/*.audit.jsonl"],
    "processes": ["antiai", "antiai-guard"]
  },
  "always_block_commands": ["rm\\s+-rf\\s+/(?:\\s|$)", "...fork 炸弹正则..."],
  "rules": [
    {
      "id": "allow-read-tools",
      "match": { "tool": ["file.read", "search.*"] },   // fnmatch 通配，可传列表
      "verdict": "allow",
      "severity": "low",
      "reason": "常规只读操作"
    },
    {
      "id": "allow-corp-egress",
      "match": { "tool": "http.*", "host": "*.mycorp.com" },
      "verdict": "allow", "priority": 10,               // 更高 priority 才能放行
      "reason": "公司内网 API"
    },
    {
      "id": "block-policy-edit",
      "match": { "path": "**/antiai-policy*.json" },
      "verdict": "block", "severity": "critical",
      "reason": "护栏策略不可被修改"
    }
  ]
}
```

**匹配语义**

| 字段 | 含义 | 语法 |
| :--- | :--- | :--- |
| `tool` | 工具名 | fnmatch 通配（`file.*`、`shell.exec`、`*`） |
| `path` | 路径（自动 expanduser / abspath） | fnmatch；相对模式自动命中任意层级 |
| `host` | 主机名（不区分大小写） | fnmatch |
| `command` | 命令文本 | 正则（不区分大小写，`re.search`） |

**规则决胜**：先取 `priority` 最高的一档；同档内取判定最强的一条（`block > review > allow`）。
想放行某类动作，需要给它**更高的 priority**。

## 检测器参数

| 检测器 | 拦截行为 | 默认严重级 | 可调参数（`detectors.params.<名称>`） |
| :--- | :--- | :--- | :--- |
| `tamper` | 破坏护栏资产/进程 | critical | — |
| `self_preservation` | 持久化、脱离监管、阻止关停 | critical / high | — |
| `privilege_escalation` | 提权与权限扩张 | high | — |
| `exfiltration` | 凭据读取 + 非白名单外联 | critical / medium | `secret_globs`、`egress_allow`、`link_window_seconds`(300) |
| `evasion` | 清痕迹、混淆载荷、命令遮蔽 | high / medium | — |
| `runaway` | 高频重复、失控循环、冷却期复犯 | high / medium | `repeat_threshold`(25)、`window_seconds`(60)、`burst_threshold`(300)、`cooldown_seconds`(120) |
| `dangerous_command` | 永久禁止命令清单 | critical | 由 `always_block_commands` 配置 |

## 审计与紧急制动

- **审计**：`<状态目录>/audit/<会话>.jsonl`，每条记录含 `seq/ts/event/session/payload/prev/hash`，
  `hash` 为前序哈希 + 本条的 sha256（哈希链）。任何改写、删除、重排都会在校验时暴露：
  `antiai log --verify`（整条尾部被截断无法自证，建议另行备份）。
- **状态目录**：默认 `~/.antiai`，可用 `--state-dir` 或环境变量 `ANTIAI_STATE_DIR` 指定：

  ```
  <状态目录>/
  ├── STOP.json                     # 全局紧急制动标志
  ├── sessions/<会话>.frozen         # 单会话冻结标志
  ├── sessions/<会话>.state.json     # 拦截计数（跨进程持久化，供自动冻结累计）
  └── audit/<会话>.jsonl            # 哈希链审计日志
  ```
- **解除冻结**（`antiai release`）会把拦截计数一并清零，使"人工放行"成为真正的重置。
- **单会话冻结**：`antiai freeze --session agent-1 --reason "..."`（AI 侧不可解除）。
- **全局停机**：`antiai stop-all`（所有会话立即全部阻止）。
- **人工解除**：`antiai release --session agent-1` / `antiai resume-all`。

## CLI 参考

| 命令 | 说明 |
| :--- | :--- |
| `antiai init [--dir D] [--force]` | 写入默认策略 `antiai-policy.json` |
| `antiai validate [--policy P]` | 校验策略（结构 + 语义 lint） |
| `antiai check --tool T [--command C] [--path X] [--host H] [--arg K=V ...] [--json] [--advisory] [--stateless]` | 判定单个动作，退出码即结论 |
| `antiai eval-json [--session S]` | 旁路：stdin 逐行读动作 JSON，stdout 逐行写判定 JSON |
| `antiai demo` | 运行内置演示（模拟 AI 反击 → 拦截 → 冻结） |
| `antiai log [--session S] [--tail N] [--verify] [--json]` | 查看 / 校验审计日志 |
| `antiai status [--session S] [--json]` | 冻结状态 + 审计统计 + 链校验结果 |
| `antiai freeze / release --session S` | 冻结 / 解除会话 |
| `antiai stop-all / resume-all` | 全局紧急制动 / 解除 |

退出码：`0 放行 / 2 用法或策略错误 / 3 需人工确认 / 4 阻止 / 5 会话已冻结`。

## 边界与定位

ANTIAI 是**应用层行为护栏**，不是操作系统级沙箱的替代品。生产部署建议叠加：
容器/虚拟机隔离、最小权限账号、文件系统 ACL、出网代理白名单、独立审计存储（只追加介质）。

护栏生效的前提是**状态目录、策略文件与审计日志真正受保护**（例如以独立用户运行 Guard、
审计目录对 AI 进程只读甚至不可见）；否则被管对象可能绕过应用层直接落盘篡改。
请在自己的授权范围内对自有系统使用本工具。

## 开发与测试

```bash
pip install -e ".[dev]"
pytest                      # 190 个用例：策略 / 检测器 / 审计链 / 冻结 / Guard / CLI / 演示
```

## 项目结构

```
antiai/
├── models.py       # Action / Finding / Decision / Verdict / Severity
├── policy.py       # 规则匹配、策略加载与校验、内置默认策略
├── adapters.py     # 各种工具调用形态 → Action 归一化
├── detectors.py    # 七类行为检测器（tamper / self_preservation / ...）
├── guard.py        # Guard 核心：判定流水线、装饰器、GuardedShell
├── control.py      # 冻结 / 全局停机开关（文件化，对 AI 不可绕过）
├── audit.py        # sha256 哈希链审计日志
├── demo.py         # 内置演示场景
└── cli.py          # 命令行入口
```

详细设计见 [ARCHITECTURE.md](ARCHITECTURE.md)。
