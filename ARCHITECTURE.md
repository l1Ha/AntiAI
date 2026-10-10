# ANTIAI 架构

## 数据流

```
                    ┌────────────────────────────────────────────────┐
   工具调用/命令     │                  Guard.evaluate                │
   ─────────────▶  │                                                │
   (adapters 归一化) │  0. control.is_blocked(会话)                   │
                    │     ├─ 全局停机 / 会话冻结 → block(frozen) 直接返回│
                    │     └─ 否则继续                                 │
                    │  1. policy.decide_rules(action)                │
                    │     → 最高 priority 档内取最强判定               │
                    │  2. 逐个检测器 check(action, state, policy)      │
                    │     → findings（命中即硬约束）                   │
                    │  3. 合成：most_restrictive(规则 + findings)      │
                    │     → 无输入时 default_verdict（默认 review）     │
                    │  4. review → approver 回调（异常视为不批准）      │
                    │  5. 计数：block 达到阈值 → control.freeze(自动)   │
                    │  6. audit.append(完整 Decision)                │
                    └───────────────┬────────────────────────────────┘
                                    ▼
                      Decision{verdict, allowed, reasons, findings,
                               matched_rules, frozen, requires_approval}
```

## 模块职责

| 模块 | 职责 | 关键约束 |
| :--- | :--- | :--- |
| `models.py` | 动作/发现/判定的数据模型，动作指纹 | 纯数据，无 I/O |
| `adapters.py` | 把 dict / OpenAI 工具调用 / 字符串归一化为 `Action`，提取 command/path/host | 不解析命令内容（那是检测器的事） |
| `policy.py` | 规则匹配语义、决胜规则、策略加载与校验、默认策略 | 校验期失败要给出可定位的中文错误 |
| `detectors.py` | 七类行为检测器 + 会话状态（重复计数、冷却、敏感访问时间戳） | 每个检测器只做一件事；异常由 Guard 兜底为阻断 |
| `control.py` | 冻结标志 / 全局停机标志的读写（原子写） | 文件化，保证跨进程与"AI 之外"的解除途径 |
| `audit.py` | JSONL 追加 + sha256 哈希链 + 校验 + 统计 | 内存缓存最后一条记录，避免每次追加都全量读 |
| `guard.py` | 判定流水线、会话状态管理、装饰器、GuardedShell | fail-closed；检测器不可被 allow 规则漂白 |
| `demo.py` | 内置演示脚本（11 步，覆盖七类行为 + 失控 + 冻结后试探） | 复用真实 Guard，不做假判定 |
| `cli.py` | 全部子命令，退出码即结论 | 人类输出与 `--json` 输出分离 |

## 关键设计决策

1. **fail-closed 默认**
   无规则命中 → `default_verdict`（默认 `review`，即不放行）；
   检测器抛异常 → 追加 critical 阻断发现。宁可误拒，不可误放。

2. **检测器是硬约束**
   判定合成只做"取最严格"，不存在"allow 规则覆盖检测项"的路径。
   需要放行时只有两种正道：提高对应规则 priority 以覆盖**规则**判定，
   或在策略里显式禁用/调参**检测器**（这是一个显式、可审计的决定）。

3. **五级升级阶梯与自动冻结**
   `allow → review → block → freeze → stop-all`。
   拦截计数持久化在 `<状态目录>/sessions/<会话>.state.json`（时间窗内保留最近 100 个拦截时刻），
   冻结标志在 `sessions/<会话>.frozen`——前者让**多次独立的一次性进程调用**（如脚本里的
   `antiai check` 门禁）也能累计试探次数，后者跨进程可读、可被外部监督进程写入。
   窗口内拦截数达到 `session.freeze_after_blocks` 时 Guard 自动冻结：
   这是对"持续试探、换姿势重试"的最终反制；解除只能人工，且解除会清零计数。
   计数持久化是"最后写入者胜"（并发多进程下计数可能少计，冻结标志文件则为原子语义），
   高并发场景建议单点 Guard 或容器内单会话串行化。

4. **审计哈希链**
   每条记录 `hash = sha256(prev_hash ‖ canonical(body))`。
   校验同时检查 `seq` 连续性与 `prev` 指向，因此**改写、删除中间行、重排**都会暴露；
   尾部整体截断无法自证，属于已知盲区（文档中明示，建议异地备份）。

5. **归一化而非内容解析**
   适配器只负责把"动作"映射到 `tool/command/path/host/args` 五个维度；
   对命令文本的语义判断全部集中在检测器，便于独立测试与调参。

6. **状态隔离**
   所有会话级状态以 `session_id` 为键：`SessionState`（内存计数）、
   审计文件、冻结标志文件互不干扰；会话名统一净化后用作文件名。

## 扩展指南

### 自定义检测器

```python
from antiai.detectors import Detector, SessionState
from antiai.models import Action, Finding, Severity, Verdict
from antiai.policy import Policy
from antiai.guard import Guard

class CryptoMiningDetector(Detector):
    name = "crypto_mining"          # 可被 detectors.disabled / params 引用
    description = "检测挖矿类命令"

    def check(self, action: Action, state: SessionState, policy: Policy):
        text = (action.command or "") + " " + str(action.args)
        if "xmrig" in text or "stratum+tcp://" in text:
            return [self._finding(Severity.CRITICAL, "疑似挖矿行为")]
        return []

guard = Guard()
guard.detectors.append(CryptoMiningDetector())
```

注意：`policy.validate_policy` 的 lint 使用 `detectors.KNOWN_DETECTORS` 白名单，
新增检测器时把它注册进去（或忽略该条 lint）。

### 自定义适配器

如果 Agent 框架的动作格式特殊（例如 MCP 工具调用、自研 DSL），
在调用 `guard.evaluate` 之前自行构造 `Action` 即可，无需改动护栏内部：

```python
from antiai import Action
action = Action(tool="mcp.filesystem.write", args={...}, path="/abs/path")
decision = guard.evaluate(action)
```

### 新增一类"反击行为"的完整步骤

1. 在 `detectors.py` 增加检测器（模式列表 + `check`）；
2. 注册进 `DETECTOR_CLASSES` 与 `KNOWN_DETECTORS`；
3. 在 `DEFAULT_POLICY["rules"]` 补可选的策略规则（如需按 tool/path 先行拦截）；
4. 在 `demo.py` 增加一行演示场景；
5. 在 `tests/test_detectors.py` 补正/负例（正例给"最像攻击"的真实命令）。

## 性能与并发

- 单动作开销 = 若干正则扫描（O(命令长度)）+ `SessionState` 双端队列操作 + 一次追加写。
  审计写入按需 `fsync` 由操作系统缓冲，高频场景可在批量模式下自行关闭（`Guard(audit=False)`）。
- `Guard` 线程安全（`RLock` 保护状态字典与审计实例表）；跨进程通过文件标志协作。
- 重复动作统计窗口内只保留最近 5000 条指纹，内存有界。
