# ANTIAI 架构

## 数据流

```
                    ┌────────────────────────────────────────────────┐
   工具调用/命令     │                  Guard.evaluate                │
   ─────────────▶  │                                                │
   (adapters 归一化) │  0. control.is_blocked(会话)                   │
                    │     ├─ 全局停机 / 会话冻结 → block(frozen) 直接返回│
                    │     └─ 否则继续                                 │
                    │  0.5 control.is_lockdown(会话)                 │
                    │     └─ 封锁中且动作属于执行/网络类 → 注入阻断项    │
                    │  1. policy.decide_rules(action)                │
                    │     → 最高 priority 档内取最强判定               │
                    │  2. 逐个检测器 check(action, state, policy)      │
                    │     → findings（命中即硬约束；含蜜罐路径/内容级）  │
                    │  3. 合成：most_restrictive(规则 + findings)      │
                    │     → 无输入时 default_verdict（默认 review）     │
                    │  4. review → approver 回调（异常视为不批准）      │
                    │  4.5 未放行 + deception 开启 → 投放 canary 诱饵   │
                    │  5. 计数：block 达到阈值 → control.freeze(自动)   │
                    │  6. counterstrike.respond(decision, state)     │
                    │     → 封锁/冻结/隔离/取证/告警/终止（逐条审计）     │
                    │  7. audit.append(完整 Decision)                │
                    └───────────────┬────────────────────────────────┘
                                    ▼
                      Decision{verdict, allowed, reasons, findings, matched_rules,
                               frozen, requires_approval, decoy, countermeasures}
```

## 模块职责

| 模块 | 职责 | 关键约束 |
| :--- | :--- | :--- |
| `models.py` | 动作/发现/判定的数据模型，动作指纹 | 纯数据，无 I/O |
| `adapters.py` | 把 dict / OpenAI 工具调用 / 字符串归一化为 `Action`，提取 command/path/host | 不解析命令内容（那是检测器的事） |
| `policy.py` | 规则匹配语义、决胜规则、策略加载与校验、默认策略、反制与诱饵配置 | 校验期失败要给出可定位的中文错误 |
| `detectors.py` | 八类行为检测器（含蜜罐）+ 会话状态（重复计数、冷却、敏感访问时间戳） | 每个检测器只做一件事；异常由 Guard 兜底为阻断 |
| `honeytokens.py` | 蜜罐凭据：投放诱饵文件、canary 登记表、内容/路径检索、诱饵内容模板 | 诱饵全部是假凭据，不含任何真实密钥 |
| `counterstrike.py` | 主动反制引擎：条件匹配、六种反制动作、事件报告（JSON+Markdown） | 反制失败不影响判定主流程；已放行动作不反制 |
| `control.py` | 冻结 / 封锁 / 全局停机标志的读写（原子写） | 文件化，保证跨进程与"AI 之外"的解除途径 |
| `audit.py` | JSONL 追加 + sha256 哈希链 + 校验 + 统计 | 内存缓存最后一条记录，避免每次追加都全量读 |
| `guard.py` | 判定流水线、会话状态管理、装饰器、GuardedShell、hooks 注入 | fail-closed；检测器不可被 allow 规则漂白 |
| `demo.py` | 内置演示：防御模式（11 步覆盖七类行为 + 失控 + 冻结后试探）与主动反制模式（含假情报包与面包屑情节） | 复用真实 Guard，不做假判定 |
| `decoys.py` | 假情报生成器：诱饵文档包（quick/standard/full）、面包屑引导、提示词片段、按清单清理 | 构建期强制保留命名空间自检；整包 < 100 KB；不生成真实人物信息 |
| `cli.py` | 全部子命令，退出码即结论 | 人类输出与 `--json` 输出分离 |

## 关键设计决策

1. **fail-closed 默认**
   无规则命中 → `default_verdict`（默认 `review`，即不放行）；
   检测器抛异常 → 追加 critical 阻断发现。宁可误拒，不可误放。

2. **检测器是硬约束**
   判定合成只做"取最严格"，不存在"allow 规则覆盖检测项"的路径。
   需要放行时只有两种正道：提高对应规则 priority 以覆盖**规则**判定，
   或在策略里显式禁用/调参**检测器**（这是一个显式、可审计的决定）。

3. **六级升级阶梯与自动冻结**
   `allow → review → block → lockdown → freeze → stop-all`。
   拦截计数持久化在 `<状态目录>/sessions/<会话>.state.json`（时间窗内保留最近 100 个拦截时刻），
   冻结/封锁标志在 `sessions/<会话>.{frozen,lockdown}`——前者让**多次独立的一次性进程调用**
   （如脚本里的 `antiai check` 门禁）也能累计试探次数，后者跨进程可读、可被外部监督进程写入。
   窗口内拦截数达到 `session.freeze_after_blocks` 时 Guard 自动冻结：
   这是对"持续试探、换姿势重试"的最终反制；解除只能人工，且解除会清零计数。
   计数持久化是"最后写入者胜"（并发多进程下计数可能少计，冻结标志文件则为原子语义），
   高并发场景建议单点 Guard 或容器内单会话串行化。
   封锁（lockdown）是介于 block 与 freeze 之间的一档：掐掉执行与对外网络、保留只读观察，
   用于"先控制住、再取证"的主动反制场景。

4. **审计哈希链**
   每条记录 `hash = sha256(prev_hash ‖ canonical(body))`。
   校验同时检查 `seq` 连续性与 `prev` 指向，因此**改写、删除中间行、重排**都会暴露；
   尾部整体截断无法自证，属于已知盲区（文档中明示，建议异地备份）。

5. **归一化而非内容解析**
   适配器只负责把"动作"映射到 `tool/command/path/host/args` 五个维度；
   对命令文本的语义判断全部集中在检测器，便于独立测试与调参。

6. **主动反制：条件是数据，动作是副作用**
   反制规则（条件 → 动作列表）完全由策略描述，引擎只负责评估与执行；
   条件支持检测器/严重级/判定/冻结触发/窗口计数/路径范围六个维度，
   **路径范围（`paths`）是破坏性动作（隔离）的安全阀**——可把作用面锁死在指定目录内。
   规则默认每会话触发一次（`repeat` 可开），避免告警风暴；
   已放行的动作（含人工批准）不反制，避免"批了又抢"的矛盾行为；
   反制异常一律降级为 `failed` 结果并继续判定主流程（反制绝不反噬护栏本身）。
   `terminate` 与 `alert` 通过 hooks 把真实能力（docker kill / systemctl stop / webhook）
   留给部署侧注入：护栏只做判定与编排，不内置任何"杀进程"默认行为。

7. **蜜罐与诱饵：双触发 + 可溯源**
   蜜罐触发有两条独立通道：**路径级**（动作命中已登记诱饵文件，含命令文本提到该路径）
   与**内容级**（动作携带/外发 canary 标记）。canary 正则以字面量 `antiai-canary-<12hex>`
   与伪装成 AWS key id 的 `AKIA<12hex>` 两种形式匹配，并用否定断言避免误伤真实凭据格式。
   诱饵投放（deception）复用同一套登记表：被阻止的窃取动作"拿到"的假凭据内嵌新 canary，
   因此攻击方后续任何使用/外发都会被精确指认到具体诱饵与会话。

8. **假情报包：生成即自检，面包屑即证据**
   `decoys.py` 批量生成高仿真诱饵文档（.env / deploy.yaml / runbook / onboarding），
   每条假信息内嵌独立 canary（字段级溯源），canary 编号取自种子随机流（诱饵包可复现）。
   两个硬约束：
   - **构建期自检**：URL/邮箱/IP 全部强制落在保留命名空间（`.internal`/`.example`/`.test`、
     RFC 5737 文档段），显式拒绝真实服务域名——诱饵"看起来真"但永远不可用；
   - **体积预算**：整包 < 100 KB、单文件 < 16 KB（测试固化）。
   面包屑（onboarding / README 的"顺手一提"）让发现路径本身成为行为证据；
   提示词片段（`decoy snippet`）把同一机制延伸到上下文层面：放进系统提示的假信息
   一旦出现在任何对外输出中即可溯源。清理按清单执行且拒绝清单根目录之外的路径。

9. **状态隔离**
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
