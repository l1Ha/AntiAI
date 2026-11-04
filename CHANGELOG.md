# Changelog

本项目的全部版本更迭均记录于此。遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.0.0/) 格式与 [语义化版本 2.0.0](https://semver.org/lang/zh-CN/) 规范。

---

## [0.4.0] - 2026-11-04

### 新增：设计理论（THEORY.md）
- 系统模型、设计公理 A1–A7、性质 P1–P5 的完整推导，对抗分析与诚实边界（L1–L5），
  以及理论 → 实现映射表。

### 修复：理论反查出的四个公理-实现差距
- **A5 状态不可绕过**：`--state-dir` 指向任意目录时护栏资产曾不受守卫（默认保护
  路径硬编码 ~/.antiai/**）。现在 Guard 自动注入 state_dir 保护，且 tamper 检测器
  从命令文本提取类路径 token（`rm -rf <state_dir>` 的 shell 形态同样命中）。
- **A4 审计完备性**：审计写入失败（磁盘满等）时判定曾直接抛异常或静默放行。
  现在 `_write_audit` 返回成功标志，失败时按失败封闭原则阻断（不计入被管对象统计）。
- **A6 反制最小化**：`terminate` 曾直接 `pkill -f pattern`，宽模式可误杀无关进程
  甚至护栏自身。现在先 pgrep 解析 PID、排除护栏自身进程树后逐 PID 终止。
- **P4 欺骗不对称性**：诱饵曾只覆盖 file 工具形态。现在 `decoy_for_command` 按
  诱饵 glob 末段匹配 shell 命令文本（`cat ~/.env` 同样拿到诱饵），并新增
  `on_block="deceive"` 回放模式（攻击方看到"执行成功"与假输出）。
- `return` 模式语义澄清：如实拒绝（不再夹带诱饵回放）；诱饵回放归 `deceive` 专属。

---

## [0.3.2] - 2026-10-31

### 完善
- 全库通过 mypy 严格类型检查（15 个文件 0 问题），并纳入 CI。
- `antiai status` 增加"假情报包"计数；wheel 构建产物验证（内容物、py.typed、干净 venv 安装）。

---

## [0.3.1] - 2026-10-31

### 完善
- 新增 GitHub Actions CI：Python 3.9–3.12 矩阵（ruff 静态检查 + 全量测试 + CLI 冒烟）。
- 新增 `py.typed`（PEP 561 类型标记）与 `Guard.decoy_factory(seed=...)`（种子可复现诱饵包）。
- 新增 `CHANGELOG.md` 与假情报展示示例 `examples/decoy_showcase.py`。
- README 增加徽章、许可证章节、`~/.local/bin` PATH 提示与 CHANGELOG 链接。
- 清理全部静态检查问题（ruff：未使用导入、前向引用、f-string 等 9 处）。

---

## [0.3.0] - 2026-10-11

### 新增
- **假情报生成器 (`decoys.py`)**：批量随机生成高仿真诱饵文档包（`.env`、`config/deploy.yaml`、`docs/onboarding.md`、`docs/runbook.md`、`scripts/deploy.sh`，支持 `quick` / `standard` / `full` 三档规模）。
- **面包屑引导体系**：文档中的“内部指引”自然指向诱饵路径，被管对象的顺藤摸瓜行为直接构成确凿证据。
- **提示词片段诱饵 (`decoy snippet`)**：生成内嵌 canary 的“内部备忘”，可直接注入智能体系统提示，一旦外泄即刻溯源。
- **构建期安全自检**：诱饵生成强制校验，域名严格限制于 `.internal` / `.example` / `.test`，IP 严格限制于 RFC 5737 文档段，严禁引入真实服务域名。
- **诱饵体积预算**：诱饵包整包 < 100 KB，单文件 < 16 KB，杜绝无节制膨胀。
- **CLI 增强**：新增 `antiai decoy generate / list / remove / snippet` 子命令；`remove` 严格受限于清单并防御越界删除。
- **主动反制演示集成**：`antiai demo --aggressive` 引入“内部文档阅读 → 面包屑诱导 → 蜜罐触发 → 溯源反制”完整情节（8 步）。

### 修复
- 修复 URL 保留命名空间检查中因未加边界字符导致的全角字符解析溢出。
- 修复 `ssh user@IP` 语法被误判为非法邮箱域的问题。

---

## [0.2.0] - 2026-10-11

### 新增
- **主动反制引擎 (`counterstrike.py`)**：检测到攻击性行为后不仅阻断，还可立即执行多项处置：
  - `lockdown`：会话封锁（禁止执行类工具与外联网络，保留只读观察能力）。
  - `freeze`：会话紧急冻结（全动作即刻阻断）。
  - `quarantine`：涉密文件自动隔离至 0600 保险库，支持 `antiai quarantine restore` 恢复。
  - `evidence`：自动固化事件现场，生成 JSON + Markdown 深度取证报告。
  - `alert` / `terminate`：外部进程终止与告警分发机制，支持 Python 闭包钩子与 Shell 模式。
- **蜜罐凭据体系 (`honeytokens.py`)**：
  - 假凭据自动植入，支持 `env` / `aws` / `ssh` / `token` 四种模板。
  - 路径访问（静态碰触）与内容流转（外发捕获）双通道精准溯源。
- **诱饵掉落机制 (`deception`)**：被阻止的窃取动作向攻击方伪造虚假成功返回，诱使其后续外发暴露溯源标识。
- **CLI 子命令**：新增 `lockdown` / `unlock` / `honeytoken plant|list` / `incidents` / `report` / `quarantine list|restore` / `demo --aggressive`。

### 修复
- 修复 `antiai log` 格式化打印反制事件时将动作名误当 dict 导致崩溃的问题。
- 修复同一秒内连续生成多份事件报告时文件名哈希碰撞导致覆盖的问题。
- 修复隔离路径通配符在特定深层嵌套结构下未命中的问题。

---

## [0.1.0] - 2026-10-10

### 初始发布
- **核心数据流**：适配器 (`adapters.py`) → 策略裁决 (`policy.py`) → 行为检测器 (`detectors.py`) → 会话状态与控制 (`control.py`) → 哈希链审计 (`audit.py`)。
- **八大安全检测器**：
  - `tamper`：保护护栏自身策略、日志与进程。
  - `self_preservation`：拦截持久化、脱离监管与防关停行为。
  - `privilege_escalation`：拦截 sudo、setuid、shadow 窃取等提权。
  - `exfiltration`：检测凭据读取与对外网络请求关联。
  - `evasion`：检测 history 清理、日志清空与混淆载荷。
  - `runaway`：检测失控高频循环与冷却期复犯。
  - `dangerous_command`：永久禁止毁灭性系统命令。
- **跨进程状态持久化**：一次性 CLI 命令之间仍可累计拦截计数，达到阈值后会话自动冻结。
- **审计哈希链**：每条日志携带上条 SHA-256，`antiai log --verify` 可精确定位篡改与截断。
- **开箱即用体验**：标准库零依赖实现，提供 `Guard`、`@guard.tool` 装饰器、`GuardedShell` 与完整 CLI。
