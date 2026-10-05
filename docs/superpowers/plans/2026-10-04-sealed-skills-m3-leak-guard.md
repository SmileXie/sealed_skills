# Sealed Skills — M3「防泄漏（leak-guard）」实现计划

- 计划文件：`docs/superpowers/plans/2026-10-04-sealed-skills-m3-leak-guard.md`
- 规格来源：`docs/superpowers/specs/2026-10-04-sealed-skills-design.md` §8 / §10.2 / §10.3 / §10.4 / §11 / §12
- 前置：M1（`c7cc700`）与 M2（`5f39ef2`）已并入 `master`（173 测试全绿，两个冒烟 `disk-leak-check: clean`）。
- 接口依据：`docs/sealed-skills/notes/dsh-0.2-seams.md`（全部来自已发布 npm 产物，逐条带 file:line）。
- 目标运行时：**`@deepseek-ai/dsh@0.2.0-rc.2`**（cordis `~4.0.4`）；skill 接缝与 `0.2.1-alpha.1` 字节一致。

## 0. 目标与非目标

**M3 目标**：把"明文永不落盘"从 M1 的部分断言，升级为**在真实 dsh 上可验证的运行时保证**，并补齐 M2 遗留的"loader 未验证"。

交付物：
1. dsh 0.2.x 接缝对齐 + 兼容门（peerDependencies、注释、真机实验台）。
2. 真实 dsh 集成测试（关闭 M2 遗留项）。
3. `log-mask`：基于会话消息投影的"密文落盘、明文只进模型派生视图"。
4. `invariants` 包级检查：已提交会话事件不得出现 sealed 明文。
5. `tool-runtime`：沙箱内脚本工具，**源码不经 argv/临时文件**。
6. 泄漏验收 gate：金丝雀扫描 + §8 错误路径全覆盖 + 崩溃残留；作为发布前置。

**非目标**（属 M4 / Plan 2B / M5）：五篇生态文档、golden vectors、市场/分发与 CI 发布流水线、OS 密钥库后端、原生/WASM `DecryptBackend`。

## 1. Global Constraints（每个任务都受约束）

- **目标版本**：`@deepseek-ai/dsh@0.2.0-rc.2`（cordis `~4.0.4`）。**代码**必须同时兼容 `0.2.1-alpha.1`（skill 接缝字节一致，已核实）——这条不因下面的 peer 规则而放宽。
- **peer 版本钉定（Task 1 裁决）**：`peerDependencies` 的取值范围**刻意钉在 `0.2.0-rc.2`**（cordis `~4.0.4`），以照抄同仓插件写法。代价：app-boot 兼容门用精确 `semver.satisfies(runtime, "0.2.0-rc.2")` 判定，在 `0.2.1-alpha.1` 运行时会跳过本插件。逃生舱是官方 `dsh plugin allow-version`（精确版本豁免），在 0.2.1 运行时上显式豁免后即可加载。故"代码兼容 0.2.1"与"peer 钉 0.2.0-rc.2"并存：前者是接缝事实，后者是分发策略。
- **兼容门**：我们的包必须声明与运行时匹配的 dsh `peerDependencies`，否则 app-boot 会把 bundle 记入 `skippedBundles`。写法**照抄同仓插件**（实现前用 `npm view <pkg> peerDependencies` 核实 `@deepseek-ai/dsh-tool-skill@0.2.0-rc.2` 的实际写法）。这些 peer 必须是**可选**的：未安装 dsh 时包仍可 `build` / `test`。
- **不新增仓库依赖**：**不得**把 `@deepseek-ai/dsh*` 加进仓库依赖图（安装 ≈ 462 MB）。真机实验走 `scripts/dsh-lab.mjs`，把 dsh 装进 git-ignore 的临时目录，相关测试用环境变量门控。
- pnpm 仅经 `corepack pnpm <args>`；TS ESM NodeNext、`strict: true`；密码学只用 Node 内置；无第三方运行时依赖。
- **零明文承诺**：任何时刻不得把技能正文 / 条目密钥写进磁盘、日志、错误、遥测。泄漏 gate 必须为绿。
- **事件兼容**：自有会话事件类型必须带 `ignorable: true`（官方下游兼容机制）。**不得**让旧 reader 因未知类型拒绝重建会话，也不得让我们的 marker 成为必需事件。
- **fail-closed 且可跳过**：拿不到 dsh lab 时，真机测试显式 `skip`（不得伪装通过）；`log-mask`/`invariants` 未就绪时插件拒绝服务。
- **Node**：≥ 20（`dsh-sealed-skills` 现有 floor）；`license-server` 仍 ≥ 22.13.0，M3 不触碰。

## 2. 侦察结论（实现依据）

> 完整引用见 `docs/sealed-skills/notes/dsh-0.2-seams.md`；此处只列实现所需的最小事实。

- **事件类型**：`declare module '@deepseek-ai/dsh-session/types' { interface SessionEventMap { 'sealed/redacted': {...} } }`；事件信封 `{ type, seq, time, data, ignorable? }`，数据须为 lossless JSON（拒绝 BigInt/Map/Set/Date/class/NaN 等）。
- **消息投影**：`SessionMessageProjection<T>` 的 `project(event, ctx) => ReadonlyMap<SessionSeq, Message>`；**只能改写已提交消息 seq 的派生 `Message`（必须保留 `message.id`，不得原地修改输入）**；投影事件自身是 log-only，不进入 surface。
- **注册/恢复**：`registerMessageProjection(p)`（服务名以 `dsh-session` 的 Context 增强为准，Task 1 核实）；创建 / 恢复 / 分叉三路都要传 projections；若恢复时缺插件，`deriveMessages()` 静默回退到日志里的原始内容。
- **落盘明文的两条路径**：① 内建 `skill` 工具的 `tool/result`（内容来自 `renderSkillContent(skill)`）；② `/name` 注入的 `user/message`（`source.kind === 'skill-invocation'`）。持久化的是 `ToolExecutionSuccess.content`（`value` 不落盘）。
- **工具**：`ctx.tools.register(defineTool({ name, description, parameters, output:{schema,render}, execute }))`；schema 是自定义 DSL（非 JSON Schema）；可用 `tools/post-execute` / `tools/execute` / `tools/result` 瀑布观察或改写。
- **沙箱**：`ctx.sandbox.confine(argv: readonly string[], policy: SandboxPolicy, signal?) => ConfinedArgv`；`SandboxUnavailableError` / `SANDBOX_UNAVAILABLE` 为 fail-closed；`ctx.ptcRuntime` 非必需（普通注册工具即可）。`policy.mode ∈ {'read-only','workspace-write'}`。
- **不变式**：`ctx.invariants.register(pkg, installer)`，`installer(ctx, fail)`；`fail(msg)` 抛 `InvariantError(code:'INVARIANT')`，只拆除我们的注册。
- **加载**：profile 目录 `$DSH_HOME/profiles/<name>/cordis.yml`（+ `cordis.patch.yml`）；条目 `{ id, name, config }`；`dsh headless "<task>"` 无界面运行；`--dump-config` 自检。

## 3. 设计（一次讲清；任务按此实现）

### 3.1 让正文"只存在于派生视图"

1. 我们的 provider 对**目录与 `/name` 路径**只返回**占位正文**（不含明文；占位符携带不可猜测 token + `entryId`，便于识别）。真实正文只以密文形式存在于 pack。
2. 在**任何承载占位正文的事件提交之后**，追加自有事件 `sealed/redacted { refSeq, entryId, alg }`（`ignorable: true`）：
   - 工具结果路径：订阅 `tools/result`（观察冻结结果）或 `session/event`，识别 `tool/result` 且内容含我们的占位 token → 追加 marker。
   - `/name` 路径：订阅 `session/event`，识别 `user/message` 且 `source.kind === 'skill-invocation'` 且 name 属于我们的 pack → 追加 marker。
3. 注册 `SessionMessageProjection{ type:'sealed/redacted' }`：读取 `ctx.events` 被引用的 seq，从密文条目解密，返回 `Map{ refSeq => { ...原消息, content:[{type:'text', text:明文}] } }`，**保留 `message.id`**。→ 模型看到明文；durable log 只有占位符。
4. **恢复语义**：插件 `apply` 时注册投影；恢复时若缺插件，模型只能看到占位符（安全回退）。测试必须同时覆盖"恢复后仍有明文视图"与"缺插件时绝不出现明文"。

### 3.2 运行时不变式

`ctx.invariants.register('@sealed/dsh-sealed-skills', installer)`：订阅 `session/event`（或包装持久化后端），断言**已提交事件中不出现 sealed 明文**（金丝雀 / 条目正文），违规调用 `fail(...)`。这是"自证清白"的运行时哨兵，与离线金丝雀扫描互补。

### 3.3 脚本工具（源码不落盘、不进 argv）

`ctx.tools.register(defineTool({ name:'sealed_script_<id>', …, execute }))`：
- `execute` 在**内存**解密脚本源码，`ctx.sandbox.confine(['node','--input-type=module','-'], policy, signal)`（Python 为 `['python3','-']`），随后 spawn 并把源码写入子进程 **stdin**：既不进 argv（进程列表不可见），也不经临时文件。
- 沙箱不可用（`SandboxUnavailableError`）→ 结构化拒绝脚本工具；**纯提示词技能不受影响**。
- 呈现模式用 `native`/`both`（`ptc` 模式下模型直呼只允许保留名 `run_code`）。
- 用后零化源码缓冲；错误信息脱敏。

### 3.4 泄漏验收 gate

`scripts/leak-gate.mjs`：跑「安装 → 激活 → 列技能 → 调用技能 → 跑脚本 → 逐条触发 §8 错误表」，随后扫描**会话日志（含 zstd 压缩的 `session.jsonl`）、spill 目录、临时目录、日志、遥测**，断言金丝雀零命中；另做"解密中途杀进程"的崩溃残留检查。作为发布前置 gate（CI）。

## 4. 任务

### Task 1：dsh 0.2.x 接缝对齐 + 兼容门

**Files**：`packages/dsh-sealed-skills/package.json`、`src/provider.ts`、`src/plugin.ts`、`docs/sealed-skills/notes/dsh-skill-provider.md`（已加 SUPERSEDED 横幅，本任务补实测行）
**Produces**：与 `0.2.0-rc.2` 匹配的 optional `peerDependencies`；注释从 `0.0.1-rc.1` 更新为 `0.2.0-rc.2`（并写明 `SkillRegistry`、`SkillSummary.path?` 的"虚拟技能不提供 path"契约）；核实会话服务名与投影注册 API。

- [ ] Step 1：`npm view @deepseek-ai/dsh-tool-skill@0.2.0-rc.2 peerDependencies` 与 `@deepseek-ai/dsh-skill@0.2.0-rc.2 peerDependencies`，照抄写法。
- [ ] Step 2：修改 `package.json`（`peerDependencies` + 每个 peer 标 `optional`；`peerDependenciesMeta`）。
- [ ] Step 3：更新 `provider.ts` / `plugin.ts` 顶部注释与 `SkillSummary.path` 说明；核实 `dsh-session` 的 `Context` 增强确定服务名（记录到 notes）。
- [ ] Step 4：验证 `corepack pnpm -r build` / `-r test` 全绿（未装 dsh 仍可跑）；`node -e "await import('@sealed/dsh-sealed-skills')"` 可加载。
- [ ] Commit：`chore(dsh): align the plugin with dsh 0.2.x seams and declare optional peers`

**验收**：dsh 包 53 测试保持全绿；peer 写法与同仓插件一致；notes 记录实测的服务名/API。

### Task 2：dsh 实验台（可跳过、幂等、离线缓存）

**Files**：`scripts/dsh-lab.mjs`、`.gitignore`（加 `.dsh-lab/`）、`packages/dsh-sealed-skills/test/dsh-lab.test.ts`（门控）
**Produces**：把 `@deepseek-ai/dsh@0.2.0-rc.2` 安装进 `.dsh-lab/`（git-ignored），生成一个测试 profile（`cordis.yml` 挂载我们的 bundle），提供 `dump-config` 自检与 `headless` 运行入口。

- [ ] Step 1：脚本支持 `--ensure`（装/cache）、`--dump-config`、`--headless "<task>"`、`--clean`；幂等；失败输出可诊断原因。
- [ ] Step 2：门控测试：无 `.dsh-lab` 或未设 `SEALED_DSH_LAB=1` → `it.skip`（显式打印跳过原因，不得伪装通过）。
- [ ] Step 3：确认 `scripts/m1-smoke.mjs` / `m2-smoke.mjs` 不受影响。
- [ ] Commit：`test(dsh): add an optional out-of-tree dsh lab harness`

**验收**：`node scripts/dsh-lab.mjs --ensure --dump-config` 成功（在有网环境）；未设门控时测试 skip 且退出码 0。

### Task 3：真实 dsh 集成（关闭 M2 遗留）

**Files**：`packages/dsh-sealed-skills/test/dsh-integration.test.ts`、`docs/sealed-skills/notes/dsh-skill-provider.md`
**Consumes**：Task 2 的 lab；M2 的 pack/license 产物。

- [ ] Step 1：在测试 profile 安装 bundle、放入我们签发的 pack + license。
- [ ] Step 2：断言 `ctx.skills.list()/get()`：虚拟技能**无 `path`**、`provider` 正确、`content` 正确、`resourceBase` 正确；`skills/change` 可触发失效。
- [ ] Step 3：断言加载日志的 `skippedBundles` **不含**我们（peer 匹配生效）。
- [ ] Step 4：把 notes 的"未验证"清单中已关闭项划掉并记录实测命令/输出。
- [ ] Commit：`test(dsh): verify the sealed provider on a real 0.2.x profile`

**验收**：真机测试在 lab 就绪时通过；notes 未验证项显著收敛。

### Task 4：log-mask 核心（事件类型 + 投影 + 占位正文）

**Files**：`packages/dsh-sealed-skills/src/session-events.ts`、`src/log-mask.ts`、`src/provider.ts`、`test/log-mask.test.ts`
**Produces**：`sealed/redacted` 事件类型（TS 模块增强 + `ignorable: true`）；投影实现；provider 目录/`/name` 返回占位正文；投影的注册与 `ctx.effect` 清理。

- [ ] Step 1：声明事件类型与数据形状（`refSeq`/`entryId`/`alg`）；数据必须 lossless JSON。
- [ ] Step 2：实现投影（保留 `message.id`、输入不可变、仅改写被引用 seq）。
- [ ] Step 3：provider 目录/`/name` 改返回占位正文（占位 token 不可猜测）。
- [ ] Step 4：注册/注销投影；恢复路径重注册。
- [ ] Step 5：单测：改写正确、id 保留、缺插件回退占位（无明文）、恢复后仍返回明文、并发/重复 marker 稳定。
- [ ] Commit：`feat(leak-guard): add the sealed session event and message projection`

**验收**：单测全绿；投影在 restore 后仍生效；缺插件时不出现明文。

### Task 5：两条落盘路径的遮蔽

**Files**：`src/log-mask.ts`、`test/log-mask.test.ts`
**Consumes**：Task 4。

- [ ] Step 1：订阅 `tools/result` / `session/event`，在承载占位正文的事件后追加 marker（工具结果路径）。**必须非重入**：`session/event` 观察者在 `append` 的发布边界内被调用，同步 `append` 会抛 `session append cannot reenter…`（见 `notes/dsh-0.2-seams.md` §9.5）。用 `queueMicrotask`（或等价的后提交钩子）在边界之外追加，或退回 §3.1 的兜底（自己注册 `sealed_skill` 工具）。重入失败是 fail-safe 的（不泄漏明文，但占位符对模型可见）。
- [ ] Step 2：识别 `/name` 的 `user/message` 并追加 marker。
- [ ] Step 3：断言 **durable log 只有占位符**，`deriveMessages()` 才有明文。
- [ ] Step 4：边界：marker 顺序/并发、同一 seq 多 marker、restore 后再 append。
- [ ] Commit：`feat(leak-guard): redact both skill-content landing paths`

**验收**：落盘断言全绿；模型视图正文正确。

### Task 6：invariants 包级检查

**Files**：`src/invariant.ts`、`test/invariant.test.ts`、`package.json`（如需）
**Consumes**：Task 1 的服务名核实。

- [ ] Step 1：`ctx.invariants.register('@sealed/dsh-sealed-skills', installer)`，订阅 `session/event`（或包装持久化后端），断言无 sealed 明文。
- [ ] Step 2：单测：正常流程不触发；伪造"明文进事件"场景 → 触发 `InvariantError`（证明检查有效，而非空转）。
- [ ] Commit：`feat(leak-guard): register the sealed-plaintext runtime invariant`

**验收**：伪造场景可稳定触发；正常流程零误报。

### Task 7：沙箱脚本工具

**Files**：`src/tool-runtime.ts`、`test/tool-runtime.test.ts`、`demo/translate/`（示例脚本条目）

- [ ] Step 1：`defineTool` 注册 `sealed_script_*`；`execute` 内存解密 → `confine` → spawn，源码经 **stdin**。
- [ ] Step 2：用后零化；错误脱敏；`SandboxUnavailableError` → 结构化拒绝。
- [ ] Step 3：断言源码不出现在 argv / 磁盘 / 日志；提示词技能不受影响。
- [ ] Commit：`feat(leak-guard): run sealed scripts inside the dsh sandbox`

**验收**：脚本可执行且源码零落盘；沙箱不可用时拒绝脚本但提示词技能可用。

### Task 8：泄漏验收 gate

**Files**：`scripts/leak-gate.mjs`、`package.json`（`leak-gate` script）、`.github/workflows/leak-gate.yml`（或等价 CI 入口）、`test/leak-gate.test.ts`（如有）

- [ ] Step 1：金丝雀扫描器：会话日志（含 zstd）、spill、temp、日志、遥测；零命中断言。
- [ ] Step 2：§8 错误表逐条执行（错误消息不含正文）。
- [ ] Step 3：崩溃残留：解密中途杀进程，断言磁盘无明文。
- [ ] Step 4：作为 `corepack pnpm leak-gate`；CI 中作为必过 gate。
- [ ] Commit：`test(leak-guard): add the canary leak gate and CI wiring`

**验收**：`corepack pnpm leak-gate` 输出 `leak-gate: clean`。

### Task 9：退出标准、文档回填与最终评审

**Files**：`docs/sealed-skills/README.md`（路线图 M3 已完成项）、`docs/sealed-skills/notes/*`、必要时 spec 的 M3 注记。

- [ ] Step 1：回填文档与路线图。
- [ ] Step 2：逐条核对 M3 Exit Criteria。
- [ ] Step 3：整分支最终评审（最有力模型）+ 一次修复轮 + 定向复审。
- [ ] Commit + 收尾。

## 5. M3 Exit Criteria（合并前必须全部成立）

1. `corepack pnpm -r build` 与 `-r test` 全绿；M1/M2 的 173 个测试**零回归**。
2. 真实 dsh `0.2.0-rc.2` profile 中：虚拟技能无 `path`、正文正确、`resourceBase` 正确；`skippedBundles` 不含我们。
3. durable 会话日志 / 持久化后端 / spill / 临时目录 / 日志 / 遥测中，金丝雀**零命中**；模型派生视图正文正确。
4. **缺插件恢复**时不出现明文（回退占位符）。
5. `invariants` 检查可被"伪造明文事件"场景稳定触发，正常流程零误报。
6. 脚本源码**不经 argv、不经临时文件**；沙箱不可用时脚本工具被拒且提示词技能可用。
7. `corepack pnpm leak-gate` 输出 `leak-gate: clean`；CI gate 就位。
8. 崩溃残留：解密中途杀进程，磁盘零明文（崩溃安全）。
9. 文档回填完成，notes 未验证清单收敛并如实标注残余风险。

### 5.1 Ruling addendum（Task 5，2026-10-04，真机实测）

`docs/sealed-skills/notes/dsh-0.2-seams.md` §9.7 以真机实测**取代**本文档早先的两处写法；二者冲突时一律以 §9.7 为准：

- **Global Constraints「事件兼容」**：dsh 0.2.x 的 `session.append` 自建事件信封，`...opts` 只承载 surface metadata，非 surface 类型**无法**携带 `ignorable: true`。因此"必须带 `ignorable: true`"在 0.2.x 上不可实现。取代方案：apply 时把 `sealed/redacted` 注册进 dsh 导出的 `KNOWN_SESSION_EVENT_TYPES`（模块单例，persistence 读路径共用）；装了本插件的 harness 可正常重开会话。
- **Exit Criteria #4「缺插件恢复时不出现明文（回退占位符）」**：**"回退占位符"不可达成**——未安装本插件的 harness 因该类型不在其目录且无法标 `ignorable`，log 级 reader（`validateStoredEvents`）会直接**拒绝整条日志**（`_assertProjections` 亦会抛）。实际达成的性质是"缺插件时**无明文**"，以**拒绝读取**而非优雅回退实现；在此如实记录，不假装回退成立。
- 残余风险与上游缺口见 §9.7（建议 dsh 提供 append-with-ignorable 或 session 级 redaction API）。

## 6. Self-Review

**规格覆盖**

| 规格章节 | 落点 |
| --- | --- |
| §8 两条硬性保障（顺序保障、崩溃安全） | Task 5（顺序/遮蔽）、Task 8（崩溃残留）、Task 4（投影注册顺序） |
| §8 错误表（log-mask 注册失败、沙箱不可用等） | Task 8（逐条执行）、Task 7（沙箱拒绝） |
| §10.3 金丝雀 / 错误路径 / 崩溃 / CI gate / 不变式插件 | Task 6、Task 8 |
| §10.4 真实 dsh 集成、沙箱 | Task 3、Task 7 |
| §9 技术选型（Node 内置、TS、pnpm、脚本语言 v1） | Global Constraints、Task 7 |
| §12 仓库布局（tool-runtime / log-mask 在 bundle 内） | Task 4、Task 6、Task 7 |
| M2 遗留：loader 未验证 | Task 2、Task 3 |

**占位符扫描**：无 TBD/TODO。唯二"由实现期实测确定"的点（会话服务名、peer 版本写法）已在 Task 1 明确指定核实方式与产出。

**类型一致性**：投影返回 `ReadonlyMap<SessionSeq, Message>`；事件数据 lossless JSON；工具走 `defineTool` 的 schema DSL；沙箱 `SandboxPolicy.mode` 只用 `read-only`/`workspace-write`。

**风险与残余**（如实记录，不掩饰）
- 真实 dsh 启动仍需 `$DSH_HOME` 与模型适配器；Task 2/3 的 lab 若在本机不可行，则真机项按门控 skip，并在最终报告中标注为**未验证残余**（不得算作已通过）。
- `SessionMessageProjection` 是"派生视图"机制，不是"写时加密"；本设计据此成形（密文/占位落盘 + 派生恢复明文）。
- Windows 沙箱后端（`dsh-sandbox-local`/`dsh-pwsh-sandbox`）可用性未定；Task 7 必须显式处理不可用分支。
