# Sealed Skills 生态文档（M1 – M4）

Sealed Skills 让技能作者以**加密包**的形式分发技能：正文、脚本、资源以密文落盘，只有在
**设备绑定**的 license 有效期内、且该条目被授权时，才在运行时内存中解密，并以「无磁盘路径的
虚拟技能」交给 [DeepSeek Harness](https://deepseek-harness.github.io/deepseek-harness/)（dsh）使用。

一句话概括威胁模型：**用户能使用技能，但磁盘上永远拿不到技能正文的明文。**

> 本文档描述当前仓库已实现的范围：**M1 加密核心与虚拟技能加载** + **M2 授权闭环**
> （授权服务器、设备激活、续期、试用、吊销、离线宽限）+ **M3 防泄漏**（日志掩码、运行时哨兵、
> 沙箱脚本执行、金丝雀 gate）+ **M4 生态与交付**（公开线格式规范 + golden vectors + 面向作者 /
> loader 作者 / 市场的文档 + 发布级 CI）。DPAPI / Keychain / libsecret 等 OS 密钥库后端属于
> Plan 2B，尚未实现，详见文末路线图。

## M1 范围（当前可用的部分）

M1 打通的是**作者本机闭环**：

```
技能目录 (demo/translate)
   │  seal-cli packSkillDir        作者打包（一次加密，全客户共用同一份密文）
   ▼
translate.sealedpack  ──┐
                        │  seal-cli makeTrialLicense   本机 dev 私钥签发试用 license
   .sealed-home/device.json (X25519 设备密钥)  ──┘
                        ▼
              .license（逐条目封装 CK，绑定本机设备公钥）
                        ▼
   dsh-sealed-skills：SealedCore 验签 + 验 license + 解密 meta
                        ▼
        ctx.skills 上的虚拟技能（无 path，明文只在内存）
```

**M1 已实现**

- `.sealedpack` v1 容器：JCS manifest、作者 Ed25519 签名、逐条目 HKDF-SHA256 派生 + AES-256-GCM。
- `license` v1：Ed25519 签名令牌、X25519 ECDH + HKDF + AES-GCM 的逐条目 CK 封装、设备绑定、有效期与宽限期。
- `seal-cli`（`seal` 可执行）：生成作者密钥、打包目录（同时产出 `x.master.json`）、检查包、签发试用 license。
- `dsh-sealed-skills`：文件密钥库、`SealedCore`（授权 + 解密 + 元数据）、`PackRegistry`、dsh `SkillProvider` 适配层与 `plugin.ts`。
- `scripts/m1-smoke.mjs`：端到端冒烟，产出密文包 + license，再从磁盘读回并解出明文正文。

**M1 明确不做**（见路线图）

- 没有授权服务器：试用 license 由作者本机私钥签发，仅用于开发/演示。
- 没有日志掩码：会话日志里若出现解密后的正文，M1 不负责遮蔽（M3）。
- 没有脚本执行运行时：包里的 `scripts/` 条目会被打包，但 M1 不提供执行入口（M3）。
- 没有 OS 密钥库后端：设备私钥以明文存于 `.sealed-home/device.json`（Plan 2B 接入 DPAPI / Keychain / libsecret）。

## M2 范围（授权闭环，已实现）

M2 把「作者本机自签」升级为「授权服务器签发」的完整闭环：

```
用户首次激活 / 试用
   │  license-client：purchase_token / trial
   ▼
POST /v1/activate | /v1/trial      授权服务器：校验凭据 + 席位 + 试用去重
   │  逐条目封装 CK，Ed25519 签发 license（TTL 7 天 / 宽限 3 天）
   ▼
$SEALED_HOME/licenses/<lid>.license.json    客户端验签 + 设备绑定后落盘
   │  剩余 < 2 天：POST /v1/renew（设备证明 DH-MAC，无需 token）
   ▼
SealedCore 解密 → dsh 虚拟技能
   │
   └ 断网：宽限期内继续可用；吊销：下次续期 403 → 删除缓存
```

**M2 已实现**

- `@sealed/license-server`：`node:http` + `node:sqlite`；端点 `/v1/health`、`/v1/trial`、`/v1/activate`、`/v1/renew`、`/v1/revoke`、`/v1/admin/packs`；管理端点 bearer 鉴权；master key 静态加密存储；限流与幂等。
- `license-client`（在 `dsh-sealed-skills` 内）：`activate` / `activateTrial` / `renew` / `importLicense` / `ensureLicense` 状态机；离线宽限、时钟回拨检测、指数退避；**断网不改写任何状态**。
- `plugin.ts`：每个 mount 可给 `licensePath`（离线导入）或 `purchaseToken` / `trial`（在线激活），懒激活 + 逐 mount fail-closed。
- `SealedCore` 改用 license 里的 `pack.author_pub` 验证 pack 签名（作者公钥不再由调用方传入）。
- `scripts/m2-smoke.mjs`：进程内起服务器，跑通 发布 → 激活 → 解密 → 续期 → 吊销 → 续期被拒，并验证试用只解锁 `trial_entries`。

**M2 明确不做**（见路线图）

- OS 密钥库后端未实现：设备私钥仍以文件形式存于 `$SEALED_HOME/device.json`（Plan 2B）。
- 无日志掩码、无脚本执行沙箱（M3）。
- 无实时踢下线：吊销延迟 ≤ license TTL（7 天）。

## M3 范围（防泄漏，已实现）

M3 把「明文只在内存」从 M1 的部分断言升级为**在真实 dsh `0.2.0-rc.2` 上可验证的运行时保证**：

```text
技能正文解密 → 交给 dsh 的虚拟技能（无 path）
   │
   ├─ log-mask：写会话日志时正文→⟦sealed:pack:entry⟧ 占位符；派生视图读取时还原明文
   ├─ invariants：已提交会话事件中出现 sealed 明文 → 运行时哨兵告警（纵深防御）
   └─ tool-runtime：包内 scripts/ 以 defineTool 注册；源码只在内存、经沙箱 confine 后写入子进程 stdin
                       │
                       └─ 会话日志 / spill / 临时目录 / 日志 / 遥测：金丝雀零命中（leak-gate）
```

**M3 已实现**

- `dsh-sealed-skills` 对齐 dsh `0.2.0-rc.2` 接缝（optional peer + `cordis.patch.yml` bundle patch），真实 profile 集成测试（`test/dsh-integration.test.ts`）与真机实验台（`scripts/dsh-lab.mjs`，环境变量 `SEALED_DSH_LAB=1` 门控；未设门控时**响亮 skip**，不伪装通过）。
- `log-mask`（`src/log-mask.ts`）：注册 dsh 消息投影；两条落盘路径（内建 `skill` 工具的 `tool/result`、`/name` 的 `user/message`）落盘为占位符，模型派生视图还原明文；`log-mask` 未就绪时 skill-provider **fail-closed 拒绝服务**（宁可不可用，也不产生明文日志）。
- `invariants`（`src/invariant.ts`）：包级运行时哨兵，已提交会话事件不得含 sealed 明文（**检测而非阻断**；命中即告警，不关停 provider）。
- `tool-runtime`（`src/tool-runtime.ts`）：包内 `scripts/` 条目 → `sealed_script_*` 工具；源码只在内存、经 `ctx.sandbox.confine` 后写子进程 **stdin**（不进 argv、不经临时文件），用后零化；沙箱不可用或非 fully-enforcing 时**拒绝脚本工具但纯提示词技能不受影响**；子进程输出若回显源码 → `output-redacted`。
- `scripts/leak-gate.mjs`：金丝雀扫描（会话日志含 zstd、spill、temp、logs、telemetry）+ spec §8 错误表 32 行 + 解密中途 SIGKILL 崩溃残留；`corepack pnpm leak-gate` 打印 `leak-gate: clean`，CI 见 `.github/workflows/leak-gate.yml`。

**M3 明确不做 / 上游缺口（如实记录）**

- `sealed/redacted` 事件兼容：dsh 0.2.x 的 `session.append` **无法**携带 `ignorable: true`，插件改为在 apply 时把该类型注册进 dsh 导出的 `KNOWN_SESSION_EVENT_TYPES`。**代价**：用过 sealed 技能的会话，若在**未装本插件**的 harness 上打开，读取器会**整条拒绝**（而非优雅回退占位符）。这是 dsh 上游缺口（建议 upstream 提供 append-with-ignorable 或 session 级 redaction API），详见 `docs/sealed-skills/notes/dsh-0.2-seams.md` §9.7。
- OS 密钥库后端仍属 Plan 2B；设备私钥仍明文落盘于 `$SEALED_HOME/device.json`。
- Windows 真实沙箱后端未启用；不可用分支已实现并测试（注入不可用沙箱）。
- 无法在本机跑通需要模型凭据的完整 `dsh-base`+`dsh-headless` 模型回合（`DEEPSEEK_API_KEY`）——标为**未验证**。
## M4 范围（生态与交付，已实现）

M4 把「能用的框架」升级为「可被第三方采纳的生态」：

- **公开线格式**：`spec/pack-format.md`（`.sealedpack` v1）与 `spec/license-format.md`（license v1），
  第三方 loader 只依据规范 + `test-vectors/` 即可实现读取、验签、验 license、解封密钥。
- **golden vectors**：`test-vectors/pack-format.json`、`test-vectors/license-format.json`（TEST-ONLY，
  固定密钥/nonce，可脱离 dsh 复现）；生成脚本 `test-vectors/generate.mjs`。
- **生态文档**：`guide/threat-model.md`（保证边界与 UNVERIFIED 清单）、
  `guide/build-your-own-loader.md`（第三方 runtime 接入）、`guide/trial-and-marketplace.md`
  （试用 / 席位 / 定价 / 分发 / 市场集成）。
- **发布级 CI**：`.github/workflows/` 内的 `test` / `leak-gate` 门禁与 release dry-run（**不发布**）。

**M4 明确不做**：原生 / WASM `DecryptBackend`、OS 密钥库后端、真实市场后端、多语言 SDK 实现
（只提供规范 + 向量 + 指南使其可行）——分别属 M5 / Plan 2B。

## 六个包各自的职责

| 包 | 职责 | 关键导出 |
|---|---|---|
| `@sealed/canonical-json` | JCS（RFC 8785 子集）规范化，供 manifest / license 签名前序列化 | `canonicalJson` |
| `@sealed/pack-format` | `.sealedpack` v1 容器读写、条目密钥派生、AEAD、JCS manifest 签名 | `writeContainer` / `readContainer` / `encodeManifest` / `deriveEntryKey` / `sealEntry` / `openEntry` / `signManifest` / `verifyManifestSignature` |
| `@sealed/license-format` | license v1 令牌编解码、Ed25519 验签、X25519 编解码、CK 封装/解封 | `signLicense` / `verifyLicense` / `wrapEntryKey` / `unwrapEntryKey` / `licenseStatus` |
| `@sealed/seal-cli` | 作者侧工具（`seal` CLI）：keygen、目录打包、包检查、本机签发试用 license | `packSkillDir` / `inspectPack` / `makeTrialLicense` / `generateAuthorKey` / `saveAuthorKey` / `loadAuthorKey` |
| `@sealed/dsh-sealed-skills` | 运行时：密钥库、`SealedCore`、`PackRegistry`、dsh 技能提供者适配与插件入口 | `FileKeystore` / `SealedCore` / `PackRegistry` / `createDshSkillProvider` / `apply` |
| `@sealed/license-server` | 授权服务器：HTTP 端点、SQLite 存储、master 静态加密、签发 / 续期 / 吊销 | `createApp` / `openStore` / `loadServerKeys` / `serverLicensePublicB64` / `wrapMaster` / `unwrapMaster` |

加密只用 Node 内置 `crypto`（X25519 / HKDF-SHA256 / AES-256-GCM / Ed25519），不引入任何第三方密码学库；`license-server` 需要 Node ≥ 22.13（未加 flag 的 `node:sqlite`），其余包 Node ≥ 20。

## 快速开始（可复制）

前置：Node ≥ 20（跑授权服务器需 ≥ 22.13）、`corepack` 可用。本仓库统一使用 `corepack pnpm`，
不要用裸 `pnpm`。

```bash
corepack pnpm install
corepack pnpm -r build
node scripts/m1-smoke.mjs   # M1：本地打包 → 自签试用 license → 读回解密
node scripts/m2-smoke.mjs   # M2：发布 → 激活 → 解密 → 续期 → 吊销 → 续期被拒 + 试用边界
```

`scripts/m2-smoke.mjs` 的**实测输出**（M2 验收基准）：

```text
m2-smoke: publish → activate → decrypt → renew → revoke → renew-denied OK
m2-smoke: trial grants only trial entries OK
disk-leak-check: clean (no plaintext body in .sealed-home/ artifacts)
```

`scripts/m1-smoke.mjs` 的**实测输出**（M1 验收基准）：

```text
skills: [
  {
    name: 'translate',
    description: '把用户输入翻译成英文',
    invocation: { modelInvocable: true, userInvocable: true },
    whenToUse: '当用户要求翻译文本时'
  }
]
content: 把用户输入翻译成自然、地道的英文，保留原有语气与格式。

disk-leak-check: clean (no plaintext body in .sealed-home/ artifacts)
```

脚本做了四件事：

1. 用 `packSkillDir` 把 `demo/translate/` 打成 `.sealedpack`（密文）。
2. 在本机创建 X25519 设备密钥（`.sealed-home/device.json`），并用作者 Ed25519 私钥签发 7 天试用 license。
3. 把**密文包**与 **license** 写到 `.sealed-home/`，再从磁盘读回构造 `SealedCore`。
4. 打印 `list()` 摘要与解密后的正文，并断言三个落盘产物（包 / license / 设备密钥）中不含正文明文。

跑完测试与冒烟后，磁盘上只有密文包与 license，没有技能正文明文（`demo/` 是作者的源码目录，属于例外）。
冒烟脚本的 `disk-leak-check` 会**从 `demo/translate/SKILL.md` 现场解析出正文字节**再比对落盘产物，
因此脚本自身不含第二份明文拷贝；本文档为演示需要引用了该 demo 的正文（示例内容本就公开）。

**明文边界一句话**：运行时的落盘产物（`.sealedpack` / `.license` / `device.json`、会话日志、临时文件）
中不得出现技能正文明文；作者源码目录 `demo/` 与公开文档中引用示例正文不属于泄漏。

```bash
corepack pnpm -r test
```

六个包各自跑 vitest；M3 完成后的基线为 **275 个测试全绿 + 5 个显式门控 skip**（`canonical-json` 5、`pack-format` 36、`license-format` 19、`seal-cli` 32、`license-server` 28、`dsh-sealed-skills` 155）。另加 `corepack pnpm leak-gate` 金丝雀扫描作为发布前置 gate。

## 打包与签发试用 license

完整的作者流程（含预期输出）见 `docs/sealed-skills/guide/author-quickstart.md`。最小示例（用 `seal-cli` 声明的 `seal` bin；也可写成 `node packages/seal-cli/dist/cli.js`）：

```bash
seal keygen -o author.key.json
seal pack ./demo/translate -o translate.sealedpack --pack-id com.example.translate \
  --version 1.0.0 --label 翻译 --key author.key.json --trial meta,skill:translate:body
```

预期输出（`pack` 末行；`pack` 同时写出 `translate.sealedpack.master.json`，仅作者/服务端保留）：

```text
entries: meta, skill:translate:body
```

条目 id 约定：`meta` / `skill:<name>:body` / `skill:<name>:res:<path>` / `script:<name>:path` / `data:<name>`。
`trialEntryIds` 决定试用 license 解锁哪些条目——未列出的条目即使包里有密文也解不开（逐条目封装 CK）。

## 在 dsh 中挂载（demo/cordis.yml）

`demo/cordis.yml` 演示如何把 `plugin.ts` 挂到 dsh 的插件树上：

```yaml
- insert:
    - id: sealed
      name: '/abs/path/to/sealed_skills/packages/dsh-sealed-skills/src/plugin.ts'
```

**注意：该文件不是「开箱即跑」的。** `/abs/path/to/sealed_skills/...` 是占位符，必须替换为本
机器上本仓库的**绝对路径**（例如 Windows 上是 `D:/my_code/sealed_skills/packages/...`，POSIX 上是
`/home/you/sealed_skills/packages/...`），否则 dsh 找不到插件模块。`plugin.ts` 的编译产物为
`packages/dsh-sealed-skills/dist/plugin.js`；如需指向构建产物，请把 `name` 换成该 `dist` 路径。

真实 dsh 集成尚未在本机跑通（无法 clone harness 仓库），`plugin.ts` 的具体接线细节属于「未验证」，
详见 `docs/sealed-skills/notes/dsh-skill-provider.md`。

## 安全模型与威胁模型边界

**威胁模型等级：B 级 —— 有技术能力的付费用户**（会翻中间文件、抓内存、找密钥）。M1 **不防专业逆向工程**，也不做 DRM 级防拷贝。

信任边界：

- **可信**：作者签名私钥、pack `master` key、（M2 起的）授权服务器及其签名私钥。
- **不可信**：用户机器上的一切——文件系统、进程内存、loader 插件代码、会话日志、临时目录、系统时钟。

因此所有授权判定都依赖**密码学验证**，绝不依赖客户端「守规矩」。M1 成立的安全属性：

| 编号 | 属性 | M1 状态 |
|---|---|---|
| S1 | 磁盘产物中不出现技能正文/脚本明文 | ✅ M3：`m1/m2-smoke` 覆盖 `.sealed-home/`；`scripts/leak-gate.mjs` 在**会话日志（含 zstd）、spill、临时目录、日志、遥测、崩溃残留**上做金丝雀扫描并断言零命中（`SEALED_DSH_LAB=1` 时含真实 dsh 会话日志）；脚本源码只经子进程 stdin，不进 argv/临时文件 |
| S2 | 无有效 license 无法解密任何条目 | ✅ `SealedCore` 逐条目解封，缺 grant → `NOT_GRANTED` |
| S3 | license 与设备绑定，换机不可用 | ✅ CK 用设备 X25519 公钥封装 |
| S4 | 试用 license 解不开非试用条目 | ✅ license 只包含被授权条目的封装密钥 |
| S5 | 篡改包内容必被检测 | ✅ manifest Ed25519 签名 + 逐条目 GCM 认证标签 |
| S6 | 包密文与客户无关，license 是唯一按客户产物 | ✅ 同一份 `.sealedpack` 可给所有客户 |
| S7 | 吊销在 TTL 内生效 | ✅ 服务端标记吊销并释放席位；客户端最迟下次续期（≤ 一个 TTL）失效 |
| — | 会话日志 / spill / 遥测不得出现明文 | ✅ M3：`log-mask` 消息投影（密文/占位落盘、明文只在派生视图）+ `invariants` 运行时哨兵 + leak-gate 金丝雀扫描 |

**明确接受的残余风险（M1 与实际部署都适用）**

- 模型请求构造时明文短暂存在于进程内存；有本机调试权限的用户最终可提取。M5 的原生/WASM
  `DecryptBackend` 可缩小窗口，但无法消除。
- 用户可修改开源的 loader 代码，但**无法伪造签名、也无法解出未授权的 CK**；篡改只会让自己不可用。
- 设备私钥目前是明文落盘的 `device.json`：这**达不到**「设备私钥由 OS 密钥库静态保护」的目标，
  仅作为开发/演示退路。生产使用须等 Plan 2B 的 DPAPI / Keychain / libsecret 后端。

**不使用的方法（不要指望）**

- 不防专业逆向；不保护「模型请求已发出」之后的明文（模型提供方会看到内容）。
- 不阻止用户在自己的机器上调试、读取进程内存；不实现实时踢下线（吊销延迟 = license TTL）。

## M1 → M5 路线图（诚实版）

- **M1（已实现）**：`pack-format` + `license-format` + `seal-cli` + `sealed-core` +
  `skill-provider`；本地自签试用 license 跑通「加密加载虚拟技能」。
- **M2（已实现）授权闭环**：`license-server`（activate / renew / trial / revoke / publish）+
  `license-client` 状态机 + 离线宽限期与时钟回拨检测 + 席位与吊销 + S7。
  **Plan 2B（尚未实现）**：DPAPI / Keychain / libsecret 密钥库后端与缺省 fail-closed 退路。
- **M3（已实现）防泄漏**：`log-mask` 消息投影 + `ctx.invariants` 运行时哨兵 + `tool-runtime` 沙箱脚本执行
  + 金丝雀泄漏扫描 CI gate（`pnpm leak-gate`）+ 真实 dsh 0.2.0-rc.2 集成与实验台。
  **上游缺口**：缺插件 harness 打开 sealed 会话会被整条拒绝（见 notes §9.7）；OS 密钥库仍属 Plan 2B。
- **M4（已实现）生态与交付**：`spec/pack-format.md` / `spec/license-format.md` 公开线格式 +
  `test-vectors/` golden vectors + `guide/threat-model.md` / `guide/build-your-own-loader.md` /
  `guide/trial-and-marketplace.md` + 发布级 CI（test / leak-gate / release dry-run，不发布）。
- **M5（尚未实现，可选）加固**：原生 / WASM `DecryptBackend`，让设备私钥与内容密钥不进入 JS 堆。

当前文档交付物：本文件；`guide/` 下 `for-skill-developers` / `author-quickstart` /
`publish-and-license` / `trial-and-marketplace` / `threat-model` / `build-your-own-loader`；
`spec/` 下 `protocol` / `pack-format` / `license-format`；`notes/` 下 `dsh-skill-provider` /
`dsh-0.2-seams`（M3 真机接缝权威，含 §9.7 上游缺口）；以及 `test-vectors/` 的 golden vectors。

## 仓库布局

```text
sealed_skills/
├─ packages/
│  ├─ canonical-json/          JCS 规范化
│  ├─ pack-format/             .sealedpack 容器 / 派生 / AEAD
│  ├─ license-format/          license 令牌 / X25519 / CK 封装
│  ├─ seal-cli/                作者工具（打包 / 检查 / 本机试用 license）
│  ├─ dsh-sealed-skills/       运行时（keystore / core / provider / license-client / plugin / log-mask / invariant / tool-runtime）
│  └─ license-server/          授权服务器（端点 / SQLite / 签发 / 续期 / 吊销）
├─ demo/
│  ├─ translate/SKILL.md       示例技能源码（明文，作者侧固有）
│  ├─ translate/scripts/       示例脚本条目（script:translate:run.mjs）
│  └─ cordis.yml               dsh 挂载示例（路径需替换，见上文）
├─ test-vectors/
│  ├─ generate.mjs             黄金向量生成脚本（TEST-ONLY）
│  ├─ pack-format.json         `.sealedpack` v1 黄金向量
│  └─ license-format.json      license v1 黄金向量
├─ scripts/
│  ├─ m1-smoke.mjs             M1 端到端冒烟
│  ├─ m2-smoke.mjs             M2 授权闭环端到端冒烟
│  ├─ dsh-lab.mjs              真机 dsh 实验台（.dsh-lab/，SEALED_DSH_LAB=1 门控）
│  └─ leak-gate.mjs            M3 金丝雀泄漏扫描 gate（pnpm leak-gate）
├─ .github/workflows/          CI：test / leak-gate 门禁与 release dry-run（不发布）
├─ docs/sealed-skills/         生态文档（README / spec / guide / notes）
└─ docs/superpowers/           设计与计划（含本任务的 plan / spec）
```

## 相关文档

**写给技能作者**

- `docs/sealed-skills/guide/for-skill-developers.md` —— 生态邀请：为什么、怎么赚钱、如何参与。
- `docs/sealed-skills/guide/author-quickstart.md` —— 30 分钟从技能目录到密文包。
- `docs/sealed-skills/guide/publish-and-license.md` —— 部署服务器、登记、签发、续期、席位、吊销。
- `docs/sealed-skills/guide/trial-and-marketplace.md` —— 试用切分、席位、定价、分发与市场集成模式。

**格式规范（第三方实现只需这些）**

- `docs/sealed-skills/spec/pack-format.md` —— `.sealedpack` v1 线格式（容器 / 派生 / AEAD / 错误码）。
- `docs/sealed-skills/spec/license-format.md` —— license v1 令牌（JCS / Ed25519 / X25519 封装 / 状态机）。
- `docs/sealed-skills/spec/protocol.md` —— 授权服务器 HTTP 协议参考（端点 / 错误码 / 设备证明）。
- `test-vectors/pack-format.json`、`test-vectors/license-format.json` —— TEST-ONLY 黄金向量。

**安全与接入**

- `docs/sealed-skills/guide/threat-model.md` —— 威胁模型、保证边界、M3 残余与 UNVERIFIED 清单。
- `docs/sealed-skills/guide/build-your-own-loader.md` —— 第三方 runtime 实现 loader 的算法与检查清单。
- `docs/sealed-skills/notes/dsh-skill-provider.md` —— 真实 dsh `SkillProvider` 契约、适配差异与未验证项。
- `docs/sealed-skills/notes/dsh-0.2-seams.md` —— M3 真机接缝权威（tool/sandbox/invariants/session 契约，逐条 file:line；§9.7 上游缺口）。
- `docs/superpowers/specs/2026-10-04-sealed-skills-design.md` —— 完整设计规范（格式、密码学、里程碑）。
