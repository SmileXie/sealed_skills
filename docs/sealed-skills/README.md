# Sealed Skills —— M1 生态文档

Sealed Skills 让技能作者以**加密包**的形式分发技能：正文、脚本、资源以密文落盘，只有在
**设备绑定**的 license 有效期内、且该条目被授权时，才在运行时内存中解密，并以「无磁盘路径的
虚拟技能」交给 [DeepSeek Harness](https://deepseek-harness.github.io/deepseek-harness/)（dsh）使用。

一句话概括威胁模型：**用户能使用技能，但磁盘上永远拿不到技能正文的明文。**

> 本文档描述当前仓库的 **M1（加密核心与虚拟技能加载）**。M2 起的能力在文末「路线图」中
> 明确标注为「尚未实现」，请勿按已实现能力使用。

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
- 没有 OS 密钥库后端：设备私钥以明文存于 `.sealed-home/device.json`（M2 接入 DPAPI / Keychain / libsecret）。

## 五个包各自的职责

| 包 | 职责 | 关键导出 |
|---|---|---|
| `@sealed/canonical-json` | JCS（RFC 8785 子集）规范化，供 manifest / license 签名前序列化 | `canonicalJson` |
| `@sealed/pack-format` | `.sealedpack` v1 容器读写、条目密钥派生、AEAD、JCS manifest 签名 | `writeContainer` / `readContainer` / `encodeManifest` / `deriveEntryKey` / `sealEntry` / `openEntry` / `signManifest` / `verifyManifestSignature` |
| `@sealed/license-format` | license v1 令牌编解码、Ed25519 验签、X25519 编解码、CK 封装/解封 | `signLicense` / `verifyLicense` / `wrapEntryKey` / `unwrapEntryKey` / `licenseStatus` |
| `@sealed/seal-cli` | 作者侧工具（`seal` CLI）：keygen、目录打包、包检查、本机签发试用 license | `packSkillDir` / `inspectPack` / `makeTrialLicense` / `generateAuthorKey` / `saveAuthorKey` / `loadAuthorKey` |
| `@sealed/dsh-sealed-skills` | 运行时：密钥库、`SealedCore`、`PackRegistry`、dsh 技能提供者适配与插件入口 | `FileKeystore` / `SealedCore` / `PackRegistry` / `createDshSkillProvider` / `apply` |

加密只用 Node ≥ 20 内置 `crypto`（X25519 / HKDF-SHA256 / AES-256-GCM / Ed25519），M1 不引入任何第三方密码学库。

## 快速开始（可复制）

前置：Node ≥ 20、`corepack` 可用。本仓库统一使用 `corepack pnpm`，不要用裸 `pnpm`。

```bash
corepack pnpm install
corepack pnpm -r build
node scripts/m1-smoke.mjs
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

五个包各自跑 vitest；M1 基线为 **123 个测试全绿**（`canonical-json` 5、`pack-format` 33、`license-format` 13、`seal-cli` 32、`dsh-sealed-skills` 40）。

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
| S1 | 磁盘产物中不出现技能正文/脚本明文 | ⚠️ 部分自动断言：`scripts/m1-smoke.mjs` 从 `demo/translate/SKILL.md` 现场解析出正文，断言它不出现在 `.sealed-home/` 的三个落盘产物（`.sealedpack` / `.license` / `device.json`）中；脚本条目、错误输出、临时文件与会话日志**尚未**纳入自动断言 |
| S2 | 无有效 license 无法解密任何条目 | ✅ `SealedCore` 逐条目解封，缺 grant → `NOT_GRANTED` |
| S3 | license 与设备绑定，换机不可用 | ✅ CK 用设备 X25519 公钥封装 |
| S4 | 试用 license 解不开非试用条目 | ✅ license 只包含被授权条目的封装密钥 |
| S5 | 篡改包内容必被检测 | ✅ manifest Ed25519 签名 + 逐条目 GCM 认证标签 |
| S6 | 包密文与客户无关，license 是唯一按客户产物 | ✅ 同一份 `.sealedpack` 可给所有客户 |
| S7 | 吊销在 TTL 内生效 | ⛔ M2（需要授权服务器） |
| — | 会话日志 / spill / 遥测不得出现明文 | ⛔ M1 无日志掩码，属 M3 |

**明确接受的残余风险（M1 与实际部署都适用）**

- 模型请求构造时明文短暂存在于进程内存；有本机调试权限的用户最终可提取。M5 的原生/WASM
  `DecryptBackend` 可缩小窗口，但无法消除。
- 用户可修改开源的 loader 代码，但**无法伪造签名、也无法解出未授权的 CK**；篡改只会让自己不可用。
- M1 的设备私钥是明文落盘的 `device.json`：这**达不到**「设备私钥由 OS 密钥库静态保护」的目标，
  仅作为开发/演示退路。生产使用须等 M2 的 DPAPI / Keychain / libsecret 后端。

**不使用的方法（不要指望）**

- 不防专业逆向；不保护「模型请求已发出」之后的明文（模型提供方会看到内容）。
- 不阻止用户在自己的机器上调试、读取进程内存；不实现实时踢下线（吊销延迟 = license TTL）。

## M1 → M5 路线图（诚实版）

- **M1（本仓库当前实现）**：`pack-format` + `license-format` + `seal-cli` + `sealed-core` +
  `skill-provider`；本地自签试用 license 跑通「加密加载虚拟技能」。
- **M2（尚未实现）授权闭环**：`license-server`（activate / renew / trial / revoke）+ `license-client`
  状态机 + DPAPI / Keychain / libsecret 密钥库后端 + 离线宽限期与时钟回拨检测 + 席位与吊销 + S7。
- **M3（尚未实现）防泄漏**：`log-mask`（消息投影掩码，退路为自定义 `SessionPersistence` provider）+
  金丝雀泄漏扫描 CI gate + `ctx.invariants` 插件 + `tool-runtime` 脚本执行。
- **M4（尚未实现）生态与交付**：`docs/sealed-skills/` 完整七篇 + golden vectors + 发布流程与 CI。
- **M5（尚未实现，可选）加固**：原生 / WASM `DecryptBackend`，让设备私钥与内容密钥不进入 JS 堆。

M1 的文档交付物只有本文件、`guide/author-quickstart.md` 与 `notes/dsh-skill-provider.md`；
spec 系列、`publish-and-license`、`trial-and-marketplace`、`build-your-own-loader`、`threat-model`
等篇目属于 M4，尚未编写。

## 仓库布局（与 M1 相关部分）

```text
sealed_skills/
├─ packages/
│  ├─ canonical-json/          JCS 规范化
│  ├─ pack-format/             .sealedpack 容器 / 派生 / AEAD
│  ├─ license-format/          license 令牌 / X25519 / CK 封装
│  ├─ seal-cli/                作者工具（打包 / 检查 / 试用 license）
│  └─ dsh-sealed-skills/       运行时（keystore / core / registry / provider / plugin）
├─ demo/
│  ├─ translate/SKILL.md       示例技能源码（明文，作者侧固有）
│  └─ cordis.yml               dsh 挂载示例（路径需替换，见上文）
├─ scripts/m1-smoke.mjs        端到端冒烟
├─ docs/sealed-skills/         M1 生态文档
└─ docs/superpowers/           设计与计划（含本任务的 plan / spec）
```

## 相关文档

- `docs/sealed-skills/guide/author-quickstart.md` —— 30 分钟从技能目录到可安装包 + 试用 license。
- `docs/sealed-skills/notes/dsh-skill-provider.md` —— 真实 dsh `SkillProvider` 契约、我们的适配差异与未验证项。
- `docs/superpowers/specs/2026-10-04-sealed-skills-design.md` —— 完整设计规范（格式、密码学、里程碑）。
