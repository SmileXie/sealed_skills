# Sealed Skills

Sealed Skills 让AI Agent技能(Skills)作者把技能（正文 / 脚本 / 资源 / 数据）以**加密包** `.sealedpack` 的形式
分发。技能内容在磁盘上始终是密文，只有在**设备绑定**的 license 有效期内、**且该条目被授权**时，
才在运行时内存中解密，并以「没有磁盘路径的虚拟技能」交给AI Agent（当前仅兼容
[DeepSeek Harness](https://deepseek-harness.github.io/deepseek-harness/)（dsh））使用。

一句话说明：**用户能使用技能，但磁盘上永远拿不到技能正文的明文。**

---

## 项目介绍

### 它解决什么问题

- 技能作者想按技能收费，同时允许试用；用户必须能**使用**技能，但不能读取源码、不能修改、
  不能拷贝给别人用。
- 作者不希望自己提供 runtime，只想提供插件 + 数据包，复用用户已有的 dsh。

### 目标

1. 作者以加密包 `.sealedpack` 分发技能（一次加密，所有客户共用同一份密文，可放 CDN）。
2. 明文只在运行时内存中存在；磁盘、会话日志、临时文件、错误输出均不得出现明文。
3. 运行时用密码学手段校验 license 的签名、有效期与**设备绑定**，绝不依赖客户端「守规矩」。
4. 以 dsh 插件方式挂载，不 fork 宿主。
5. 支持试用：试用 license 只能解锁试用范围内的条目。

### 非目标

- 不防专业逆向（C 级威胁），不做 DRM 级防拷贝。
- 不保护「模型请求已发出」之后的明文（模型提供方会看到内容）。
- 不阻止用户在自己的机器上调试或读取进程内存。
- 不实现实时踢下线（吊销延迟 ≤ license TTL）。

### 当前状态

已实现 **M1 – M4**：

| 里程碑 | 内容 | 状态 |
|---|---|---|
| **M1** 加密核心 | `.sealedpack` v1 容器、license v1、`seal-cli` 打包工具、虚拟技能加载 | ✅ |
| **M2** 授权闭环 | 授权服务器（激活 / 试用 / 续期 / 吊销 / 席位）、`license-client` 状态机、离线宽限 | ✅ |
| **M3** 防泄漏 | 日志掩码、运行时不变式哨兵、沙箱脚本执行、金丝雀泄漏 gate | ✅ |
| **M4** 生态与交付 | 公开线格式规范、golden vectors、作者 / loader / 市场文档、发布级 CI | ✅ |
| **M5** 加固（可选） | 原生 / WASM `DecryptBackend`，让密钥不进入 JS 堆 | ⏳ 未实现 |

> 尚余：OS 密钥库后端（DPAPI / Keychain / libsecret，Plan 2B）未实现，设备私钥当前以明文存于
> `$SEALED_HOME/device.json`；M5 加固未实现。

---

## 基本原理

### 总体架构与两条密钥链

```
内容层：  pack master ──HKDF-SHA256──▶ CK_i ──AES-256-GCM──▶ entry 密文
                                          ▲
                                          │ 服务端用 设备公钥 封装
                                          │ (X25519 ECDH + HKDF + AES-GCM key wrap)
授权层：  服务端 Ed25519 私钥 ──签名──▶ license（含被封装的多把 CK_i）
```

- **内容层**：每个 pack 版本一把 32 字节的 **pack master key**（pack 主密钥；代码与 CLI 中简称 `master`），仅作者 / 服务端持有。条目 `i` 的内容密钥
  `CK_i = HKDF-SHA256(master, salt = pack_id || version, info = "entry:" || entry_id)`。
  条目用 `CK_i` 做 AES-256-GCM 加密。**包只加密一次，所有客户共用同一份密文。**
- **授权层**：每台设备用 X25519 设备密钥对；服务端用设备公钥把该设备被授权的 `CK_i` 逐条目
  封装进 license，再用 Ed25519 对 license 签名。**license 是每个客户唯一的产物。**

因此：没有有效 license 就解不开任何条目；license 与设备绑定，换机不可用；试用 license 只封装
`trial_entries` 的 `CK_i`，天然解不开非试用条目。

### `.sealedpack` v1 容器

单个二进制容器，布局为：magic `SLDSK1` + 版本 + **JCS 规范化 manifest** + 作者 Ed25519 签名 +
entry table + chunk area（每条目 12 字节 nonce + AES-GCM 密文）。明文 manifest 只含**不透明**的
`id / 类型 / 密文长度 / 试用标记`，**不含**技能名、描述或正文哈希，避免泄露与内容确认攻击。

### license v1 令牌

两字段 JSON 信封 `{ payload, sig }`：

- `payload` = base64url(JCS(payload 对象))，`sig` = Ed25519 签名。
- payload 含 `pack`（含作者公钥 `author_pub`）、设备公钥 `dev`、`iat / exp / grace_until`、
  `caps`，以及**逐条目封装的 `keys`**（真正的授权载体）。

### 虚拟技能与防泄漏

- **虚拟技能**：`SkillProvider` 在内存中提供没有 `path` 的 skill（dsh `SkillDefinition.path` 缺省），
  正文只在内存，`list()` 只解密 `meta` 条目。
- **日志掩码**：会话日志按消息投影遮蔽 sealed 明文，满足 dsh「模型可见即已记录」的不变式。
- **运行时哨兵**：通过 `ctx.invariants` 注册「已提交会话事件中不得出现 sealed 明文」的包级检查。
- **沙箱脚本**：包内脚本以只读沙箱、限时方式执行，磁盘上不落源码。
- **金丝雀 gate**：CI 用唯一金丝雀串跑全套路径并扫描日志 / spill / 临时目录，零命中才允许发布。

### 在线激活与离线宽限

```
首次激活 / 试用 ──▶ POST /v1/activate | /v1/trial
                             │  逐条目封装 CK，Ed25519 签发 license（TTL 7 天 / 宽限 3 天）
                        ▼
              $SEALED_HOME/licenses/<lid>.license.json（验签 + 设备绑定后落盘）
                             │  剩余 < 2 天：POST /v1/renew（设备证明 DH-MAC，无需 token）
                        ▼
              SealedCore 解密 ──▶ dsh 虚拟技能
                        └ 断网：宽限期内继续可用；吊销：下次续期 403 ──▶ 删除缓存
```

---

## Quick Start

### 角色一：技能开发者

> 目标：把技能目录打包成加密包 `.sealedpack`，架设授权服务器，并为买家签发可激活的授权。

#### 1. 依赖与安装

| 依赖 | 版本 | 说明 |
|---|---|---|
| Node.js | ≥ 20（CI 用 24） | 加密只用内置 `node:crypto`，无需第三方密码学库 |
| pnpm | `pnpm@12.9.1`（根 `packageManager` 固定） | 经 `corepack` 启用，命令统一写 `corepack pnpm` |

```bash
corepack enable
corepack pnpm install
corepack pnpm -r build     # 产出各包 dist/，seal CLI 与 license server 都在其中
```

下文的 `seal` 统一指 `node packages/seal-cli/dist/cli.js`（该包也声明 `bin.seal`，安装后可直接调用 `seal`）。

#### 2. 生成作者密钥

```bash
node packages/seal-cli/dist/cli.js keygen -o author.key.json
```

> `author.key.json` 等价于作者身份：**不要提交进仓库、不要随包分发**。

#### 3. 打包技能目录（一次加密，全客户共用）

```bash
node packages/seal-cli/dist/cli.js pack ./demo/translate -o translate.sealedpack \
  --pack-id com.example.translate --version 1.0.0 --label 翻译 \
  --key author.key.json --trial meta,skill:translate:body
```

打包规则：`SKILL.md` frontmatter 必须有 `name` / `description`；正文 → `skill:<name>:body`，
`resources/` → `skill:<name>:res:<相对路径>`，`scripts/` → `script:<name>:<相对路径>`，
`data/` → `data:<name>`，另有自动生成的加密元数据条目 `meta`。`--trial` 列出试用 license 可解锁的条目 id。

产出：

- `translate.sealedpack` —— 密文包，可给所有客户（可放 CDN）。
- `translate.sealedpack.master.json` —— pack master key，**只留在作者 / 服务端**，绝不随包分发。

#### 4. 检查包（不解密）

```bash
node packages/seal-cli/dist/cli.js inspect translate.sealedpack --author-pub <author.key.json 的 pub>
```

#### 5. 本机试用 license（可选，自测用）

```bash
node packages/seal-cli/dist/cli.js trial translate.sealedpack \
  --master translate.sealedpack.master.json --device-pub <本机设备公钥> \
  --days 7 --key author.key.json -o translate.license
```

本机设备公钥从客户端密钥库读取（`.sealed-home/device.json`）。此 license 由作者私钥签发，仅用于
开发与演示；生产签发走授权服务器。

#### 6. 架设授权服务器并登记 pack

```bash
SEALED_SERVER_ADMIN_TOKEN=dev-token \
SEALED_SERVER_LICENSE_KEY=... SEALED_SERVER_PROOF_KEY=... SEALED_SERVER_MASTER_KEY=... \
node packages/license-server/dist/bin.js
```

端点：`/v1/health`、`/v1/trial`、`/v1/activate`、`/v1/renew`、`/v1/revoke`、`/v1/admin/packs`
（管理端点需 bearer 鉴权）。把 pack 的 **master key 登记到服务器**（`POST /v1/admin/packs`，
**绝不上传 `.sealedpack` 或明文**）；买家付款后由计费系统写入一张 `purchase_token`
（`Store.putPurchase({ token, sub, packId, version, plan, seats })`，`seats` 控制设备数）。

#### 7. 交付

- **交付**：`.sealedpack` + `purchase_token`（或预签发 `*.license`）。
- **绝不交付**：`*.master.json`、`author.key.json`。
- 包只加密一次、全客户共用同一份密文；**license 是唯一按客户产物**。

完整部署 / 续期 / 席位 / 吊销见 `docs/sealed-skills/guide/publish-and-license.md`，HTTP 协议见
`docs/sealed-skills/spec/protocol.md`。

### 角色二：技能使用者

> 目标：在自己的 dsh 里安装本插件，加载并使用加密后的技能。

#### 1. 前置

- 一个可用的 dsh（Cordis）环境，`@deepseek-ai/dsh-*` 版本对齐 `0.2.0-rc.2`。
- 从作者处取得：`xxx.sealedpack`，外加 `purchase_token`（在线激活）、预签发的 `xxx.license`
  （离线导入），或作者的试用入口（`trial: true`）。

#### 2. 安装插件（dsh bundle）

本项目交付一枚 dsh bundle：`@sealed/dsh-sealed-skills` 声明 `dsh.bundle.patch -> ./cordis.patch.yml`，
向插件树插入一行：

```yaml
- insert:
    - id: sealed-skills
      name: '@sealed/dsh-sealed-skills'
      config: {}
```

**方式 A：用仓库自带实验台（最快验证）**

```bash
corepack pnpm install && corepack pnpm -r build
node scripts/dsh-lab.mjs --ensure        # 装 dsh 到 .dsh-lab/ 并生成挂载本插件的 profile
node scripts/dsh-lab.mjs --dump-config   # 查看合成后的 profile 树
```

生成的 profile 位于 `.dsh-lab/home/profiles/m3-lab/`，其 `dsh.profile.bundles` 含
`@deepseek-ai/dsh-base`、`@deepseek-ai/dsh-headless` 与 `@sealed/dsh-sealed-skills`。可用
`SEALED_DSH_LAB_MOUNTS_FILE`（`SealedPackMount[]` 的 JSON 文件）与
`SEALED_DSH_LAB_PLUGIN_CONFIG_FILE`（插件配置 JSON 对象）注入 pack 与授权设置，无需手改生成物。

**方式 B：接进你自己的 dsh profile**

1. 让 profile 能解析到本包。注意：**本包尚未发布到任何 registry**——`@sealed` 只是仓库内的
   workspace scope，`release-dry-run.yml` 只做 `npm pack --dry-run`、从不发布，仓库内也没有 `.npmrc`
   或 `publishConfig`；因此 `corepack pnpm add @sealed/dsh-sealed-skills` 在默认 npm 源上会 404。
   请改用本地解析（二选一）：
   - 在 profile 目录执行 `corepack pnpm add link:<仓库绝对路径>/packages/dsh-sealed-skills`；
   - 或按 `scripts/dsh-lab.mjs` 的做法，把该包 junction 到 profile 的
     `node_modules/@sealed/dsh-sealed-skills`。
   （只有把它发布到自建私有 registry 或自有 npm scope 后，`corepack pnpm add
   @sealed/dsh-sealed-skills` 才会命中。）
2. 在 profile 的 `package.json` 里把它加进 bundle 列表：

   ```json
   {
     "dsh": {
       "profile": {
         "bundles": [
           "@deepseek-ai/dsh-base",
           "@deepseek-ai/dsh-headless",
           "@sealed/dsh-sealed-skills"
         ]
       }
     }
   }
   ```

3. 在 profile 自己的 `cordis.patch.yml` 里按 `id: sealed-skills` 覆盖配置（bundle 层的 patch 先应用，
   profile 的 patch 后应用）：

   ```yaml
   - id: sealed-skills
     config:
       keystoreDir: '/abs/path/.sealed-home'
       mounts:
         - packPath: '/abs/path/translate.sealedpack'
           purchaseToken: 'pt_...'
       serverUrl: 'https://license.example.com'
       serverProofPubB64: '<base64url X25519 公钥>'
       trustedLicenseKeysB64: ['<base64url Ed25519 授权服务器公钥>']
   ```

   bundle 层自身不带 pack 配置，配置全部由 profile 层注入——这正是 dsh 内置 bundle 的通用分层做法。

#### 3. 加载与授权

每个 mount 用三选一提供授权来源：

| 来源 | 字段 | 适用 |
|---|---|---|
| 离线导入 | `licensePath` | 作者 / 服务器预签发的 `*.license` |
| 在线激活 | `purchaseToken` | 首次联网激活，之后缓存 + 离线宽限 |
| 试用 | `trial: true` | 向服务器申请试用 license（只解锁 `trial_entries`） |

- 激活状态落盘于 `$SEALED_HOME/licenses/<lid>.license.json`；剩余 < 2 天时自动续期（无需 token）。
- 配置回退：`serverUrl` ← `SEALED_SERVER_URL`、`serverProofPubB64` ← `SEALED_SERVER_PROOF_PUB`、
  `keystoreDir` ← `SEALED_HOME`（缺省 `<cwd>/.sealed-home`）。
- 作者公钥随 license 传递（`pack.author_pub`），无需单独配置。

#### 4. 使用

挂载后，sealed 技能以**虚拟技能**形式出现在 `ctx.skills` 上——**没有磁盘 `path`，明文只在内存**：
`ctx.skills.list()` 只解密 `meta`；`ctx.skills.get('translate')` 才在内存解密正文；包内脚本以只读
沙箱、限时执行。对模型而言与普通技能无异。

#### 5. 常见错误

- `NOT_GRANTED`：license 未包含该条目（试用只解锁 `trial_entries`）。
- `LICENSE_INVALID`：license 未绑定本机设备（换机不可用）。
- `LICENSE_EXPIRED`：已过 `exp` 且超过 `grace_until` 宽限期。
- `DECRYPT_FAILED`：密文被篡改或条目身份（pack id / version / entry id）不匹配。

### 角色三：贡献者 / 开发者

> 目标：配置本仓库开发环境，构建、测试并参与贡献。

#### 1. 环境要求与依赖

| 依赖 | 版本 | 说明 |
|---|---|---|
| Node.js | ≥ 20（CI 用 24） | 只用内置 `node:crypto` |
| pnpm | `pnpm@12.9.1`（根 `packageManager` 固定） | 经 `corepack` 启用 |
| TypeScript / Vitest / @types/node | 根 `devDependencies` | 仅构建与测试 |

- 运行时依赖只有 workspace 内的 `@sealed/*`，由 pnpm workspace 软链，**不下载任何第三方运行时依赖**。
- `dsh-sealed-skills` 的 dsh 依赖全部是 **optional peerDependencies**（`0.2.0-rc.2`）：**构建与测试
  不需要 dsh**，只有真实 dsh 集成才需要。
- `license-server` 使用 Node 内置 `node:http` + `node:sqlite`，无外部依赖。

```bash
corepack enable
corepack pnpm install      # CI 用 --frozen-lockfile
corepack pnpm -r build
```

#### 2. 测试与门禁

```bash
corepack pnpm -r test      # 六个包全部单测
node scripts/m1-smoke.mjs  # M1：打包 + 试用 license + 解密
corepack pnpm smoke:m2     # M2：发布 → 激活 → 解密 → 续期 → 吊销
corepack pnpm leak-gate    # M3：金丝雀泄漏扫描 gate（发布必过）
```

#### 3. 真实 dsh 实验台（可选）

真实 harness 集成需要 `@deepseek-ai/dsh@0.2.0-rc.2`（约 462 MB）。脚本会把它装进 git-ignored 的
`.dsh-lab/`，**不进入仓库依赖图**，需要网络；缺省状态下依赖它的测试会 loud-skip：

```bash
node scripts/dsh-lab.mjs --ensure
node scripts/dsh-lab.mjs --dump-config
node scripts/dsh-lab.mjs --headless '翻译 hello'   # 需模型凭证
```

#### 4. 仓库布局

```text
sealed_skills/
├─ packages/
│  ├─ canonical-json/          JCS 规范化
│  ├─ pack-format/             .sealedpack 容器 / HKDF 派生 / AEAD
│  ├─ license-format/          license 令牌 / X25519 / CK 封装
│  ├─ seal-cli/                作者工具（keygen / pack / inspect / trial）
│  ├─ dsh-sealed-skills/       运行时（keystore / core / provider / license-client / plugin / log-mask / invariant / tool-runtime）
│  └─ license-server/          授权服务器（端点 / SQLite / 签发 / 续期 / 吊销）
├─ demo/
│  ├─ translate/SKILL.md       示例技能源码（明文，作者侧固有）
│  └─ cordis.yml               dsh 挂载示例（路径需替换）
├─ test-vectors/               golden vectors（TEST-ONLY）
├─ scripts/                    m1-smoke / m2-smoke / dsh-lab / leak-gate
├─ docs/sealed-skills/         生态文档（README / spec / guide / notes）
└─ docs/superpowers/           设计与计划
```

#### 5. 文档索引

**写给技能开发者**

- `docs/sealed-skills/guide/for-skill-developers.md` —— 生态邀请：为什么、怎么赚钱、如何参与。
- `docs/sealed-skills/guide/author-quickstart.md` —— 30 分钟从技能目录到密文包。
- `docs/sealed-skills/guide/publish-and-license.md` —— 部署服务器、登记、签发、续期、席位、吊销。
- `docs/sealed-skills/guide/trial-and-marketplace.md` —— 试用切分、席位、定价与市场集成模式。

**写给技能使用者 / loader 作者**

- `docs/sealed-skills/guide/build-your-own-loader.md` —— 第三方 runtime loader 实现指南。

**格式规范（第三方实现只需这些）**

- `docs/sealed-skills/spec/pack-format.md` —— `.sealedpack` v1 线格式。
- `docs/sealed-skills/spec/license-format.md` —— license v1 令牌。
- `docs/sealed-skills/spec/protocol.md` —— 授权服务器 HTTP 协议参考。
- `test-vectors/*.json` —— golden vectors（TEST-ONLY）。

**安全与设计**

- `docs/sealed-skills/guide/threat-model.md` —— 威胁模型、保证边界、残余风险。
- `docs/sealed-skills/README.md` —— 生态总览（M1 – M4 全量）。
- `docs/superpowers/specs/2026-10-04-sealed-skills-design.md` —— 完整设计规范。

#### 6. CI

`.github/workflows/` 三个工作流：`test.yml`（build + `pnpm -r test` + M1/M2 smoke）、`leak-gate.yml`
（金丝雀泄漏门禁）、`release-dry-run.yml`（`npm pack --dry-run`，**从不发布**）。

---

## 安全属性（必须成立）

| 编号 | 属性 |
|---|---|
| S1 | 磁盘上不出现技能正文 / 脚本源码明文（含日志、spill、临时文件、错误输出） |
| S2 | 无有效 license 无法解密任何条目 |
| S3 | license 与设备绑定，换机不可用 |
| S4 | 试用 license 解不开非试用条目 |
| S5 | 篡改包内容必被检测 |
| S6 | 包密文与客户无关，license 是唯一按客户产物 |
| S7 | 吊销在 TTL 内生效 |

残余风险与保证边界详见 `docs/sealed-skills/guide/threat-model.md`。

---

## 路线图

- **Plan 2B（未实现）**：OS 密钥库后端（DPAPI / Keychain / libsecret）与缺省 fail-closed 退路。
- **M5（可选）**：原生 / WASM `DecryptBackend`，让设备私钥与内容密钥不进入 JS 堆。
- **上游缺口**：缺插件 harness 打开 sealed 会话会被整条拒绝，详见
  `docs/sealed-skills/notes/dsh-0.2-seams.md` §9.7。

