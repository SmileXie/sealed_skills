# 写给技能开发者：加入 Sealed Skills 生态

欢迎。这份文档是**为你**写的——如果你在为大模型 harness（从 DeepSeek Harness 开始）开发
技能，希望把它做成可收费、可试用、又不想直接把源码交给用户，Sealed Skills 就是为此设计的。

读完这一篇，你应该能回答：这个生态解决什么、我怎样从想法走到一份可售卖的技能、它收多少钱
由谁决定、它到底安全到什么程度、以及我能怎样参与建设。

---

## 1. 为什么会有这个生态

今天给 harness 写技能，基本等于把 `SKILL.md` 和脚本源码直接交给用户。想收费就有两个死结：

1. **源码可见可改**：用户能读到、复制、改掉你的提示词与脚本，你的劳动没有壁垒。
2. **没有授权通道**：没有“按设备授权、可试用、可续费、可吊销”的标准做法，只能整包卖或
   靠自觉。

Sealed Skills 的目标不是做 DRM，而是给技能作者一条**工程上可落地**的商业化路径：

- **源码不出密文包**：技能正文、脚本、资源、私有数据以 AES-256-GCM 密文分发；
- **按设备授权**：license 绑定用户机器的 X25519 公钥，换机即失效；
- **可试用**：试用只解锁你指定的条目（比如描述与示例），正文留给付费；
- **可续费、可吊销**：7 天 TTL + 3 天离线宽限，服务端可随时吊销；
- **复用用户自己的 runtime**：你不需要发布一个 harness，只要发布一个 loader 插件。

一句话：**用户能用，磁盘上却永远拿不到你的明文。**

## 2. 它解决什么，又明确不解决什么

**它做得到的：**

| 能力 | 说明 |
|---|---|
| 密文分发 | 同一份 `.sealedpack` 给所有客户，license 才是按客户定制的产物 |
| 设备绑定 | license 里的条目密钥用设备公钥 ECDH 封装，换机解不开 |
| 试用 | 每设备每包一次，只解锁 `trial_entries` |
| 订阅续期 | 提前 2 天自动续期，7 天 TTL 滚动 |
| 离线宽限 | 断网 3 天内已授权技能照常可用 |
| 吊销 | 管理端吊销，客户端最迟下次刷新/续期失效（≤ 24h） |
| 席位 | 一个订单 N 台设备，吊销释放席位 |

**它明确做不到的（请务必读完）：**

- 不防专业逆向工程。有本机调试权限的用户，最终可以把明文从进程内存里捞出来。
- 不保护“模型请求已发出”之后的明文——模型提供方会看到内容。
- 不做实时踢下线：客户端按 24h 窗口惰性刷新，吊销在最坏情况下要等到下一次刷新才生效（≤ 24h 活跃期）。
- M2 的设备私钥仍以文件形式落盘（`$SEALED_HOME/device.json`）。OS 密钥库后端（DPAPI /
  Keychain / libsecret）属于 Plan 2B，尚未实现。

> **一句话定位**：面向“技术上有能力、但不会为破解付费”的用户（威胁模型 B）。它是
> **商业护栏**，不是军用级防拷贝。把它当 DRM 用，你会失望；把它当“认真做付费技能的标准
> 工具箱”用，它就很好用。

## 3. 五分钟上手

前置：Node ≥ 20、`corepack` 可用，且已 `corepack pnpm install && corepack pnpm -r build`。
仓库统一用 `corepack pnpm`，不要用裸 `pnpm`。

### 3.1 打包你的技能

技能目录就是普通 dsh 技能目录：

```text
my-skill/
├─ SKILL.md          # frontmatter: name / description / whenToUse
├─ scripts/          # 可选，随包加密
├─ resources/        # 可选，随包加密
└─ data/             # 可选，私有数据
```

```bash
node packages/seal-cli/dist/cli.js keygen -o author.key.json
node packages/seal-cli/dist/cli.js pack ./my-skill -o my-skill.sealedpack \
  --pack-id com.you.myskill --version 1.0.0 --label "我的技能" \
  --key author.key.json --trial meta
```

你会得到 `my-skill.sealedpack`（可分发）与 `my-skill.sealedpack.master.json`（**服务端机密**）。

### 3.2 起一个授权服务器并登记

```bash
SEALED_SERVER_ADMIN_TOKEN=dev-token \
SEALED_SERVER_LICENSE_KEY=$(node -e "console.log(require('node:crypto').generateKeyPairSync('ed25519').privateKey.export({format:'jwk'}).d)") \
SEALED_SERVER_PROOF_KEY=$(node -e "console.log(require('node:crypto').generateKeyPairSync('x25519').privateKey.export({format:'jwk'}).d)") \
SEALED_SERVER_MASTER_KEY=$(node -e "console.log(require('node:crypto').randomBytes(32).toString('base64url'))") \
node packages/license-server/dist/bin.js
```

登记 pack、签发购买 token、用户激活的完整步骤见
`docs/sealed-skills/guide/publish-and-license.md`。流程图：

```
seal pack  →  POST /v1/admin/packs  →  计费系统签发 purchase_token  →  交付包 + token
 密文+master        只上传 master              你自己的订单系统              用户激活
```

### 3.3 用户侧只需三样东西

```ts
{
  serverUrl: 'https://license.example.com',
  serverProofPubB64: '<服务器 proof 公钥>',
  trustedLicenseKeysB64: ['<服务器 license 签名公钥>'],
  mounts: [{ packPath: '/abs/my-skill.sealedpack', purchaseToken: '<订单 token>' }],
}
```

作者公钥来自 `author.key.json` 的 `pub`，用于验证包没被掉包；它在 license 里随包签名传递，
无需单独配置。详细配置见 `publish-and-license.md` 第 4 节。

## 4. 商业模式示例

协议层不限定你的定价方式；下面是三种用现有机制就能实现的模式：

| 模式 | 用到的机制 | 例子 |
|---|---|---|
| **订阅制** | 滚动 TTL + 自动续期 | 每月 ¥29，续费失败后 3 天宽限，再停用 |
| **团队席位** | `purchase.seats` + 席位占用/释放 | 一个订单 5 台设备，换机吊销旧设备即释放 |
| **免费试用转付费** | `trial_entries` + 试用去重 | 试用只给描述与 1 个示例条目，正文需购买 |
| **按版本售卖** | 同一 `pack_id` 多个 `version` | 大版本升级作为新产品登记，独立定价 |

要点：

- **试用范围由你定**：`--trial meta` 只放行元数据；`--trial meta,skill:x:body` 直接给正文。
- **一份密文包服务所有客户**：客户差异全在 license，不需要为每个客户重新打包。
- **升级即升版本**：`/v1/admin/packs` 对同一版本幂等；改了内容必须升 `--version`。

## 5. 端到端作者工作流

```
① 写技能            普通 dsh 技能目录（SKILL.md + scripts/resources/data）
② seal keygen       生成作者身份密钥（长期；等于你的署名与签名权）
③ seal pack         目录 → .sealedpack（密文）+ .master.json（服务端机密）
④ 起授权服务器       自托管；登记 master，配置密钥与管理员 token
⑤ 计费签发 token     买家付款 → 你的系统写 purchase_token
⑥ 交付               .sealedpack + purchase_token（绝不交付 master / 作者私钥）
⑦ 运营              续期自动进行；需要时后台吊销、释放席位、看审计
```

每一环的可复制命令都在 `author-quickstart.md`（①③）与 `publish-and-license.md`（④⑤⑥⑦）。

## 6. 授权与试用机制速查

| 参数 | 默认值 | 含义 |
|---|---|---|
| license TTL | 7 天 | 每次签发/续期的有效期 |
| 宽限期 | 3 天 | `exp` 之后仍可离线使用 |
| 续期阈值 | 剩余 2 天 | 客户端提前续期 |
| 时钟偏差容忍 | ±5 分钟 | `renew` 时间戳窗口 |
| nonce 保留 | 10 分钟 | 防重放 |
| 请求体上限 | 1 MiB | 服务端拒绝更大请求 |
| 试用 | 每设备每包一次 | 只解锁 `trial_entries` |

流程要点：

- **激活**：`purchase_token` → 服务端按设备逐条目封装密钥 → 签发 license → 本地缓存。
- **续期**：设备证明（X25519 ECDH + HKDF + HMAC，见协议 §4）换取新 license，无需重发 token。
  插件按 24h 窗口惰性刷新已挂载的 pack，因此长时间运行的进程也会自动续期，不会在 `exp + grace` 后静默丢失技能。
- **离线**：缓存未过期直接解密；断网不会写入新 license，也不会推进时钟锚点。
- **吊销**：服务端标记 + 释放席位；客户端在下一次刷新/续期时拿到 `403 REVOKED` 即删除缓存并停用技能。

## 7. 安全与威胁模型（诚实版）

**信任边界**

- **可信**：作者 Ed25519 私钥、pack master key、授权服务器及其签名私钥。
- **不可信**：用户机器上的一切——文件系统、进程内存、loader 代码、会话日志、临时目录、系统时钟。

因此所有授权判定都依赖**密码学验证**，绝不依赖客户端“守规矩”。

**成立的安全属性**

| 编号 | 属性 | 状态 |
|---|---|---|
| S1 | 磁盘产物不含技能正文/脚本明文 | ✅ 冒烟脚本自动断言（`disk-leak-check`） |
| S2 | 无有效 license 无法解密任何条目 | ✅ 逐条目解封，缺授权 → `NOT_GRANTED` |
| S3 | license 绑定设备，换机不可用 | ✅ 条目密钥用设备公钥封装 |
| S4 | 试用解不开非试用条目 | ✅ license 只含被授权条目的密钥 |
| S5 | 篡改包内容必被检测 | ✅ manifest Ed25519 签名 + 逐条目 GCM 认证 |
| S6 | 密文与客户无关 | ✅ 同一份包给所有客户 |
| S7 | 吊销在 TTL 内生效 | ✅ 依赖授权服务器（M2） |

**明确接受的残余风险**

- 明文在模型请求构造期间短暂存在于进程内存；有本机调试权限的用户最终可提取。
- 用户可修改开源的 loader，但**无法伪造签名、也无法解出未授权的条目密钥**；篡改只会让自己不可用。
- 设备私钥在 M2 是文件形式（`device.json`）；OS 密钥库保护在 Plan 2B。
- 模型提供方会看到送进模型的内容——这不是本生态能解决的问题。

**请这样宣传你的技能**：说“源码不出密文包、按设备授权、可试用可吊销”；不要说“无法破解”
或“DRM 级防拷贝”。

## 8. 在运行时里接入

Sealed Skills 复用用户**已有的** harness，只加一个 loader 插件。核心接口很小：

| 接口 | 位置 | 作用 |
|---|---|---|
| `SealedCore` | `@sealed/dsh-sealed-skills` | 验签、验 license、按条目解密、解析 meta |
| `createSkillProvider(core)` | 同上 | 把 `list()` / `readSkill()` 适配成通用 `SkillProvider` |
| `createDshSkillProvider(core, opts)` | 同上 | DeepSeek Harness 的 `ctx.skills.registerProvider` 适配层 |
| `apply(ctx, config)` | `plugin.ts` | dsh 插件入口：多个 mount 聚合 + 懒激活 + 逐 mount fail-closed |

为**别的** harness 写适配器，只需把该 harness 的技能接口映射到
`Pick<SealedCore, 'list' | 'readSkill'>`。sealed 技能是**虚拟技能**：没有磁盘路径，明文只在内存，
`SkillSummary.path` / `resourceBase` 一律不提供。

## 9. 如何参与生态

这是一个开放格式 + 开源 loader 的生态，欢迎从任何一层加入：

| 参与方向 | 切入点 |
|---|---|
| **写技能** | 用 `seal-cli` 打包，起服务器，按 §4 选商业模式 |
| **适配新 runtime** | 实现 `SkillProvider` 形状的适配器（参考 `provider.ts`） |
| **密钥库后端** | Plan 2B：Windows DPAPI / macOS Keychain / Linux libsecret，实现 `Keystore` 接口 |
| **脚本执行沙箱** | M3：让 `scripts/` 条目在受限沙箱内运行且不落临时文件 |
| **日志掩码** | M3：会话日志写入时把正文替换为占位符 |
| **协议扩展** | 改 `packages/license-format/src/protocol.ts`——它是协议**单一真源** |
| **文档与示例** | 补 `docs/sealed-skills/`，所有示例都当冒烟测试跑 |

开发约定：TypeScript ESM（`NodeNext`，`strict`），密码学只用 Node 内置 `crypto`，
**不引入第三方运行时依赖**；测试全绿 + `node scripts/m1-smoke.mjs` / `m2-smoke.mjs` 通过是合并门槛。

## 10. FAQ

**Q：用户断网了还能用吗？**
能。缓存 license 未过期就直接解密；过期后还有 3 天宽限。断网不会改写任何状态。

**Q：用户换电脑怎么办？**
license 绑定设备公钥，换机解不开。让用户在新机重新激活，并吊销旧设备释放席位。

**Q：试用能限制多少次？**
每台设备每个 pack 一次（服务端按设备+包去重）。范围由你的 `trial_entries` 决定。

**Q：我把 master key 交给服务器安全吗？**
服务器用 `SEALED_SERVER_MASTER_KEY` 把它加密静态存储。它是**你自己的**服务器，属于信任边界内；
关键是别把 master 或作者私钥交付给终端用户。

**Q：包会很大吗？**
典型“提示词 + 脚本 + 少量私有数据”约 1 MB 量级，协议对单条目有 32 MiB 上限。

**Q：能防住专业破解吗？**
不能，也不假装能。见 §2 与 §7。它挡的是“顺手复制/分享”，不是逆向工程师。

**Q：支持哪些 harness？**
目前是 DeepSeek Harness（Cordis 插件体系）。协议与 loader 是解耦的，欢迎贡献别的适配器。

**Q：Offline 预置 license 怎么用？**
mount 里给 `licensePath` 即可（`importLicense` 校验签名与设备绑定后落盘），无需联网。

## 11. 相关文档

- `docs/sealed-skills/README.md` —— 生态总览与仓库布局。
- `docs/sealed-skills/guide/author-quickstart.md` —— 30 分钟：技能目录 → 密文包。
- `docs/sealed-skills/guide/publish-and-license.md` —— 部署服务器、登记、签发、席位、吊销。
- `docs/sealed-skills/spec/protocol.md` —— 授权协议参考。
- `docs/superpowers/specs/2026-10-04-sealed-skills-design.md` —— 完整设计规范（含威胁模型与里程碑）。

有想法、想接新 runtime、或想共建密钥库后端？从上面任一“参与方向”开一个 issue 或 PR，
我们欢迎你加入这个生态。
