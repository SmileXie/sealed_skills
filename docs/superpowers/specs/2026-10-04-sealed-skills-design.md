# Sealed Skills 设计规范

- 状态：待审阅（brainstorming 第 6 步产出）
- 日期：2026-10-04
- 目标宿主：DeepSeek Harness（dsh）插件体系
- 威胁模型：B 级 —— 有技术能力的付费用户（会翻中间文件、抓内存、找密钥）
- 许可模式：在线激活 + 离线宽限期（A→B 修订版），自建轻量授权服务器

---

## 1. 背景与目标

### 1.1 问题

Skill 作者希望按技能收费，同时允许试用。用户必须能够**使用**技能，但**不能读取源码、不能修改、不能拷贝给别人使用**。作者不希望提供 runtime，只提供插件与数据包。

### 1.2 目标

1. 作者以加密形式分发技能包（`.sealedpack`）。
2. 技能正文/脚本/数据以密文形态进入 runtime，明文只在内存中存在。
3. 运行时校验 license 的有效性、有效期与设备绑定。
4. 复用用户已有的 dsh 运行时，仅以插件方式挂载，不 fork 宿主。
5. 支持试用：试用 license 能且仅能解锁试用范围内的内容。
6. 仓库交付一份面向 skill 开发者的详尽生态文档。

### 1.3 非目标

- 不防专业逆向工程（C 级威胁）。不做 DRM 级防拷贝。
- 不保护「模型请求已发出」之后的明文（模型提供方会看到内容）。
- 不阻止用户在自己的机器上调试、读取进程内存。
- 不实现实时踢下线（吊销延迟 = license TTL）。

---

## 2. 威胁模型与安全目标

### 2.1 信任边界

- **可信**：作者签名私钥、授权服务器及其签名私钥、pack master key。
- **不可信**：用户机器上的一切——文件系统、进程内存、loader 插件代码、会话日志、临时目录、系统时钟。
- 结论：所有授权判定必须依赖**密码学验证**，绝不能依赖客户端「守规矩」。

### 2.2 安全属性（必须成立）

| 编号 | 属性 | 验证方式 |
|---|---|---|
| S1 | 磁盘上不出现技能正文/脚本源码明文（含会话日志、spill、临时文件、错误输出、遥测） | 金丝雀泄漏扫描（§10.3） |
| S2 | 无有效 license 无法解密任何条目 | 授权测试（§10.4） |
| S3 | license 与设备绑定，换机不可用 | 对抗测试（§10.4） |
| S4 | 试用 license 解不开非试用条目 | 授权测试 |
| S5 | 篡改包内容必被检测 | 篡改测试（§10.1） |
| S6 | 包密文与客户无关，license 是唯一按客户产物 | 构建期检查 |
| S7 | 吊销在 TTL 内生效 | 服务端测试 |

### 2.3 残余风险（明确接受）

- 模型请求构造时明文短暂存在于进程内存；有本机调试权限的用户最终可提取。
- 授权服务器被攻破会导致该 pack 的 master key 泄漏。缓解：master key 加密静态存储、管理通道 TLS + mTLS、审计日志。
- 用户可修改开源 loader 代码，但无法伪造签名或解出未授权的 CK——修改只会让自己不可用。
- dsh 会话存储实现变更可能破坏日志掩码；§10.3 的泄漏 gate 会失败（fail-closed）。

---

## 3. 术语

- **pack / `.sealedpack`**：加密技能包容器。
- **entry**：包内独立加密的最小单元（技能正文、脚本、资源文件、数据块、meta）。
- **CK_i**：条目 i 的内容密钥，`CK_i = HKDF-SHA256(master, salt = pack_id||version, info = "entry:"||entry_id)`。
- **master**：每个 pack 版本一把的 pack master key，仅服务端持有。
- **license**：Ed25519 签名的授权令牌，含设备绑定与逐条目封装的 CK。
- **设备密钥**：用户机上的 X25519 密钥对，私钥存于 OS 密钥库，永不导出。
- **虚拟技能**：由 `SkillProvider` 在内存中提供、没有磁盘路径的 skill（dsh `SkillDefinition.path` 缺省）。
- **loader**：开源 dsh 插件 bundle `dsh-sealed-skills`。
- **TTL**：license 有效期，默认 7 天。
- **grace**：离线宽限期，默认 3 天。

---

## 4. 总体架构

### 4.1 角色

- **作者**：编写技能；用 `seal-cli` 打包；持有作者签名私钥（可选，用于包签名）。
- **授权服务器**：签发/续期/吊销 license、管席位、发试用；持有 Ed25519 license 签名私钥与 pack master key。
- **用户**：在自己的 dsh 里安装 loader、放置包、激活授权。
- **运行时**：用户自己的 dsh（Cordis 插件树）。

### 4.2 两条密钥链

```
内容层：  master ──HKDF──▶ CK_i ──AES-256-GCM──▶ entry 密文
                                   ▲
                                   │ 服务端用 设备公钥 封装（X25519 ECDH + HKDF + AES-GCM key wrap）
授权层：  服务端 Ed25519 私钥 ──签名──▶ license（含被封装的多把 CK_i）
```

- 包只加密一次，所有客户共用同一份密文 → 可放 CDN / npm / 开发者市场。
- 每个客户唯一的产物是 license。
- **逐条目封装**：license 只封装被授权条目的 CK_i。试用与按技能售卖天然安全，不依赖客户端规则。

### 4.3 客户端拓扑

```
用户自己的 dsh  (--profile sealed)
├─ dsh-sealed-skills            ← 开源、可审计
│  ├─ pack-registry       扫描 $DSH_HOME/sealed/*.sealedpack，读明文 manifest 做发现
│  ├─ sealed-core         容器解析、条目解密、签名校验、缓冲零化（DecryptBackend 可替换）
│  ├─ license-client      设备密钥(OS 密钥库)、激活/续期、验签、有效期/宽限状态机、时钟回拨检测
│  ├─ skill-provider      ctx.skills.registerProvider() → 无 path 的虚拟技能
│  ├─ tool-runtime        ctx.ptcRuntime / 受限子进程执行包内脚本，源码只在内存
│  └─ log-mask            消息投影：日志写密文引用、读时还原
├─ $DSH_HOME/sealed/*.sealedpack    ← 磁盘上只有密文
└─ OS 密钥库 (DPAPI / Keychain / libsecret)  ← 设备私钥
```

### 4.4 服务端拓扑

```
license-server
├─ POST /v1/activate   设备公钥 + 购买凭据 → license
├─ POST /v1/renew      设备签名挑战        → 续期（吊销/席位在此拦截）
├─ POST /v1/trial      → 试用 license
├─ POST /v1/revoke     管理员             → 吊销 + 释放席位
├─ POST /v1/admin/packs 管理员            → 登记 pack master key
├─ GET  /v1/packs      （可选）市场目录
└─ 存储：licenses / devices / seats / revocations / packs
   密钥：Ed25519 签名私钥；master key 加密静态存储
```

### 4.5 架构不变量

1. 磁盘上永不出现明文技能正文或脚本源码——含会话日志、spill、临时文件、错误输出、遥测。
2. 包密文与客户无关；license 是唯一的按客户产物，也是唯一的吊销抓手。
3. 设备私钥由 OS 密钥库保护**静态存储**，明文私钥与 CK 只在内存中短暂存在、用后零化（M5 的原生/WASM 后端可进一步做到私钥不出模块）。
4. 解密后端可替换（JS → 原生/WASM），上层接口不变。

---

## 5. 格式规范

### 5.1 `.sealedpack` 容器

```
[ magic "SLDSK1" (6B) ]
[ u8  format_version = 1 ]
[ u8  flags (bit0: 已压缩) ]
[ u32 manifest_len ][ manifest (UTF-8, JSON Canonical / RFC 8785) ]
[ u32 sig_len ][ Ed25519 签名(manifest 字节) ]
[ u32 entry_count ]
[ entry table: { entry_id, u64 offset, u32 ct_len } × entry_count ]
[ chunk area: { u12 nonce, ct } × entry_count ]
```

明文 manifest：

```json
{
  "pack_id": "com.example.translate",
  "version": "1.4.0",
  "label": "翻译助手",              // 非敏感公开名，用于在未授权时显示
  "entry_count": 12,
  "entries": [
    { "id": "meta",                    "type": "meta",  "size": 2048,  "trial": true },
    { "id": "skill:translate:body",    "type": "text",  "size": 9021,  "trial": true },
    { "id": "script:translate:run.py", "type": "script","size": 15230, "trial": false },
    { "id": "data:glossary.json",      "type": "data",  "size": 700112,"trial": false }
  ]
}
```

- **manifest 不包含任何明文的技能名/描述/正文哈希**。只含不透明 id、类型、密文长度、试用标记。
  - 不存明文 sha256：避免已知明文确认攻击；完整性由 AES-GCM 认证标签保证。
- manifest 由作者 Ed25519 私钥签名；客户端用 license 中的 `pack.author_pub` 验签（离线可验），AEAD 标签作为第二道完整性保障。
- **meta 条目（加密）**才是真正的技能元数据：

```json
{
  "skills": [
    { "name": "translate", "description": "…", "whenToUse": "…",
      "invocation": { "modelInvocable": true, "userInvocable": true },
      "entries": ["skill:translate:body", "script:translate:run.py"] }
  ],
  "resources": { "skill:translate:res:template.md": "templates/t.md" }
}
```

条目 id 约定：`meta` / `skill:<name>:body` / `skill:<name>:res:<path>` / `script:<name>:<path>` / `data:<name>`。

加解密：

- `CK_i = HKDF-SHA256(master, salt = pack_id || 0x00 || version, info = "entry:" || entry_id, len = 32)`
- `ct_i = AES-256-GCM(key = CK_i, nonce = 随机 12B, aad = pack_id || 0x00 || version || 0x00 || entry_id, plaintext)`
- AAD 绑定条目身份，防止密文块互换。
- 压缩（可选）在加密前施加，按条目记录于 flags；v1 支持 `zstd` 与不压缩。
- v1 每个条目整体在内存中解密（规模约 1MB，单段足够）；预留多段扩展位。

条目 id 与 pack 版本一经发布不可复用（防止旧 license 解新内容）。

### 5.2 license 令牌

外层：

```json
{ "payload": "<b64url(JCS(payload))>", "sig": "<b64url(Ed25519(作者/服务端私钥, payload 字节))>" }
```

payload：

```json
{
  "v": 1,
  "lid": "lic_01H...",
  "sub": "cust_42",
  "pack": {
    "id": "com.example.translate",
    "version": "1.4.0",
    "author_pub": "<b64url(作者 Ed25519 公钥)>"
  },
  "dev": "<b64url(设备 X25519 公钥)>",
  "iat": 1760000000,
  "exp": 1760604800,
  "grace_until": 1760864000,
  "caps": ["trial"],
  "groups": ["translate-core"],
  "keys": [
    { "eid": "meta",
      "eph": "<b64url(服务端临时 X25519 公钥)>",
      "n": "<b64url(12B nonce)>",
      "c": "<b64url(wrapped CK)>" }
  ],
  "seats": { "plan": "pro", "limit": 2 }
}
```

- 签名算法：Ed25519，载荷规范化 JCS。
- 密钥封装：服务端为每个条目生成临时 X25519 密钥对，`ss = ECDH(eph_priv, dev_pub)`，`kek = HKDF-SHA256(ss, salt = lid, info = "wrap:" || eid, 32)`，`wrapped = AES-256-GCM(kek, n, aad = lid || 0x00 || eid, CK_i)`。
  - 临时密钥对一次性使用，删除私钥。
- license 文件落盘无害：其中的 CK 已被设备公钥封装，无设备私钥（在 OS 密钥库中）不可解封。
- 客户端内置服务端公钥（可轮换：payload 增加 `kid`）。

### 5.3 版本与兼容

- 三套版本号：pack `format_version`（u8）、license `v`、服务端协议 `/v1`。
- 客户端规则：遇到更高的 pack 版本 → 拒绝并提示升级 loader；遇到更高 license `v` → 拒绝。
- 未知字段必须忽略（向前兼容）；未知条目 type → 忽略该条目，不整体失败。

---

## 6. 组件

### 6.1 契约层（开放格式，双方共用）

- `@sealed/pack-format`：容器编解码、条目分段、AEAD 封装、manifest 签名。依赖：仅 Node 内置 `crypto`。公开规范。
- `@sealed/license-format`：令牌编解码、JCS 规范化、Ed25519 验签、CK 解封。公开规范。

两者均发布**golden vectors**（§10.2），供第三方实现互操作。

### 6.2 作者侧

- `@sealed/seal-cli`
  - `seal keygen`：生成作者签名密钥对。
  - `seal pack <dir> -o x.sealedpack`：解析技能目录 → 条目 → 生成 master → 派生 CK_i → 加密 → 写 manifest → 签名 → 输出包；同时输出 `x.master.json`（供上传服务端）。
  - `seal inspect <pack>`：不解密，校验容器完整性与 manifest 签名。
  - `seal publish <pack>`：上传包元数据与 master key 到服务端（管理通道）。
  - `seal trial <pack> --days N`：开发期本地签发试用 license（不联网，仅用于自测）。

### 6.3 客户端 bundle（开源）

| 模块 | 职责 | 依赖 | 关键接口 |
|---|---|---|---|
| `pack-registry` | 扫描 `$DSH_HOME/sealed/*.sealedpack`；读明文 manifest 做发现；监听文件变化 | `pack-format` | 提供候选 pack 列表 |
| `sealed-core` | 打开容器、按条目解密、签名校验、缓冲零化 | `pack-format` | `openPack(path) → { manifest, readEntry(id) }`；`DecryptBackend` 接口 |
| `license-client` | 设备密钥生成/存取（OS 密钥库）、激活、续期、验签、状态机、时钟回拨检测 | `license-format`、`keystore` | `ensureLicense(pack) → { state, grants }` |
| `skill-provider` | 实现 dsh `SkillProvider`；`list()` 解密 meta 并套用 invocation 策略；`get(name)` 解密正文；返回无 path 虚拟技能 | `sealed-core`、`license-client` | `ctx.skills.registerProvider()` |
| `tool-runtime` | 包内脚本 → 模型可用工具；源码只在内存 | `sealed-core`、`ctx.ptcRuntime`、`ctx.sandbox` | 向 `ctx.tools` 注册定义；`sealed_resource` 工具按需返回资源 |
| `log-mask` | 注册纯消息投影：写日志时明文→`⟦sealed:pack:entry⟧`，读时还原 | dsh 投影 seam | 确定性、同步的投影处理器 |

`Keystore` 接口（实现可替换）：

```ts
interface Keystore {
  /** 解密出设备私钥到内存；v1 后端为导出式，M5 原生后端可改为不出模块。 */
  loadDevicePrivateKey(): Promise<Buffer | undefined>
  loadDevicePublicKey(): Promise<Buffer | undefined>
  createDeviceKey(): Promise<void>
  deleteDeviceKey(): Promise<void>
  /** 可选：在密钥库/原生模块内完成 ECDH（M5）。存在时必须优先使用，避免私钥进入 JS 堆。 */
  ecdh?(peerPublicKey: Buffer): Promise<Buffer>
}
```

v1 的导出式后端在 ECDH 前把私钥读入内存、用后立即零化；M5 原生后端通过 `ecdh()` 让私钥永不离开模块。

v1 后端：Windows DPAPI（PowerShell 助手调用 `ProtectedData`，无需原生编译）、macOS Keychain（`security` CLI）、Linux libsecret（`secret-tool` CLI）。密钥库不可用时的策略见 §8。

`DecryptBackend` 接口（§4.5 不变量 4）：

```ts
interface DecryptBackend {
  readonly id: 'node-crypto' | 'native' | 'wasm'
  aeadOpen(key: Buffer, nonce: Buffer, aad: Buffer, ct: Buffer): Buffer
  zeroize(buf: Buffer): void
}
```

### 6.4 服务端

- `@sealed/license-server`：HTTP 服务（§7.2 端点）、设备/席位/吊销存储（SQLite 起步）、Ed25519 签名、master key 加密静态存储、临时 X25519 封装。
- 管理员接口需 bearer token + mTLS；审计日志记录全部签发/吊销操作。
- 遥测最小化：仅记录 license id、设备公钥哈希、时间戳、端点、pack id/version。不记录任何技能内容。

---

## 7. 数据流

统一约定：`CK_i = HKDF(master, "entry:"||entry_id)`；license 逐条目封装 CK_i。

### 7.1 打包

```
1. seal pack 解析技能目录 → 条目列表（正文 / 脚本 / 资源 / 数据各一条，另加 meta）
2. 标记每条目类型、大小、是否试用集
3. 生成 master；派生 CK_i；payload_i = AES-256-GCM(CK_i, 明文)
4. 写明文 manifest（仅不透明 id/类型/大小/试用标记）+ 签名
5. 产出 .sealedpack 与 x.master.json
6. seal publish 经管理通道登记 master 到授权服务器
```

### 7.2 激活

```
1. license-client 查 OS 密钥库；无设备密钥则生成 X25519 密钥对，私钥入库
2. 本地无有效 license 且有购买凭据：
   POST /v1/activate { device_pub, purchase_token, pack:{id,version} }
3. 服务端校验凭据/席位 → 为该设备逐条目封装 CK_i → Ed25519 签发 license(exp=+7d, grace_until=exp+3d)
4. 客户端用内置服务端公钥验签，校验 exp / dev == 本机设备公钥 / grants 覆盖
5. license 落 $DSH_HOME/sealed/licenses/<lid>.license.json
```

### 7.3 首次调用（核心链路）

```
模型调用技能 → dsh 的 skill 工具 → ctx.skills.get(name)
1. skill-provider 从 pack 的 meta 条目解析技能定义（需 license 覆盖 meta）
2. 校验 license 状态：active / grace / expired；时钟回拨 → 不可信
3. 校验该技能的 entries 均被 license 覆盖
4. 用设备私钥经 Keystore 解封 CK_i
5. sealed-core 解密正文 → 内存字符串
6. 返回 SkillDefinition{ content, 无 path, resourceBase: { kind: 'opaque', description } }
7. log-mask 介入：写会话日志时正文替换为 ⟦sealed:…⟧；投影读取时还原
8. 用完在 finally 路径零化缓冲
```

- `list()` 只解密 `meta` 条目（小），**不解密正文**；未授权时退化为只读 manifest 的公开 label。
- 脚本条目：不落盘。JS/TS 经 `ctx.ptcRuntime` 在沙箱执行，绑定最小化；Python 等经标准输入管道喂给解释器（`python -`），无临时文件。语言支持清单见 §9。
- 资源条目：通过 `sealed_resource` 工具按需解密返回；`resourceBase: opaque` 的 description 说明如何取用。

### 7.4 续期

```
1. 启动时 + 每 24h：若剩余 < 阈值（如 2 天）
   POST /v1/renew { license_id, device_pub, nonce, ts, sig(设备私钥, nonce||ts) }
2. 服务端验签证明设备持有私钥 → 查吊销/席位/订阅 → 签发新 license
3. 联网失败但未过 exp：静默继续，缩短下次重试间隔（指数退避 + 抖动）
4. 已过 exp 未续上：进入 grace，技能照常 + 提示续费
5. grace 结束：技能停用；包与数据不删除
```

### 7.5 吊销

```
1. 管理员 POST /v1/revoke { license_id | device_pub | seat }
2. 服务端标记吊销并释放席位
3. 用户本地未过期 license 在 exp 前仍可用（延迟 ≤ TTL）
4. 下次 renew 返回 403 → 到期后失效（不立即中断进行中的会话）
```

### 7.6 试用

```
1. POST /v1/trial { device_pub, pack }；服务端按设备+pack 去重（每设备每包一次）
2. 签发 trial license：capabilities=["trial"]，grants 仅含 meta + 试用条目
3. 客户端走正常流程；试用范围外 get() 返回未授权
4. 购买后 /v1/activate 覆盖为正式 license，无需重装
```

---

## 8. 错误处理与降级

总原则：

- **授权相关 fail-closed**（无有效 license → 不给内容）。
- **可用性相关在宽限内 fail-open**（断网不打断已授权用户）。
- 任何错误路径都不产生明文落盘；错误消息与遥测一律脱敏，禁止携带 `content`。

| 场景 | 检测 | 处理 | 用户可见 |
|---|---|---|---|
| 激活时断网 | HTTP 失败/超时 | 指数退避重试 | 「首次激活需联网」 |
| 续期断网，未过期 | 定时任务失败 | 静默继续 | 无感 |
| 已过 exp 未续上 | 本地状态机 | 进入 grace | 「授权过期，宽限 3 天」 |
| grace 结束 | 本地状态机 | 停用技能，保留包与数据 | 「请续费」 |
| 系统时钟回拨 | 与密钥库存的上次时间比对，超阈值 | 判不可信 → 要求联网续期 | 「检测到时钟异常」 |
| license 验签失败 | Ed25519 验签 | 拒绝，不缓存 | 「授权无效」 |
| license 与设备不符 | dev 比对 | 拒绝 | 「此授权不适用于本机」 |
| 包被篡改 | manifest 签名 / AEAD 标签失败 | 该条目拒绝解密，整包标记损坏 | 「技能包损坏」 |
| 包版本过新 | format_version | 拒绝并提示升级 | 「请升级 loader 插件」 |
| 设备私钥丢失 | 密钥库读不到 / 解封失败 | 触发重新激活；服务端按策略重发席位 | 「需重新激活」 |
| 席位已满 | activate 返回 409 | 提示释放旧设备或增购 | 「设备数已达上限」 |
| 试用已用过 | trial 返回 409 | 提示购买 | 「试用已用过」 |
| 已被吊销 | renew 返回 403 | 到期后停用 | 「授权已失效」 |
| 密钥库不可用/被锁 | 解封失败 | 降级只读发现（能列出、不能解密） | 「无法访问系统密钥库」 |
| **log-mask 注册失败** | 启动自检 | **fail-closed：skill-provider 拒绝服务** | 「安全组件未就绪」 |
| 沙箱不可用/审批被拒 | ptcRuntime/sandbox 报错 | 拒绝脚本类工具；纯提示词技能不受影响 | 「脚本工具需授权沙箱」 |
| 多进程并发访问密钥库 | 锁 | 串行化；拿不到锁则等待 | 无感 |
| 条目解密内存超限 | 大小上限（如 32MB） | 报错而非 OOM | 「技能包过大」 |
| 服务端 5xx / 限流 | HTTP 状态 | 退避重试；不删除本地 license | 无感 / 「服务暂时不可用」 |
| nonce 重放 | 服务端一次性 nonce 表 | 拒绝该次 renew | 「授权校验失败」 |
| 插件卸载/进程退出 | `ctx.effect()` 清理钩子 | 零化内存中的 CK 与明文缓冲 | — |

**两条硬性保障**

1. **顺序保障**：`log-mask` 必须先于任何解密完成注册并自检通过，否则 `skill-provider` 拒绝服务（宁可不可用，也不产生明文日志）。
2. **崩溃安全**：明文只在内存；解密缓冲在 `finally` 路径零化；异常对象与日志统一脱敏。

---

## 9. 技术选型

- 语言：TypeScript（Node ≥ 20），包管理 pnpm，与 dsh 生态一致。
- 密码学：Node 内置 `crypto` —— X25519（ECDH）、HKDF-SHA256、AES-256-GCM、Ed25519。
- 序列化规范化：JCS（RFC 8785）。
- 压缩：`zstd`（可选依赖，缺失时退化为不压缩）。
- 服务端存储：SQLite（起步）；master key 用服务端密钥加密静态存储。
- 脚本语言 v1 支持：JS/TS（`ctx.ptcRuntime` 沙箱装饰）、Python（stdin 管道）。其他语言作为扩展点，需满足「源码不经临时文件」约束；不满足则拒绝并在文档说明。
- 密钥库 v1 后端：DPAPI（PowerShell 助手）/ Keychain（`security` CLI）/ libsecret（`secret-tool` CLI）。
- 若三者皆不可用：默认 fail-closed（不落盘长期私钥，改为每次会话重新激活）；提供显式的 `--allow-file-keystore` 退路（0600 文件 + 机器派生密钥包装），并在文档标注安全等级下降。

---

## 10. 测试策略

### 10.1 单元与规范层

`pack-format` 往返编解码、逐条目 AEAD、篡改任一字节必失败、版本兼容；`license-format` 验签成功/失败、过期、设备不匹配、grants 覆盖；HKDF 测试向量固定化；license 状态机全路径；时钟回拨分支。

### 10.2 协议互操作（golden vectors）

固化一组 `.sealedpack` 与 license 测试向量于 `test-vectors/`，第三方实现（含未来的其他 harness 适配器）用同一份向量自测。

### 10.3 泄漏验收（核心验收）

- **金丝雀扫描**：正文埋唯一字符串；跑完「安装→激活→列技能→调用技能→跑脚本→触发各类报错」后，扫描会话日志（含 zstd 压缩的 `session.jsonl`）、spill 目录、临时目录、日志与遥测，断言金丝雀零命中。
- **错误路径全覆盖**：§8 表格逐条执行，断言零泄漏且错误消息不含正文。
- **崩溃残留**：解密中途杀进程，断言磁盘无明文残留。
- **发布必过 CI gate**：泄漏扫描不通过则禁止发布。
- **运行时不变式插件**：通过 `ctx.invariants` 注册「已提交会话事件中不得出现 sealed 明文」的包级检查。

### 10.4 集成与对抗层

- 真实 dsh 集成：在测试 profile 安装 bundle、放包、调 `ctx.skills.get()`，断言虚拟技能无 `path`、内容正确、`resourceBase` 正确。
- 授权对抗：试用解不开非试用条目；license 换机失效；改包失败；续期重放被拒；席位超限。
- 离线语义：断网 + 伪造时钟，验证宽限行为与时钟回拨处置。
- 服务端：激活/续期/吊销/试用语义、幂等、限流、replay 防护、审计。
- 沙箱与跨平台：脚本工具在沙箱内执行且磁盘无源码；Windows/macOS/Linux 三套密钥库后端各跑一遍。

---

## 11. 生态文档（交付物）

面向 skill 开发者的详尽文档，作为仓库一等交付物：

```
docs/sealed-skills/
├─ README.md                    生态总览：为什么、能做什么、怎么加入
├─ spec/pack-format.md          .sealedpack 容器规范 + golden vectors 说明
├─ spec/license-format.md       license 令牌规范 + 规范化/验签/封装算法
├─ spec/protocol.md             授权服务器 HTTP 协议 + 错误码 + 幂等/限流约定
├─ guide/author-quickstart.md   30 分钟：从技能目录到可安装包
├─ guide/publish-and-license.md 打包、发布、签名、签发与席位管理
├─ guide/trial-and-marketplace.md 试用与按技能售卖编排
├─ guide/build-your-own-loader.md 第三方 loader 互操作指南（含测试向量用法）
└─ guide/threat-model.md        安全属性、残余风险、正确使用方式
```

文档要求：每篇含可复制运行的命令与最小示例；规范篇与实现解耦，明确标注「规范 vs 实现」；所有示例在 CI 中作为冒烟测试执行。

---

## 12. 仓库布局

```
sealed_skills/
├─ packages/
│  ├─ pack-format/
│  ├─ license-format/
│  ├─ seal-cli/
│  ├─ dsh-sealed-skills/       (bundle: pack-registry/sealed-core/license-client/skill-provider/tool-runtime/log-mask)
│  └─ license-server/
├─ test-vectors/
├─ docs/
│  └─ sealed-skills/           (§11)
├─ docs/superpowers/specs/     (本文件)
└─ AGENTS.md
```

---

## 13. 里程碑

- **M1 骨架**：`pack-format` + `seal-cli` + `sealed-core` + `skill-provider`；本地自签 license 跑通「加密加载虚拟技能」。
- **M2 授权闭环**：`license-server`（activate/renew/trial/revoke）+ `license-client` 状态机 + 密钥库后端 + 宽限与时钟检测。
- **M3 防泄漏**：`log-mask`（含 §10.3 泄漏 gate 与不变式插件）+ `tool-runtime` 脚本执行。
- **M4 生态与交付**：§11 文档、golden vectors、CI gate、市场/分发流程。
- **M5 加固（可选）**：原生/WASM `DecryptBackend`，关键运算移出 JS 堆。

---

## 14. 已定决策（无待定项）

| 决策 | 取值 | 理由 |
|---|---|---|
| 威胁模型 | B 级 | 用户选择 |
| 许可模式 | 在线激活 + 离线宽限 | 用户选择（原 A 修订为 B） |
| TTL / grace | 7 天 / 3 天 | 用户确认；吊销延迟旋钮 |
| 试用切分 | 逐条目封装 CK | 客户端不可绕过 |
| 包加密 | 一次加密、全客户共用 | 可 CDN 分发 |
| 明文 manifest 内容 | 仅不透明 id/类型/大小/试用标记 | 避免泄露技能名与内容确认攻击 |
| 技能元数据 | 加密的 `meta` 条目 | `list()` 只解密 meta |
| 设备绑定 | X25519 设备密钥对 + OS 密钥库 | 换机不可用 |
| 签名 | Ed25519 | Node 内置支持 |
| 会话日志 | 消息投影掩码（退路：自定义 SessionPersistence provider） | 满足 dsh「模型可见即已记录」不变式 |
| 解密后端 | v1 Node crypto，可替换接口 | 后续可上原生/WASM |
