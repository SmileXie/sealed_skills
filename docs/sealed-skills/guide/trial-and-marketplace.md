# 试用与市场：把技能变成可持续的生意

> 面向**技能作者与运营者**。本文只描述**当前已实现**的机制（M2 授权闭环 + M3 防泄漏），
> 不发明端点：所有线协议以 `docs/sealed-skills/spec/protocol.md` 与
> `packages/license-format/src/protocol.ts`（协议单一真源）为准。

这一篇回答四个运营层面的问题：

1. 试用怎么切、怎么防止被反复白嫖；
2. 席位和续期如何决定「一个订单能被几台设备用多久」；
3. 吊销要等多久才真正生效，退款/风控怎么用；
4. 我该怎样给技能定价、打包，并把它分发/上架到市场上。

打包与部署的具体命令见 `docs/sealed-skills/guide/author-quickstart.md` 与
`docs/sealed-skills/guide/publish-and-license.md`；协议常量与错误码见
`docs/sealed-skills/spec/protocol.md`。

---

## 1. 试用机制

### 1.1 `trial_entries`：试用边界由你指定

试用范围不是运行时策略，而是**发布时就写进服务端的授权清单**。在
`POST /v1/admin/packs` 的请求体里用一个字符串数组声明：

```json
{
  "pack": { "id": "com.example.translate", "version": "1.0.0" },
  "trial_entries": ["meta", "skill:translate:body"]
}
```

条目 id 的约定见 `docs/sealed-skills/spec/pack-format.md`：`meta` 是技能元数据，
`skill:<name>:body` 是技能正文，`skill:<name>:res:<path>` 是资源，`script:<name>:<path>`
是脚本，`data:<name>` 是私有数据。你只把**愿意白送**的条目放进 `trial_entries`。

用 `seal pack` 打包时也写同样的集合（`--trial meta` 表示只放行元数据）：

```bash
node packages/seal-cli/dist/cli.js pack ./my-skill -o my-skill.sealedpack \
  --pack-id com.you.myskill --version 1.0.0 --label "我的技能" \
  --key author.key.json --trial meta
```

### 1.2 每设备每包只能试用一次

客户端调用：

```
POST /v1/trial
{ "device_pub": "<43 字符 base64url>", "pack": { "id": "...", "version": "..." } }
```

服务端以 `(device_pub, pack_id, version)` 为去重键：

- 首次 → `200 { "license": "..." }`；
- 同一设备再次索取同一 pack 的试用 → `409 TRIAL_ALREADY_USED`；
- pack 未登记 → `404 PACK_NOT_FOUND`；
- 公开端点限流（默认 60 次/分钟）→ `429 RATE_LIMITED`。

去重绑定的是**设备公钥**，也就是新装机器/新设备密钥。重装 loader、清空缓存都不会重置试用：
只要 `$SEALED_HOME/device.json` 还在，同一台机器就只能试用一次。清掉设备密钥等于换机，会走
新的试用名额——这属于威胁模型 B 接受的成本，见 `docs/sealed-skills/guide/threat-model.md`。

### 1.3 试用 license 长什么样

`POST /v1/trial` 返回的是一份完整签名 license，由服务端按 `trial_entries` 逐条目封装密钥：

| 字段 | 试用取值 | 说明 |
|---|---|---|
| `caps` | `["trial"]` | 能力标签；正式购买为 `["full"]` |
| `groups` | `["trial"]` | 套餐分组；正式购买为 `[plan]` |
| `seats` | `{ "plan": "trial", "limit": 1 }` | 试用固定 1 席 |
| `sub` | `trial:<device_pub 前 8 字符>` | 试用不计入任何订单 |
| `keys` | 仅 `trial_entries` 中的条目 | 未授权条目**不含密钥**，客户端解不开 |
| `exp` / `grace_until` | `iat + 7d` / `exp + 3d` | 与正式 license 相同的 TTL / 宽限 |

因为未授权条目的条目密钥根本不在 license 里，客户端无法通过改 loader 绕过——这是逐条目
封装（per-entry CK wrapping）带来的保证，而不是客户端自觉。

### 1.4 试用切分建议

- **只给 `meta` 是安全默认值**：技能名、描述、`whenToUse`（来自加密的 `meta` 条目）足够让
  用户判断价值，正文与脚本仍需购买。
- **要「尝到效果」就给 1–2 个代表性条目**（例如一个示例资源或一段演示脚本），但不要给全套
  `script:*`。
- **试用集一旦发布就固定在该版本上**。修改内容必须升 `--version` 重新登记，详见 §7。

### 1.5 试用如何转购买（同一设备、零重装）

试用和正式购买走的是**同一台设备的同一个设备公钥**，因此转购买不需要卸载或重装密文包：

```
POST /v1/activate  { "device_pub": ..., "purchase_token": "...", "pack": {...} }
```

服务端为**全部条目**封装密钥、签发 `caps: ["full"]` 的 license。客户端把新 license 写到
`$SEALED_HOME/licenses/<lid>.license.json`，下一次读取技能时即可解锁正文。

---

## 2. 席位：一个订单能绑几台设备

席位由你计费系统签发的 `purchase_token` 决定。写入服务端时包含：

| 字段 | 含义 |
|---|---|
| `token` | 全局唯一的不透明凭据 |
| `sub` | 客户 / 订阅标识，席位按它归集 |
| `plan` | 套餐名，会成为 license 的 `groups` |
| `seats` | 该订单允许的设备数 |
| `expiresAt` | 可选，token 自身的过期时间（秒） |

行为规则（对应 `POST /v1/activate`）：

- 设备首次激活 → 占用一个席位，席位键为 `(sub, pack_id, version)`；
- 席位已用满 → `409 SEAT_LIMIT`；
- **同一设备重复激活同一 pack** → 复用已有 license，不额外占席位；
- 未知或已过期 token → `401 BAD_PURCHASE_TOKEN`；
- token 指向别的 pack → `404 PACK_NOT_FOUND`。

`POST /v1/revoke` 会**释放**对应席位。因此「换机」的标准话术是：
让用户在新机激活（如果还有空位），再在后台吊销旧设备释放席位；席位满了就先吊销再激活。

席位设计建议：

- **个人订阅**：`seats: 1`，换机靠吊销释放。
- **团队/企业**：按人头给 `seats`，用 `sub` 归集到同一个客户；
- **不要用席位当并发限制**：席位是「能绑定几台设备」，不是「同时能开几个会话」。当前协议
  没有并发数概念。

---

## 3. 续期节奏：7 天 TTL，提前 2 天续

license 是**滚动短周期**的：每次签发/续期有效期 7 天，客户端在剩余不足 2 天时自动续期。
相关常量（`packages/license-format/src/protocol.ts`）：

| 常量 | 值 | 含义 |
|---|---|---|
| `LICENSE_TTL_SECONDS` | `604800`（7 天） | 每次签发/续期的有效期 |
| `LICENSE_GRACE_SECONDS` | `259200`（3 天） | `exp` 之后的离线宽限 |
| `RENEW_THRESHOLD_SECONDS` | `172800`（2 天） | 客户端提前续期阈值 |
| `MAX_CLOCK_SKEW_SECONDS` | `300`（±5 分钟） | `renew` 时间戳窗口 |
| `NONCE_TTL_SECONDS` | `600`（10 分钟） | `renew` 一次性 nonce 保留时长 |

续期用**设备证明（DH-MAC）**，不需要重新下发 `purchase_token`：

```
POST /v1/renew  { "license_id": ..., "device_pub": ..., "nonce": ..., "ts": ..., "mac": ... }
```

服务端按固定顺序校验：未知 license → `404 UNKNOWN_LICENSE`；已吊销 → `403 REVOKED`；
设备不匹配 → `401 BAD_DEVICE_PROOF`；时间戳超窗 → `400 BAD_REQUEST`；MAC 不匹配 →
`401 BAD_DEVICE_PROOF`；nonce 重放 → `409 REPLAY`。全部通过后以 `exp = now + 7d` 重新签发。

客户端侧还有一层**24 小时惰性刷新**：已挂载的 pack 在每次被访问时，如果距上次成功构建超过
24h，就丢弃缓存并重跑 license 获取（该续期就续期）。因此长时间运行的进程也会自动续期，
不会在 `exp + grace` 后静默丢失技能。

离线行为：

- 缓存 license 未过期 → 直接解密，不联网、不写新 license、不推进时钟锚点；
- 过了 `exp` 但在 `grace_until` 之前 → 仍可用（宽限）；
- 超过 `grace_until` 仍未续上 → 停用（包与本地数据不删除）；
- 系统时钟回拨超过 ±5 分钟 → 判 `CLOCK_UNTRUSTED`，要求联网续期。

---

## 4. 吊销与生效延迟：最坏一个 TTL（7 天）

后台吊销：

```
POST /v1/revoke   Authorization: Bearer <admin token>
{ "license_id": "..." }        // 也支持 device_pub / seat
```

响应 `{ "revoked": N }` 只统计**本次真正发生状态翻转**的 license 数。吊销同时释放席位。

**吊销不是实时踢下线**：客户端在 `exp - 2d` 之前走本地缓存快路径、根本不联系服务器，只有
进入续期窗口（或宽限期）后才会 `renew`，此时才会拿到 `403 REVOKED` 并删除本地缓存。因此
从后台标记吊销到用户侧真正停用，**最坏要等一个 license TTL，即 7 天**（如果用户当时正好
在续期窗口内，则最迟 24 小时内生效）。

运营含义：

- **退款/盗刷**：吊销是对的，但要向客服/用户说明最长 7 天的生效窗口，别承诺「立刻失效」。
- **需要更强的即时性**：把 TTL 调短（例如 1–2 天）可以缩短吊销延迟，代价是续期请求更频繁、
  离线可用窗口更短。`LICENSE_TTL_SECONDS` 是服务端常量，改它属于改协议常量，需同步客户端。
- **别把它当封禁工具**：被吊销的设备仍可能持有已解出的明文（模型请求已发出后无法收回），
  见 `docs/sealed-skills/guide/threat-model.md`。

---

## 5. 定价与打包建议

协议层完全不管你收多少钱、怎么收。下面几种模式用现有机制就能落地：

| 模式 | 用到的机制 | 适合 |
|---|---|---|
| **订阅制（滚动）** | 7 天 TTL + 自动续期 | 持续更新的技能、SaaS 式收费 |
| **年付 / 大周期** | 购买凭据 + 定期续期；`purchase_token.expiresAt` 控制 token 生命周期 | 现金流更稳、续期请求更少 |
| **团队席位** | `sub` + `seats` + 吊销释放 | 企业按人头采购 |
| **免费试用转付费** | `trial_entries` + 每设备一次去重 | 降低决策门槛 |
| **版本买断 / 升级包** | 同一 `pack_id` 的多个 `version`，独立登记与定价 | 一次性大版本升级 |
| **能力分层** | `plan` → license 的 `groups`；不同条目集用不同 `trial_entries` / 发布版本 | 基础版 / 专业版 |

定价时可以先想清楚两个「旋钮」：

1. **续期周期 vs 价格**：TTL 越短，吊销延迟越小、但续期依赖越重。多数技能用默认 7 天即可；
   买断型可以按年发凭据。
2. **席位 vs 单价**：按设备席位计价最贴近协议模型；按并发计价当前协议不支持，不要这样宣传。

转换率建议：

- **`meta` 试用 + 正文门槛** 通常是把「能不能用」讲清楚的关键；把最有说服力的 1 个示例放进
  `trial_entries`。
- **试用到期不是断崖**：试用 license 同样是 7 天 TTL + 3 天宽限；到期后用户仍可续用试用，
  但范围不变。要解锁正文必须 `activate`。
- **升级即升版本**：`POST /v1/admin/packs` 对同一版本幂等，改了内容必须升 `--version`，
  否则买到旧版的人拿不到新内容。

---

## 6. 市场与分发模式

### 6.1 作者流程（打包 → 登记 → 交付）

```
① seal keygen                     生成作者身份密钥（长期）
② seal pack                       技能目录 → .sealedpack（密文）+ .master.json（服务端机密）
③ POST /v1/admin/packs            登记 pack：只上传 master，绝不上传明文或密文包
④ 计费系统签发 purchase_token      买家付款 → 写入服务端
⑤ 分发                            .sealedpack（CDN / 市场 / 网盘）+ token
```

```bash
node packages/seal-cli/dist/cli.js keygen -o author.key.json
node packages/seal-cli/dist/cli.js pack ./my-skill -o my-skill.sealedpack \
  --pack-id com.you.myskill --version 1.0.0 --label "我的技能" \
  --key author.key.json --trial meta
```

登记只需 `master_b64`（base64url 32 字节）与条目清单，`POST /v1/admin/packs` 返回
`{ pack, entries }`；同一版本重复发布返回缓存响应（幂等键 `publish:<id>@<version>`）。
完整可复制命令见 `docs/sealed-skills/guide/publish-and-license.md` §3。

### 6.2 部署授权服务器

授权服务器由**你**托管（它是信任边界内的签发方），部署方式与密钥管理见
`docs/sealed-skills/guide/publish-and-license.md` §2。面向用户时至少要提供：

- `serverUrl`：`GET /v1/health` 可用于探活与版本发现；
- `serverProofPubB64`：续期设备证明用的服务端 X25519 公钥；
- `trustedLicenseKeysB64`：验 license 签名的服务端 Ed25519 公钥。

### 6.3 分发 `.sealedpack` 与买家激活

密文包**对所有客户是同一份**，可以放到任何静态分发渠道（CDN、npm、市场、对象存储），
不需要为每个客户重新打包。买家侧只需三样东西：

```ts
{
  serverUrl: 'https://license.example.com',
  serverProofPubB64: '<服务器 proof 公钥>',
  trustedLicenseKeysB64: ['<服务器 license 签名公钥>'],
  mounts: [{ packPath: '/abs/my-skill.sealedpack', purchaseToken: '<订单 token>' }],
}
```

首次使用会走 `POST /v1/activate` 激活；离线交付场景可给预置 license（mount 里配
`licensePath`，无需联网）。

### 6.4 常见编排形态

| 形态 | 做法 | 要点 |
|---|---|---|
| **自建商店** | 自己的站点收款 → 签发 token → 交付包+token | 只需实现「写 purchase 记录」一步 |
| **挂到开发者市场** | 市场上架密文包；你保留 license server | 市场只管分发，授权仍在你手里 |
| **CDN / 静态托管** | 包放 CDN，token 另行交付 | 包与客户无关，可公开缓存 |
| **企业私有部署** | 客户内网自托管 license server | master 仍只在签发方；用户侧只有公钥 |

### 6.5 交付清单

- **可以交付**：`.sealedpack`、`purchase_token`、服务器公钥 + 作者公钥。
- **绝不交付**：`.master.json`、`author.key.json`、任何明文技能内容、服务端私钥
  （`SEALED_SERVER_LICENSE_KEY` / `SEALED_SERVER_PROOF_KEY` / `SEALED_SERVER_MASTER_KEY`）。

---

## 7. 完整走查：试用 → 购买 → 续期

以 `com.example.translate@1.0.0`（`trial_entries: ["meta"]`）为例，只使用
`docs/sealed-skills/spec/protocol.md` 里的端点：

1. **探活**：`GET /v1/health` → `{ "ok": true, "version": "1" }`。
2. **发布**：作者 `POST /v1/admin/packs`（Bearer）登记 `author_pub`、`master_b64`、
   `trial_entries` 与条目清单 → `200 { pack, entries }`。
3. **试用**：用户设备 `POST /v1/trial { device_pub, pack }` → `200 { license }`
   （`caps ["trial"]`，只有 `meta` 的密钥）。设备写
   `$SEALED_HOME/licenses/<lid>.license.json`。
   - 同一设备再试 → `409 TRIAL_ALREADY_USED`。
4. **购买**：你的计费系统登记 `purchase_token`（`sub` / `plan` / `seats`），交付给买家。
5. **激活**：用户设备 `POST /v1/activate { device_pub, purchase_token, pack }` →
   `200 { license }`（`caps ["full"]`，全部条目密钥）。
   - 席位满 → `409 SEAT_LIMIT`（先吊销旧设备释放席位）。
6. **日常使用**：缓存未过期直接解密（离线可用）；剩余不足 2 天时，插件自动
   `POST /v1/renew`（DH-MAC 设备证明）→ 新 license 的 `exp = now + 7d`。
7. **断网**：`exp` 前继续可用；`exp` 后仍有 3 天宽限（`grace_until`）；再之后停用。
8. **退款/风控**：后台 `POST /v1/revoke { license_id }`（Bearer）→ 释放席位；用户下一次
   `renew` 收到 `403 REVOKED`，客户端删除缓存并停用（最坏 ≤ 7 天）。

---

## 8. 排错速查（服务端错误码 → 用户可见含义）

| 错误码 | 触发场景 | 建议话术 |
|---|---|---|
| `TRIAL_ALREADY_USED` | 该设备已试过这个 pack | 「本设备已试用过，是否购买？」 |
| `SEAT_LIMIT` | 席位用满 | 「设备数已达上限，可吊销旧设备或增购」 |
| `BAD_PURCHASE_TOKEN` | token 未知/过期/不属于该 pack | 「购买凭据无效，请联系客服」 |
| `REVOKED` | license 已被吊销 | 「授权已失效，请重新购买」 |
| `REPLAY` | 续期 nonce 被复用 | 客户端内部重试，通常用户无感 |
| `UNKNOWN_LICENSE` | license 不存在 | 「授权丢失，请重新激活」 |
| `RATE_LIMITED` | 请求过于频繁 | 退避重试 |

客户端必须容忍未知错误码（折叠为 `SERVER_REJECTED`），不要因服务端新增错误码而崩溃。

---

## 9. 相关文档

- `docs/sealed-skills/spec/protocol.md` —— 授权服务器 HTTP 协议（端点、错误码、设备证明、常量）。
- `docs/sealed-skills/spec/pack-format.md` —— `.sealedpack` 线格式与条目 id 约定（含 golden vectors）。
- `docs/sealed-skills/spec/license-format.md` —— license 令牌格式、`caps` / `groups` / 席位字段。
- `docs/sealed-skills/guide/publish-and-license.md` —— 部署服务器、登记 pack、签发 token、席位与吊销。
- `docs/sealed-skills/guide/author-quickstart.md` —— 30 分钟从技能目录到密文包。
- `docs/sealed-skills/guide/threat-model.md` —— 安全属性、残余风险与「不要指望」清单。
- `docs/sealed-skills/guide/for-skill-developers.md` —— 生态邀请与商业路径总览。
- `docs/sealed-skills/guide/build-your-own-loader.md` —— 第三方 loader 如何自行实现与互操作。
