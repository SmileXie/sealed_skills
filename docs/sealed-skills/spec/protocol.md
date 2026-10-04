# 授权服务器协议参考（`/v1`）

本文件是 Sealed Skills 授权服务器 HTTP 协议的**规范**。仓库中的
`packages/license-format/src/protocol.ts` 是这份规范的**单一真源**：端点常量、错误码全集、
协议常量与请求校验都定义在那里，`@sealed/license-server` 与 `@sealed/dsh-sealed-skills`
共用同一份类型与校验函数，因此客户端与服务端不会各自漂移。

> **规范 vs 实现**：本文件描述“线上必须长什么样”。SQLite 表结构、限流算法、日志格式、
> 管理接口的部署方式都不属于协议，可自由替换。

## 1. 版本与常量

| 名称 | 值 | 含义 |
|---|---|---|
| `PROTOCOL_VERSION` | `1` | 协议主版本，路径前缀 `/v1` |
| `LICENSE_TTL_SECONDS` | `604800` | license 有效期（7 天） |
| `LICENSE_GRACE_SECONDS` | `259200` | 宽限期（3 天），`grace_until = exp + 3d` |
| `RENEW_THRESHOLD_SECONDS` | `172800` | 客户端提前续期阈值（剩余不足 2 天时续期） |
| `MAX_CLOCK_SKEW_SECONDS` | `300` | `renew` 时间戳允许的时钟偏差（±5 分钟） |
| `NONCE_TTL_SECONDS` | `600` | `renew` 一次性 nonce 的保留时长 |
| `MAX_BODY_BYTES` | `1048576` | 请求体上限（1 MiB），超限返回 413 |

`GET /v1/health` 返回 `{ "ok": true, "version": "1" }`，用于探活与版本发现。

## 2. 通用约定

- 请求体与响应体均为 JSON（`content-type: application/json`）。
- 错误统一信封：

```json
{ "error": { "code": "SEAT_LIMIT", "message": "all seats for this purchase are in use" } }
```

- 错误码全集（`ProtocolErrorCode`，客户端必须容忍未知码）：
  `BAD_REQUEST`、`PACK_NOT_FOUND`、`TRIAL_ALREADY_USED`、`BAD_PURCHASE_TOKEN`、
  `SEAT_LIMIT`、`UNKNOWN_LICENSE`、`BAD_DEVICE_PROOF`、`REPLAY`、`REVOKED`、
  `RATE_LIMITED`、`UNAUTHORIZED`、`INTERNAL`。
- 管理端点必须带 `Authorization: Bearer <admin token>`；缺失或错误返回 `401 UNAUTHORIZED`
  （常量时间比较，不区分“缺失”与“错误”）。
- 请求体超过 `MAX_BODY_BYTES` → `413 BAD_REQUEST`；非法 JSON → `400 BAD_REQUEST`。
- 服务端对客户端输入**只返回结构化错误**；`500 INTERNAL` 仅用于真正的服务端故障，
  消息不保证是固定字面量（实现里出现过 `internal error` 与 `stored master key is malformed`
  两种情况），但绝不携带技能内容、密钥或内部堆栈。
- 除 `GET /v1/health` 外，其余端点均为 `POST`；未知路径或错误方法 → `404 BAD_REQUEST`。
  （注意：`/v1/health` 为兼容 dsh 探活，对任意方法都返回 `200`。）
- 公开 `POST` 端点按来源地址滑动窗口限流（默认 60 次/分钟），超限返回 `429 RATE_LIMITED`。
- `device_pub`、`author_pub` 一律是 **base64url 编码的 32 字节裸公钥**（43 字符，无 padding）。

## 3. 端点表

| 方法 | 路径 | 鉴权 | 成功响应 | 可能错误 |
|---|---|---|---|---|
| GET | `/v1/health` | 无 | `{ ok: true, version }` | — |
| POST | `/v1/trial` | 无 | `{ license }` | `400`、`404 PACK_NOT_FOUND`、`409 TRIAL_ALREADY_USED`、`429` |
| POST | `/v1/activate` | 无 | `{ license }` | `400`、`401 BAD_PURCHASE_TOKEN`、`404 PACK_NOT_FOUND`、`409 SEAT_LIMIT`、`429` |
| POST | `/v1/renew` | 无（设备证明） | `{ license }` | `400 BAD_REQUEST`、`401 BAD_DEVICE_PROOF`、`403 REVOKED`、`404 UNKNOWN_LICENSE`、`409 REPLAY`、`429` |
| POST | `/v1/revoke` | Bearer | `{ revoked }` | `400`、`401 UNAUTHORIZED`、`404 UNKNOWN_LICENSE`、`429` |
| POST | `/v1/admin/packs` | Bearer | `{ pack, entries }` | `400 BAD_REQUEST`、`401 UNAUTHORIZED`、`429` |

请求类型（与 `protocol.ts` 逐字一致）：

```ts
interface PackRef { id: string; version: string }

interface TrialRequest { device_pub: string; pack: PackRef }

interface ActivateRequest { device_pub: string; purchase_token: string; pack: PackRef }

interface RenewRequest {
  license_id: string
  device_pub: string
  nonce: string
  ts: number      // 秒级 Unix 时间戳
  mac: string     // 见 §4
}

interface RevokeRequest { license_id?: string; device_pub?: string; seat?: string }

interface PublishPackRequest {
  pack: PackRef
  author_pub: string          // base64url raw Ed25519 公钥
  label: string               // 非敏感公开名，未授权时也能展示
  master_b64: string          // base64url raw 32 字节 pack master key
  trial_entries: string[]     // 试用可解锁的条目 id
  entries: { id: string; type: string; size: number }[]
}
```

### 3.1 `/v1/trial`

为**首次**索取该 pack 的设备签发试用 license。试用范围由发布时的 `trial_entries` 决定；
**每台设备每个 pack 只能试用一次**（服务端按 `(device_pub, pack_id, version)` 去重）。

响应中的 `license` 是完整签名的 license 令牌字符串（见 §5.2；独立的
`spec/license-format.md` 为 M4 计划项，尚未编写）。试用 license 的 `caps = ["trial"]`，
只携带 `trial_entries` 对应的条目密钥。

```json
// request
{ "device_pub": "sB0…43chars…", "pack": { "id": "com.example.translate", "version": "1.0.0" } }
// 200
{ "license": "v1.eyJ2Ijox…" }
```

### 3.2 `/v1/activate`

用购买凭据（`purchase_token`）把 pack 激活到该设备：服务端校验凭据、占用席位、为**全部条目**
封装密钥并签发 license（`caps = ["full"]`）。

- 同一设备重复激活同一 pack：复用已有 license，不额外占席位。
- 席位已满：`409 SEAT_LIMIT`；吊销会释放席位。

```json
// request
{ "device_pub": "sB0…", "purchase_token": "pt_9f2c…", "pack": { "id": "com.example.translate", "version": "1.0.0" } }
// 200
{ "license": "v1.eyJ2Ijox…" }
```

### 3.3 `/v1/renew`

用**设备证明**换取一份新的 license。服务端按固定顺序校验：
未知 license → `404`，已吊销 → `403`，设备不匹配 → `401`，时间戳超窗 → `400`，
MAC 不匹配 → `401`，nonce 重放 → `409`；全部通过后重新签发（`exp` 顺延一个 TTL）。

```json
// request
{ "license_id": "lic_full_1730000000_ab12cd34", "device_pub": "sB0…",
  "nonce": "Zk3…", "ts": 1730000000, "mac": "9Gq…" }
// 200
{ "license": "v1.eyJ2Ijox…" }
```

### 3.4 `/v1/revoke`（Bearer）

按 `license_id`、`device_pub` 或 `seat` 之一吊销 license，并释放对应席位。
`revoked` 只统计**本次真正发生状态翻转**的 license 数（重复吊销不重复计数）。

```json
// request
{ "license_id": "lic_full_1730000000_ab12cd34" }
// 200
{ "revoked": 1 }
```

> 吊销是**最终失效**：客户端本地的未过期 license 在 `exp` 前仍能离线使用（延迟 ≤ TTL）；
> 下一次 `renew` 会拿到 `403 REVOKED`，客户端随即删除本地缓存。

### 3.5 `/v1/admin/packs`（Bearer）

登记一个已打包的 pack。**只上传 master key，绝不上传明文或 `.sealedpack` 内容**。
服务端把 master key 用服务端主密钥加密后静态存储，用于后续为各设备封装条目密钥。

幂等键是 `publish:<pack_id>@<version>`：同一版本重复发布返回缓存响应，不会重复写库；
**内容变更必须升版本号**。

```json
// request
{
  "pack": { "id": "com.example.translate", "version": "1.0.0" },
  "author_pub": "Pq8…43chars…",
  "label": "翻译",
  "master_b64": "3oR…base64url-32-bytes…",
  "trial_entries": ["meta"],
  "entries": [
    { "id": "meta", "type": "meta", "size": 249 },
    { "id": "skill:translate:body", "type": "text", "size": 98 }
  ]
}
// 200
{ "pack": { "id": "com.example.translate", "version": "1.0.0" }, "entries": 2 }
```

`entries` 请求字段是数组，响应字段是**条目个数**（number）。

## 4. 设备证明（DH-MAC）

`/v1/renew` 不使用签名，而用 **DH-MAC** 证明“请求方持有与 license `dev` 相同的 X25519
私钥”。服务端把长期 X25519 证明公钥 `server_proof_pub` 内置到客户端；客户端用设备私钥做一次
ECDH，再对 `(license_id, nonce, ts)` 做 HMAC。这样服务端**无需**保存任何设备私钥材料。

公式（与 `protocol.ts` 的 `deviceProofKey` / `deviceProofMessage` / `deviceProofMac` 一致）：

```
ss  = ECDH(device_priv, server_proof_pub)                       // X25519 共享密钥，32 字节
key = HKDF-SHA256(ikm=ss, salt=utf8(license_id), info=utf8("device-proof:"), L=32)
msg = utf8(license_id) || 0x00 || utf8(nonce) || 0x00 || utf8(String(ts))
mac = base64url(HMAC-SHA256(key, msg))
```

- `salt` 是 `license_id` 的 UTF-8 字节；`info` 是字面量 `"device-proof:"`。
- 拼接分隔符是单个 `0x00` 字节。
- `ts` 是秒级 Unix 时间戳；`|now - ts| > MAX_CLOCK_SKEW_SECONDS` → `400 BAD_REQUEST`。
- `nonce` 是一次性随机串（客户端每次随机 16 字节 base64url）；服务端按
  `(license_id, nonce)` 去重，重复 → `409 REPLAY`。
- 比较必须是常量时间（`timingSafeEqual`）。

客户端伪代码：

```ts
function proofFor(licenseId: string, deviceX25519: KeyObject, serverProofX25519: KeyObject) {
  const nonce = randomBytes(16).toString('base64url')
  const ts = Math.floor(Date.now() / 1000)
  const ss = diffieHellman({ privateKey: deviceX25519, publicKey: serverProofX25519 })
  const key = Buffer.from(hkdfSync('sha256', ss, Buffer.from(licenseId, 'utf8'), Buffer.from('device-proof:', 'utf8'), 32))
  const SEP = Buffer.from([0])
  const msg = Buffer.concat([Buffer.from(licenseId, 'utf8'), SEP, Buffer.from(nonce, 'utf8'), SEP, Buffer.from(String(ts), 'utf8')])
  return { nonce, ts, mac: createHmac('sha256', key).update(msg).digest('base64url') }
}
```

`packages/dsh-sealed-skills/src/license-client.ts` 的 `proofFor()` 就是这段逻辑的参考实现。

## 5. 版本协商与兼容

三套版本号互相独立：

| 版本 | 载体 | 规则 |
|---|---|---|
| 协议 | 路径 `/v1` | 服务端只暴露已知 major；未知前缀 → `404` |
| license | payload 的 `v`（当前 `1`） | 客户端遇到**更高** `v` → 拒绝（`BAD_SERVER_LICENSE`） |
| pack | 容器 `format_version`（当前 `1`） | 客户端遇到**更高**版本 → 拒绝并提示升级 loader |

兼容原则：

1. **未知字段必须忽略**：`validate*` 只读取它认识的键，其余键原样丢弃，不报错。
2. **未知错误码必须容忍**：客户端把不认识的 `code` 折叠为 `SERVER_REJECTED`，不崩溃。
3. **未知条目 type 必须忽略**：不因单个条目类型不认识而让整包失败。
4. 新增能力优先走**可选字段**；破坏性变更才升 major。

## 6. 相关文件

- `packages/license-format/src/protocol.ts` —— 协议单一真源（常量、错误码、校验器）。
- `packages/license-format/src/token.ts` —— license 令牌格式与签验（§5.2）。
- `packages/license-server/src/routes.ts` —— 端点处理与错误映射的参考实现。
- `packages/license-server/src/bin.ts` —— 独立启动入口与环境变量。
- `docs/sealed-skills/guide/publish-and-license.md` —— 从部署到签发的完整操作指南。
