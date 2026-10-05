# `license` v1 —— 公开线格式规范

本文件是 Sealed Skills 授权令牌（license）**v1** 的**公开规范**。任何第三方 loader 都可以只依据本文
（加上 `test-vectors/license-format.json`）完成**验签、设备绑定校验、逐条目密钥解封**，
**不需要**阅读本仓库的 loader 源码。

> **TEST-ONLY**：`test-vectors/` 中的签名种子、设备私钥、临时私钥与 nonce 仅用于复现向量，
> **绝不可用于生产**。参考实现：`packages/license-format`（Node.js，仅依赖 `node:crypto` 与 JCS）。

## 1. 约定

- 二进制一律用 **base64url**（无 padding）编码为字符串。
- JSON 规范化使用 **RFC 8785 (JCS)**；签名与比较都以规范化后的**精确字节**为准。
- 签名算法 **Ed25519**（原始 64 字节签名）。
- 密钥协商 **X25519**；KDF 为 **HKDF-SHA256**；封装加密为 **AES-256-GCM**（12 字节 nonce，
  16 字节 tag 追加在密文尾部）。
- 公钥字段都是 **32 字节裸公钥**的 base64url（43 字符）。

## 2. 令牌形状

license 是一个 **JSON 对象**（UTF-8 文本），规范形状：

```json
{ "payload": "<base64url(JCS(payload))>", "sig": "<base64url(Ed25519(UTF8(JCS(payload))))>" }
```

- `payload`：对 §3 的 payload 对象做 JCS 序列化后的字节，再 base64url。
- `sig`：用授权服务器 Ed25519 私钥对**同一串字节**签名（`Ed25519(null, bytes, priv)`）后 base64url。

注意：它是**两字段 JSON 信封**，不是 JWT 风格的 `<payload>.<sig>` 圆点拼接。读取器把它当 JSON
解析（`LICENSE_MALFORMED` 若解析失败或缺少任一字段）。

## 3. payload 字段

| 字段 | 类型 | 说明 |
|---|---|---|
| `v` | `1` | 格式版本。当前只接受 `1`。 |
| `lid` | string | license id（`lic_…`），同时作为封装 KDF 的 salt 与 AAD 的一部分。 |
| `sub` | string | 主体标识（`cust:…` / `trial:<device-prefix>`），用于席位与去重，不参与密码学。 |
| `pack` | object | `{ id, version, author_pub }`；`author_pub` 是**作者 Ed25519 公钥**（base64url），用于验证 `.sealedpack` 的 manifest 签名。 |
| `dev` | string | 被绑定设备的 **X25519 公钥**（base64url）。CLI 必须校验它等于本机设备公钥。 |
| `iat` | integer | 签发时间（Unix 秒）。 |
| `exp` | integer | 到期时间（Unix 秒）。`now < exp` 为 `active`。 |
| `grace_until` | integer | 宽限截止（Unix 秒）。`exp <= now < grace_until` 为 `grace`。 |
| `caps` | string[] | 能力标签，取值 `"trial"` \| `"full"`。参考实现：试用 `["trial"]`，购买 `["full"]`。 |
| `groups` | string[] | 作者/服务器自定义分组标签（参考实现放 `[plan]`），供策略使用，不参与密码学。 |
| `keys` | object[] | **逐条目封装的 CK**，见 §5。这是真正的授权载体：没有对应 `eid` 的解封密钥就解不开该条目。 |
| `seats` | object | `{ plan, limit }`，席位说明性字段，不参与密码学。 |

`keys` 中的每条记录（`LicenseGrant`）：

| 字段 | 类型 | 说明 |
|---|---|---|
| `eid` | string | 条目 id（与 `.sealedpack` manifest 中的 `entries[].id` 一致）。 |
| `eph` | string | 本次封装的一次性 X25519 临时公钥（base64url，32 字节）。 |
| `n` | string | AES-256-GCM 的 12 字节 nonce（base64url）。 |
| `c` | string | 封装密文 = `AES-256-GCM(kek, n, aad, CK)` 的结果再追加 16 字节 tag（base64url）。 |

## 4. 校验流程

1. **解析**：JSON → 取 `payload` / `sig`，base64url 解码 → 再 JSON 解析 payload。
   形状不符（缺字段、类型错、`v != 1`）→ `LICENSE_MALFORMED`。
2. **规范化断言**：把解析出的 payload 重新 JCS 序列化，必须与解码出的 `payload` 字节**逐字节相等**；
   否则 → `LICENSE_NOT_CANONICAL`。（防止“改写 payload 但复用签名”的歧义表示。）
3. **验签**：`Ed25519.verify(trustedServerKeys, payloadBytes, sig)`；任一受信密钥通过即可。
   否则 → `LICENSE_BAD_SIGNATURE`。
4. **设备绑定**：`payload.dev` 必须等于本机设备 X25519 公钥；不等则视为不可用于本机。
5. **有效期**：按 §6 计算状态；`expired` 拒绝使用。
6. **逐条目解封**：对请求的 `eid` 调用 §5；无 `eid` 记录 → `LICENSE_NO_GRANT`，
   解封失败（tag 校验不过）→ `LICENSE_UNWRAP_FAILED`。

顺序建议 **fail-closed**：先验签再解封；任何一步失败都不得回退到“跳过授权”。

## 5. 逐条目 CK 封装

授权服务器为每个被授权条目生成一个 32 字节内容密钥 `CK`（与该条目在 pack 中的派生密钥一致，
见 `spec/pack-format.md` §5），并只用**被绑定设备**能解开的方式封装：

```
ss   = X25519(eph_priv, dev_pub)                      # 一次性临时私钥 × 设备公钥
kek  = HKDF-SHA256(key = ss, salt = lid, info = "wrap:" || eid, L = 32)
AAD  = lid || 0x00 || eid                             # UTF-8，0x00 为单字节分隔符
nonce= 12 字节随机（每条目一次）
c    = AES-256-GCM(kek, iv = nonce, aad = AAD, CK) || 16 字节 tag
```

解封（设备侧）：

```
ss   = X25519(dev_priv, eph_pub)                      # eph_pub = base64url 解码 grant.eph
kek  = HKDF-SHA256(key = ss, salt = lid, info = "wrap:" || eid, L = 32)
CK   = AES-256-GCM-open(kek, grant.n, AAD = lid || 0x00 || eid, grant.c)
```

换设备后 `dev_priv` 不同 → `ss` 不同 → `kek` 不同 → GCM tag 校验失败 → `LICENSE_UNWRAP_FAILED`，
即**设备绑定**由密码学保证，而不是靠字段检查。

## 6. 状态机

`licenseStatus(payload, now)`（`now` 为 Unix 秒）：

| 条件 | 状态 | 行为 |
|---|---|---|
| `now < exp` | `active` | 正常解密使用。 |
| `exp <= now < grace_until` | `grace` | 断网宽限期内继续使用；客户端应尝试续期。 |
| `now >= grace_until` | `expired` | 拒绝使用（`LICENSE_EXPIRED`）。 |

- 服务器签发：`grace_until = exp + LICENSE_GRACE_SECONDS`（3 天），`exp = iat + LICENSE_TTL_SECONDS`（7 天）。
- **时钟回拨**：客户端持久化“上次见到的最大时间”，若本机时间早于该值超过 `MAX_CLOCK_SKEW_SECONDS`（300 秒），
  视为可疑并收紧（不得借此延长 `grace`）。回拨检测属于客户端策略，不是线格式的一部分。

## 7. 错误码

| 码 | 触发 |
|---|---|
| `LICENSE_MALFORMED` | 非 JSON / 缺 `payload`、`sig` / payload 形状非法 |
| `LICENSE_NOT_CANONICAL` | 重新 JCS 后与令牌内字节不一致 |
| `LICENSE_BAD_SIGNATURE` | 无任一受信服务器密钥验证通过 |
| `LICENSE_NO_GRANT` | license 中无该 `eid` 的封装记录 |
| `LICENSE_UNWRAP_FAILED` | ECDH/HKDF/AES-GCM 解封失败（含换机、篡改） |

客户端上层的 `LICENSE_EXPIRED`（过期）与 `NOT_GRANTED`（该条目未授权）是**策略层**错误，
不改变线格式。

## 8. Golden vectors

`test-vectors/license-format.json` 固定了签名种子、设备 X25519 私钥、临时私钥、`lid`/`eid`、
`CK` 与 nonce，给出：

- `expected_grant`：可复现的封装记录（`eph` / `n` / `c`）；
- `expected_token`：**完整可复现的 license 令牌**（Ed25519 确定性签名）；
- `payload`：对应的 payload 对象。

`packages/license-format/test/vectors.test.ts` 用参考实现复算并断言：封装结果、解封回 `CK`、
令牌逐字节相等、验签通过，以及**篡改一个签名字节 / 换一把未受信密钥必须失败**。
生成脚本：`test-vectors/generate.mjs`（TEST-ONLY）。

> **复现封装需要固定临时私钥与 nonce**，因此参考实现提供了一个**非生产**注入参数
> `WrapEntryKeySeam`（`wrapEntryKey(payload, eid, ck, devPub, { ephemeralPrivateKey, nonce })`）。
> 生产路径不传该参数，临时密钥与 nonce 仍由 CSPRNG 生成；它**不改变线格式**。

## 9. 版本与兼容

- 版本字段为 `v`，当前 `1`。读取器遇到 `v > 1` 应拒绝并要求升级。
- **未知字段必须忽略**（payload 顶层未知键、`keys[]` 记录未知键、`seats` 未知键）。
- 追加字段（如未来的 `alg`）应保持可选，且不得改变 `v`。