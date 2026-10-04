# 发布与授权指南（作者 / 运营）

本文覆盖 **M2 授权闭环**：部署授权服务器、登记 pack、签发 `purchase_token`、用户激活、
续期、吊销与席位管理。协议细节见 `docs/sealed-skills/spec/protocol.md`。

> 前置：已完成 `docs/sealed-skills/guide/author-quickstart.md` 的打包流程，手里有
> `translate.sealedpack`（密文包）、`translate.sealedpack.master.json`（master，服务端机密）
> 与 `author.key.json`（作者签名私钥）。

## 1. 授权服务器的角色

M1 的试用 license 由作者本机私钥签发，只能自己用。M2 起，**签发改由授权服务器完成**：

- 作者把 pack 的 **master key**（不是明文、不是整包）登记到服务器；
- 服务器在激活/续期时，按设备逐条目封装密钥并 Ed25519 签发 license；
- 用户只需持有**作者公钥**（验 pack 签名）与**服务器公钥**（验 license 签名）。

服务器是唯一的签发方，因此**必须由你（作者/运营方）自己托管**，而不是交给终端用户。

## 2. 部署服务器

### 2.1 前置

- Node ≥ 22.13.0（`license-server` 用到未加 flag 的 `node:sqlite`；其余包只需 Node ≥ 20）。
- 存储：`node:sqlite`（内置，零依赖）。

### 2.2 生成服务端密钥

三份密钥都是 **base64url 编码的 32 字节**，只放服务端，绝不随包分发：

```bash
node -e "
const { generateKeyPairSync, randomBytes } = require('node:crypto')
const b = (buf) => Buffer.from(buf).toString('base64url')
console.log('SEALED_SERVER_LICENSE_KEY=' + generateKeyPairSync('ed25519').privateKey.export({ format: 'jwk' }).d)
console.log('SEALED_SERVER_PROOF_KEY=' + generateKeyPairSync('x25519').privateKey.export({ format: 'jwk' }).d)
console.log('SEALED_SERVER_MASTER_KEY=' + b(randomBytes(32)))
"
```

| 变量 | 用途 |
|---|---|
| `SEALED_SERVER_LICENSE_KEY` | Ed25519 license 签名私钥 |
| `SEALED_SERVER_PROOF_KEY` | X25519 设备证明私钥（DH-MAC，见协议 §4） |
| `SEALED_SERVER_MASTER_KEY` | 加密静态存储各 pack 的 master key |
| `SEALED_SERVER_ADMIN_TOKEN` | 管理端点 bearer token（必填，否则拒绝启动） |
| `SEALED_SERVER_PORT` | 监听端口，默认 `8787` |
| `SEALED_SERVER_DB` | SQLite 路径，默认 `sealed-license-server.sqlite` |

### 2.3 启动

```bash
corepack pnpm -r build
SEALED_SERVER_ADMIN_TOKEN=... node packages/license-server/dist/bin.js
# sealed license server listening on 8787
```

`bin` 也注册为 `sealed-license-server`，全局安装后可直接调用。

### 2.4 把公钥交给客户端

作者/运营需要把**两份公钥**配置到用户侧 loader（都可用下面的片段打印）：

```bash
node --input-type=module -e "
import { loadServerKeys, serverLicensePublicB64 } from './packages/license-server/dist/index.js'
const keys = loadServerKeys(process.env)
console.log('trustedLicenseKeysB64:', serverLicensePublicB64(keys))
console.log('serverProofPubB64:', keys.proofPublicB64)
"
```

- `serverLicensePublicB64` → 客户端 `trustedLicenseKeysB64`（验 license 签名）。
- `keys.proofPublicB64` → 客户端 `serverProofPubB64`（renew 时做 DH-MAC）。
- 用户侧的**作者公钥**来自 `author.key.json` 的 `pub` 字段，用于验 pack manifest 签名。

## 3. 作者流程：从打包到可购买

```
seal keygen  →  seal pack  →  POST /v1/admin/packs  →  签发 purchase_token  →  交付
  作者私钥       密文包+master        登记 master（仅服务器）      计费系统            包+token
```

### 3.1 生成作者密钥并打包

```bash
node packages/seal-cli/dist/cli.js keygen -o author.key.json
node packages/seal-cli/dist/cli.js pack ./demo/translate -o translate.sealedpack \
  --pack-id com.example.translate --version 1.0.0 --label 翻译 \
  --key author.key.json --trial meta
```

`--trial meta` 表示试用只解锁 `meta`（技能名/描述/状态）；正文 `skill:translate:body` 需要购买。

### 3.2 登记 pack（只上传 master）

从 `.master.json` 读 master，从 `seal inspect` 读条目清单，POST 到管理端点。可在仓库根运行：

```bash
SEALED_SERVER_ADMIN_TOKEN=... node --input-type=module -e "
import { readFileSync } from 'node:fs'
import { inspectPack } from './packages/seal-cli/dist/pack.js'
import { parseMasterFile } from './packages/seal-cli/dist/master.js'
const pack = readFileSync('translate.sealedpack')
const manifest = inspectPack(pack).manifest
const master = parseMasterFile(readFileSync('translate.sealedpack.master.json', 'utf8'))
const authorPub = JSON.parse(readFileSync('author.key.json', 'utf8')).pub
const body = {
  pack: { id: manifest.pack_id, version: manifest.version },
  author_pub: authorPub,
  label: manifest.label,
  master_b64: master.master.toString('base64url'),
  trial_entries: manifest.entries.filter((e) => e.trial).map((e) => e.id),
  entries: manifest.entries.map((e) => ({ id: e.id, type: e.type, size: e.size })),
}
const res = await fetch(process.env.SEALED_SERVER_URL + '/v1/admin/packs', {
  method: 'POST',
  headers: { 'content-type': 'application/json', authorization: 'Bearer ' + process.env.SEALED_SERVER_ADMIN_TOKEN },
  body: JSON.stringify(body),
})
console.log(res.status, await res.text())
"
```

期望 `200 { "pack": { "id": "com.example.translate", "version": "1.0.0" }, "entries": 2 }`。
重复登记同一版本是幂等的；**改了内容必须升 `--version`**。

### 3.3 在计费系统里签发 `purchase_token`

`purchase_token` 是你自己计费系统的产物：买家付款后，为订单生成一个不透明 token，
调用 `Store.putPurchase({ token, sub, packId, version, plan, seats })` 写入服务器（或按你
现有系统的做法落库）。约定：

- `token` 全局唯一；未知 token → `401 BAD_PURCHASE_TOKEN`。
- `sub` 是客户/订阅标识，用于席位归集。
- `seats` 是该订单允许的设备数；同一 `sub` 用满 `seats` 后新设备 `409 SEAT_LIMIT`。
- `plan` 会成为 license 的 `groups`，便于将来按套餐差异化授权。
- `expiresAt`（可选，秒）用于让 token 本身过期。

### 3.4 交付

给买家交付两样东西：

1. `translate.sealedpack`（密文包，**所有客户共用同一份**）；
2. 一张订单对应的 `purchase_token`。

**绝不交付** `master.json`、`author.key.json` 或任何明文技能内容。

## 4. 用户流程

### 4.1 配置 loader

在 dsh 的 sealed-skills 插件配置里给出服务器地址、服务器公钥、作者公钥与挂载点：

```ts
{
  serverUrl: 'https://license.example.com',
  serverProofPubB64: '<服务器 proof 公钥 base64url>',
  trustedLicenseKeysB64: ['<服务器 license 签名公钥 base64url>'],
  keystoreDir: '$SEALED_HOME',           // 默认 $SEALED_HOME 或 <cwd>/.sealed-home
  mounts: [{ packPath: '/abs/path/translate.sealedpack', purchaseToken: '<订单 token>' }],
}
```

也可用环境变量 `SEALED_SERVER_URL` / `SEALED_SERVER_PROOF_PUB` / `SEALED_HOME` 代替
`serverUrl` / `serverProofPubB64` / `keystoreDir`。

### 4.2 首次激活与后续离线

1. 首次使用：`purchaseToken` → `POST /v1/activate` → 签发 license → 落
   `$SEALED_HOME/licenses/<lid>.license.json`；离线导入场景用 `licensePath` 直接给一份预置 license。
2. 之后：本地缓存有效期内直接解密（`source: 'cache'`），无需联网。
3. 剩余有效期不足 `RENEW_THRESHOLD_SECONDS`（2 天）时自动 `POST /v1/renew`（设备证明）。
4. 断网但未过 `exp`：继续可用；过了 `exp` 进入**宽限期**（3 天）；宽限期结束前仍未续上即停用
   （包与本地数据不删除）。
5. 系统时钟回拨超过 `MAX_CLOCK_SKEW_SECONDS`：判 `CLOCK_UNTRUSTED`，要求联网续期。

## 5. 续期、吊销与席位

| 机制 | 行为 |
|---|---|
| 续期 | 提前 2 天触发；TTL 每次顺延 7 天；nonce 一次性、时间戳 ±5 分钟 |
| 宽限 | `exp` 后 3 天仍可用；断网不写新 license、不推进时钟锚点 |
| 吊销 | 管理端点标记吊销并释放席位；客户端最迟在下次 `renew` 时收到 `403 REVOKED` 并删除缓存 |
| 席位 | `activate` 占用，`revoke` 释放；同一设备重复激活不重复占位 |
| 试用 | 每设备每 pack 一次；只解锁 `trial_entries`；购买后 `/v1/activate` 直接覆盖，无需重装 |

## 6. 安全清单（上线前逐条确认）

- [ ] `SEALED_SERVER_LICENSE_KEY` / `SEALED_SERVER_PROOF_KEY` / `SEALED_SERVER_MASTER_KEY`
      只存在服务端密钥管理系统；不进 git、不进镜像层、不下发客户端。
- [ ] `translate.sealedpack.master.json` 与 `author.key.json` 不随包分发、不入仓库。
- [ ] 管理端点（`/v1/revoke`、`/v1/admin/packs`）只在私网或带 mTLS/网关鉴权的入口暴露；
      当前实现先校验 bearer 再限流，**不要**把管理口直接暴露到公网。
- [ ] `SEALED_SERVER_ADMIN_TOKEN` 用高强度随机值，定期轮换。
- [ ] 审计表（`audit`）保留全部签发/续期/吊销记录，按合规要求留存。
- [ ] 日志与遥测只记录 license id、设备公钥哈希、端点、pack id/version、时间戳；
      **绝不**记录技能内容或任何密钥字节。
- [ ] 吊销后确认席位已释放（`Store.listAudit()` 能看到 `revoke` 记录）。
- [ ] 用户侧只需 `trustedLicenseKeysB64` + 作者 `pub`；若换服务器密钥，需同步更新用户配置。

## 7. 相关文档

- `docs/sealed-skills/spec/protocol.md` —— 协议参考（端点、错误码、设备证明公式）。
- `docs/sealed-skills/guide/author-quickstart.md` —— 从技能目录到密文包。
- `docs/sealed-skills/guide/for-skill-developers.md` —— 生态总览与参与方式。
- `packages/license-server/src/routes.ts` —— 端点实现的参考代码。
