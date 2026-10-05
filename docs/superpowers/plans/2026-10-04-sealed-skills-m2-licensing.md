# Sealed Skills M2（授权闭环）Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 把 M1 的「本地自签试用」升级为真正的授权闭环：作者把 pack 与 master 登记到授权服务器，用户在**自己的**运行时里在线激活/续期，客户端用 OS 密钥库保护设备私钥，断网时在宽限期内可继续使用，吊销在 TTL 内生效。

**Architecture:** 三个可独立测试的部件 + 一份共享契约。`@sealed/license-format/src/protocol.ts` 定义 HTTP 端点、请求/响应、错误码与设备证明算法（服务端与客户端共用，消除协议漂移）；`packages/license-server` 是无第三方依赖的 `node:http` + `node:sqlite` 服务，负责席位、吊销、审计与逐条目 CK 封装；`dsh-sealed-skills` 新增 `license-client` 模块（设备证明、激活、续期、状态机、时钟回拨检测）与可替换的 OS 密钥库后端。服务端与客户端各自都能在被测服务器/假服务器上端到端跑通。

**Tech Stack:** TypeScript（ESM / NodeNext）、Node 内置 `crypto`、`node:http`、`node:sqlite`（Node ≥ 22.5）、vitest、pnpm（corepack）。**不引入任何第三方运行时依赖**（含 HTTP 框架与 SQLite 驱动）。

**Spec:** `docs/superpowers/specs/2026-10-04-sealed-skills-design.md`（本计划实现 §6.3/§6.4/§7.2/§7.4/§7.5/§7.6/§8/§9）

## Global Constraints

- Node ≥ 22.5（`license-server` 依赖 `node:sqlite`；其余包维持 Node ≥ 20 下限，仅服务端写进 `engines`）。
- 包管理器 pnpm，命令统一写 `corepack pnpm <cmd>`；TS ESM，`moduleResolution: NodeNext`，`strict: true`。
- 密码学只用 Node 内置 `crypto`：X25519、HKDF-SHA256、AES-256-GCM、Ed25519、HMAC-SHA256。服务端不得引入第三方加密库。
- 许可时长/TTL 常量（`license-format/src/protocol.ts`）：`LICENSE_TTL_SECONDS = 604800`（7d）、`LICENSE_GRACE_SECONDS = 259200`（3d）、`RENEW_THRESHOLD_SECONDS = 172800`（2d）、`MAX_CLOCK_SKEW_SECONDS = 300`、`NONCE_TTL_SECONDS = 600`。
- **设备证明 = DH-MAC，不是签名。** spec §7.4 写的是 `sig(设备私钥, nonce||ts)`，但设备私钥是 X25519，X25519 不能签名。实现为：`ss = ECDH(device_priv, server_proof_pub)`；`key = HKDF-SHA256(ss, salt = utf8(license_id), info = utf8("device-proof:"), 32)`；`mac = HMAC-SHA256(key, utf8(license_id)||0x00||utf8(nonce)||0x00||utf8(String(ts)))`。客户端的 `server_proof_pub` 固定预置，因此服务端也是被认证的一方。
- license 令牌沿用 M1 格式（`v = 1`，JCS 规范化，Ed25519），`pack.author_pub` 自 M2 起**必须是真实的作者 Ed25519 公钥**（M1 的设备公钥占位符在本里程碑移除）。
- 本地路径：设备密钥 `$SEALED_HOME/device.json`（沿用 M1）；license 落 `$SEALED_HOME/licenses/<lid>.license.json`；时钟状态 `$SEALED_HOME/clock.json`。
- 明文禁令不变：磁盘上不得出现明文技能正文/脚本；错误消息、日志、遥测、审计不得携带技能内容或任何密钥字节（含 CK、master、设备私钥）。服务端遥测只允许 license id、设备公钥哈希、时间戳、端点、pack id/version。
- 管理接口必须 `Authorization: Bearer <token>`；全部签发/吊销写入 `audit` 表。
- 不变量：磁盘上不得出现明文长期设备私钥，除非显式 `--allow-file-keystore`（此时 0600 + 机器派生密钥包装，且文档标注安全等级下降）。

## Review Focus

1. **断网/超时/5xx 不得让宽限期内的已授权用户不可用**（可用性 fail-open），同时不得因此放行未授权内容（授权 fail-closed）——重试退避、状态机、以及"网络失败不改状态"的测试必须钉死。
2. **续期重放与时间回拨**：同一 `(license_id, nonce)` 重放、`ts` 超出 ±300s 窗口、本机时钟回拨超阈值，都必须被拒且不产生可用的新 license。
3. **席位与吊销竞态**：并发激活同一席位不超卖；吊销后 TTL 内仍可用、renew 返回 403、到期后停用、席位被释放并可重新使用。
4. **密钥库不可用/被锁/被篡改**（DPAPI blob 损坏、Keychain 条目缺失、`secret-tool` 未安装、`device.json` 被改）：必须 fail-closed 或明确降级（只读发现），绝不静默使用坏密钥，绝不把长期私钥明文落盘。
5. **服务端输入对抗**：畸形/超长/未知字段的请求体、伪造 `device_pub`、未知 pack，必须返回结构化错误码（4xx），不 500、不泄漏内部细节、不无限增长内存。
6. **author_pub 绑定**：license 的 `pack.author_pub` 与包 manifest 的实际签名键不一致时必须拒绝（`PACK_SIGNATURE`），而不是信任调用方传入的公钥。

---

### Task 1: 共享 HTTP 契约与设备证明（`@sealed/license-format`）

**Files:**
- Create: `packages/license-format/src/protocol.ts`
- Modify: `packages/license-format/src/index.ts`（追加 `export * from './protocol.js'`）
- Test: `packages/license-format/test/protocol.test.ts`

**Interfaces:**
- Consumes: `b64u` / `unb64u`（`./b64.js`）、`x25519PublicFromRaw`（`./x25519.js`）。
- Produces:
  - `PROTOCOL_VERSION = 1`；`ENDPOINTS = { health, trial, activate, renew, revoke, publishPack }`
  - 常量：`LICENSE_TTL_SECONDS` / `LICENSE_GRACE_SECONDS` / `RENEW_THRESHOLD_SECONDS` / `MAX_CLOCK_SKEW_SECONDS` / `NONCE_TTL_SECONDS`
  - `interface PackRef { id: string; version: string }`
  - `interface TrialRequest { device_pub: string; pack: PackRef }`；`ActivateRequest { device_pub: string; purchase_token: string; pack: PackRef }`
  - `interface RenewRequest { license_id: string; device_pub: string; nonce: string; ts: number; mac: string }`
  - `interface RevokeRequest { license_id?: string; device_pub?: string; seat?: string }`
  - `interface PublishPackRequest { pack: PackRef; author_pub: string; label: string; master_b64: string; trial_entries: string[]; entries: { id: string; type: string; size: number }[] }`
  - `type ProtocolErrorCode = 'BAD_REQUEST' | 'PACK_NOT_FOUND' | 'TRIAL_ALREADY_USED' | 'BAD_PURCHASE_TOKEN' | 'SEAT_LIMIT' | 'UNKNOWN_LICENSE' | 'BAD_DEVICE_PROOF' | 'REPLAY' | 'REVOKED' | 'RATE_LIMITED' | 'UNAUTHORIZED' | 'INTERNAL'`
  - `class ProtocolRequestError extends Error { readonly code: ProtocolErrorCode }`
  - `interface LicenseEnvelope { license: string }`；`interface HealthEnvelope { ok: true; version: string }`；`interface ErrorEnvelope { error: { code: ProtocolErrorCode; message: string } }`
  - `isRawEd25519Pub(s: string): boolean`、`isRawX25519Pub(s: string): boolean`（都是 43 字符 base64url）
  - `deviceProofKey(sharedSecret: Buffer, licenseId: string): Buffer`、`deviceProofMessage(licenseId: string, nonce: string, ts: number): Buffer`、`deviceProofMac(key: Buffer, message: Buffer): string`
  - `validatePackRef(v: unknown): PackRef`、`validateTrialRequest(v: unknown): TrialRequest`、`validateActivateRequest(v: unknown): ActivateRequest`、`validateRenewRequest(v: unknown): RenewRequest`、`validatePublishPackRequest(v: unknown): PublishPackRequest`（失败一律抛 `ProtocolRequestError('BAD_REQUEST', …)`）
  - `parseErrorEnvelope(v: unknown): { code: ProtocolErrorCode; message: string } | undefined`

- [ ] **Step 1: 写失败测试**

`packages/license-format/test/protocol.test.ts`：
```ts
import { diffieHellman, generateKeyPairSync } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import {
  deviceProofKey, deviceProofMac, deviceProofMessage, isRawX25519Pub,
  parseErrorEnvelope, validateActivateRequest, validateRenewRequest, validateTrialRequest,
  rawPublicBytes, x25519PrivateFromRaw, x25519PublicFromRaw, ProtocolRequestError,
} from '../src/index.js'

describe('protocol validators', () => {
  it('accepts a well-formed trial request and rejects junk', () => {
    const ok = { device_pub: 'A'.repeat(43), pack: { id: 'com.example.p', version: '1.0.0' } }
    expect(validateTrialRequest(ok)).toEqual(ok)
    expect(() => validateTrialRequest(null)).toThrow(ProtocolRequestError)
    expect(() => validateTrialRequest({ ...ok, device_pub: 'short' })).toThrow('BAD_REQUEST')
    expect(() => validateTrialRequest({ ...ok, pack: { id: '', version: '1.0.0' } })).toThrow('BAD_REQUEST')
    expect(() => validateTrialRequest({ ...ok, extra: 1 })).not.toThrow()
  })

  it('accepts an activate request and a renew request', () => {
    expect(validateActivateRequest({ device_pub: 'A'.repeat(43), purchase_token: 't', pack: { id: 'p', version: '1' } }).purchase_token).toBe('t')
    const renew = { license_id: 'lic_1', device_pub: 'A'.repeat(43), nonce: 'n', ts: 1_700_000_000, mac: 'm' }
    expect(validateRenewRequest(renew)).toEqual(renew)
    expect(() => validateRenewRequest({ ...renew, ts: 'now' })).toThrow('BAD_REQUEST')
  })
})

describe('device proof (DH-MAC)', () => {
  it('both sides derive the same key and the server-side mac matches', () => {
    const device = generateKeyPairSync('x25519')
    const server = generateKeyPairSync('x25519')
    const devicePub = rawPublicBytes(device.publicKey)
    const clientShared = diffieHellman({ privateKey: device.privateKey, publicKey: server.publicKey })
    const serverShared = diffieHellman({ privateKey: server.privateKey, publicKey: x25519PublicFromRaw(devicePub) })
    const msg = deviceProofMessage('lic_1', 'nonce-1', 1_700_000_000)
    const clientMac = deviceProofMac(deviceProofKey(clientShared, 'lic_1'), msg)
    const serverMac = deviceProofMac(deviceProofKey(serverShared, 'lic_1'), msg)
    expect(clientMac).toBe(serverMac)
    expect(clientMac).toMatch(/^[A-Za-z0-9_-]+$/)
  })

  it('a different license id or nonce yields a different mac', () => {
    const key = Buffer.alloc(32, 7)
    expect(deviceProofMac(key, deviceProofMessage('a', 'n', 1))).not.toBe(deviceProofMac(key, deviceProofMessage('b', 'n', 1)))
    expect(deviceProofMac(key, deviceProofMessage('a', 'n', 1))).not.toBe(deviceProofMac(key, deviceProofMessage('a', 'm', 1)))
  })
})

describe('helpers', () => {
  it('recognises raw 32-byte base64url keys and error envelopes', () => {
    expect(isRawX25519Pub('A'.repeat(43))).toBe(true)
    expect(isRawX25519Pub('A'.repeat(42))).toBe(false)
    expect(parseErrorEnvelope({ error: { code: 'REPLAY', message: 'x' } })).toEqual({ code: 'REPLAY', message: 'x' })
    expect(parseErrorEnvelope({ error: { code: 'NOPE' } })).toBeUndefined()
    expect(parseErrorEnvelope('boom')).toBeUndefined()
  })
})
```

- [ ] **Step 2: 运行测试确认失败**

Run: `corepack pnpm -C packages/license-format test`
Expected: FAIL —— `../src/protocol.js` 不存在（`Does the file exist?`）。

- [ ] **Step 3: 实现**

`packages/license-format/src/protocol.ts`：
```ts
import { createHmac, hkdfSync, type KeyObject } from 'node:crypto'
import { b64u, unb64u } from './b64.js'
import { x25519PublicFromRaw } from './x25519.js'

export const PROTOCOL_VERSION = 1

export const ENDPOINTS = {
  health: '/v1/health',
  trial: '/v1/trial',
  activate: '/v1/activate',
  renew: '/v1/renew',
  revoke: '/v1/revoke',
  publishPack: '/v1/admin/packs',
} as const

export const LICENSE_TTL_SECONDS = 604800 // 7d
export const LICENSE_GRACE_SECONDS = 259200 // 3d
export const RENEW_THRESHOLD_SECONDS = 172800 // 2d
export const MAX_CLOCK_SKEW_SECONDS = 300
export const NONCE_TTL_SECONDS = 600

export interface PackRef { id: string; version: string }
export interface TrialRequest { device_pub: string; pack: PackRef }
export interface ActivateRequest { device_pub: string; purchase_token: string; pack: PackRef }
export interface RenewRequest { license_id: string; device_pub: string; nonce: string; ts: number; mac: string }
export interface RevokeRequest { license_id?: string; device_pub?: string; seat?: string }
export interface PublishPackRequest {
  pack: PackRef
  author_pub: string
  label: string
  master_b64: string
  trial_entries: string[]
  entries: { id: string; type: string; size: number }[]
}

export type ProtocolErrorCode =
  | 'BAD_REQUEST' | 'PACK_NOT_FOUND' | 'TRIAL_ALREADY_USED' | 'BAD_PURCHASE_TOKEN'
  | 'SEAT_LIMIT' | 'UNKNOWN_LICENSE' | 'BAD_DEVICE_PROOF' | 'REPLAY' | 'REVOKED'
  | 'RATE_LIMITED' | 'UNAUTHORIZED' | 'INTERNAL'

export class ProtocolRequestError extends Error {
  readonly code: ProtocolErrorCode
  constructor(code: ProtocolErrorCode, message: string) {
    super(message)
    this.name = 'ProtocolRequestError'
    this.code = code
  }
}

export interface LicenseEnvelope { license: string }
export interface HealthEnvelope { ok: true; version: string }
export interface ErrorEnvelope { error: { code: ProtocolErrorCode; message: string } }

const B64URL_32 = /^[A-Za-z0-9_-]{43}$/

export function isRawX25519Pub(value: unknown): boolean {
  if (typeof value !== 'string' || !B64URL_32.test(value)) return false
  return unb64u(value).length === 32
}

export function isRawEd25519Pub(value: unknown): boolean {
  return isRawX25519Pub(value)
}

function bad(message: string): never {
  throw new ProtocolRequestError('BAD_REQUEST', message)
}

function requireObject(value: unknown, what: string): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) bad(what + ' must be an object')
  return value as Record<string, unknown>
}

function requireString(value: unknown, what: string): string {
  if (typeof value !== 'string' || value.length === 0) bad(what + ' must be a non-empty string')
  return value
}

function requireDevicePub(value: unknown): string {
  if (!isRawX25519Pub(value)) bad('device_pub must be 32 raw bytes encoded as base64url')
  return value as string
}

export function validatePackRef(value: unknown): PackRef {
  const obj = requireObject(value, 'pack')
  return { id: requireString(obj.id, 'pack.id'), version: requireString(obj.version, 'pack.version') }
}

export function validateTrialRequest(value: unknown): TrialRequest {
  const obj = requireObject(value, 'trial request')
  return { device_pub: requireDevicePub(obj.device_pub), pack: validatePackRef(obj.pack) }
}

export function validateActivateRequest(value: unknown): ActivateRequest {
  const obj = requireObject(value, 'activate request')
  return {
    device_pub: requireDevicePub(obj.device_pub),
    purchase_token: requireString(obj.purchase_token, 'purchase_token'),
    pack: validatePackRef(obj.pack),
  }
}

export function validateRenewRequest(value: unknown): RenewRequest {
  const obj = requireObject(value, 'renew request')
  if (typeof obj.ts !== 'number' || !Number.isInteger(obj.ts)) bad('ts must be an integer unix timestamp in seconds')
  return {
    license_id: requireString(obj.license_id, 'license_id'),
    device_pub: requireDevicePub(obj.device_pub),
    nonce: requireString(obj.nonce, 'nonce'),
    ts: obj.ts,
    mac: requireString(obj.mac, 'mac'),
  }
}

export function validatePublishPackRequest(value: unknown): PublishPackRequest {
  const obj = requireObject(value, 'publish request')
  if (typeof obj.author_pub !== 'string' || !isRawEd25519Pub(obj.author_pub)) bad('author_pub must be 32 raw bytes encoded as base64url')
  if (typeof obj.master_b64 !== 'string' || unb64u(obj.master_b64).length !== 32) bad('master_b64 must be 32 raw bytes encoded as base64url')
  if (!Array.isArray(obj.trial_entries) || !obj.trial_entries.every((id) => typeof id === 'string')) bad('trial_entries must be a string array')
  if (!Array.isArray(obj.entries)) bad('entries must be an array')
  const entries = obj.entries.map((raw) => {
    const entry = requireObject(raw, 'entries[]')
    if (typeof entry.size !== 'number' || !Number.isInteger(entry.size) || entry.size < 0) bad('entries[].size must be a non-negative integer')
    return { id: requireString(entry.id, 'entries[].id'), type: requireString(entry.type, 'entries[].type'), size: entry.size }
  })
  return {
    pack: validatePackRef(obj.pack),
    author_pub: obj.author_pub,
    label: requireString(obj.label, 'label'),
    master_b64: obj.master_b64,
    trial_entries: obj.trial_entries as string[],
    entries,
  }
}

function requireObjectShape(value: unknown): Record<string, unknown> | undefined {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return undefined
  return value as Record<string, unknown>
}

export function parseErrorEnvelope(value: unknown): { code: ProtocolErrorCode; message: string } | undefined {
  const root = requireObjectShape(value)
  if (!root) return undefined
  const error = requireObjectShape(root.error)
  if (!error) return undefined
  if (typeof error.code !== 'string' || typeof error.message !== 'string') return undefined
  return { code: error.code as ProtocolErrorCode, message: error.message }
}

const SEP = Buffer.from([0])

export function deviceProofMessage(licenseId: string, nonce: string, ts: number): Buffer {
  return Buffer.concat([Buffer.from(licenseId, 'utf8'), SEP, Buffer.from(nonce, 'utf8'), SEP, Buffer.from(String(ts), 'utf8')])
}

export function deviceProofKey(sharedSecret: Buffer, licenseId: string): Buffer {
  return Buffer.from(hkdfSync('sha256', sharedSecret, Buffer.from(licenseId, 'utf8'), Buffer.from('device-proof:', 'utf8'), 32))
}

export function deviceProofMac(key: Buffer, message: Buffer): string {
  return b64u(createHmac('sha256', key).update(message).digest())
}

/** 服务端设备证明公钥的固定预置形式：43 字符 base64url。 */
export function deviceProofPublicFromRaw(raw: Buffer): KeyObject {
  return x25519PublicFromRaw(raw)
}
```

`packages/license-format/src/index.ts`：在文件末尾追加一行
```ts
export * from './protocol.js'
```

- [ ] **Step 4: 运行测试确认通过**

Run: `corepack pnpm -C packages/license-format test`
Expected: PASS（8 files…实际为 3 个测试文件、19 passed；以套件输出为准）。

- [ ] **Step 5: 提交**

```bash
git add packages/license-format
git commit -m "feat(license-format): add shared HTTP contract and device-proof mac"
```
---

### Task 2: `@sealed/license-server` 骨架与 SQLite 存储层

**Files:**
- Create: `packages/license-server/{package.json,tsconfig.json,vitest.config.ts}`
- Create: `packages/license-server/src/{store.ts,server-errors.ts,index.ts}`
- Test: `packages/license-server/test/store.test.ts`

**Interfaces:**
- Consumes: `ProtocolErrorCode`（Task 1）。
- Produces:
  - `class ServerError extends Error { constructor(readonly code: ProtocolErrorCode, message: string) }`
  - `interface PackRecord { packId: string; version: string; label: string; authorPub: string; masterWrapped: string; trialEntries: string[]; entries: { id: string; type: string; size: number }[] }`
  - `interface LicenseRecord { licenseId: string; sub: string; packId: string; version: string; devicePub: string; caps: string[]; plan: string; seatLimit: number; iat: number; exp: number; graceUntil: number; revoked: boolean }`
  - `interface PurchaseRecord { token: string; sub: string; packId: string; version: string; plan: string; seats: number; expiresAt?: number }`
  - `openStore(path: string): Store`（`path` 为 `':memory:'` 或文件路径）
  - `class Store`：`close()`、`putPack/getPack`、`putPurchase/getPurchase`、`upsertDevice`、`countSeats/putSeat/deleteSeatsForSubject/deleteSeat`、`putLicense/getLicense/getLicenseForDevice/markRevoked`、`getTrial/putTrial`、`insertNonce/pruneNonces`、`appendAudit/listAudit`、`putIdempotent/getIdempotent`

- [ ] **Step 1: 包配置**

`packages/license-server/package.json`：
```json
{
  "name": "@sealed/license-server",
  "version": "0.1.0",
  "type": "module",
  "main": "dist/index.js",
  "types": "dist/index.d.ts",
  "engines": { "node": ">=22.5" },
  "scripts": { "build": "tsc -p tsconfig.json", "test": "vitest run" },
  "dependencies": {
    "@sealed/canonical-json": "workspace:*",
    "@sealed/license-format": "workspace:*",
    "@sealed/pack-format": "workspace:*"
  }
}
```

`packages/license-server/tsconfig.json`（与其它包一致）：`{ "extends": "../../tsconfig.base.json", "compilerOptions": { "outDir": "dist", "rootDir": "src" }, "include": ["src"] }`

`packages/license-server/vitest.config.ts`（与其它包一致）：`import { defineConfig } from 'vitest/config'\nexport default defineConfig({ test: { environment: 'node' } })`

- [ ] **Step 2: 写失败测试**

`packages/license-server/test/store.test.ts`：
```ts
import { describe, expect, it } from 'vitest'
import { openStore, ServerError } from '../src/index.js'

function store() { return openStore(':memory:') }

describe('Store', () => {
  it('round-trips a pack record', () => {
    const s = store()
    s.putPack({ packId: 'com.example.p', version: '1.0.0', label: '翻译', authorPub: 'A'.repeat(43), masterWrapped: 'wrapped', trialEntries: ['meta'], entries: [{ id: 'meta', type: 'meta', size: 10 }] })
    expect(s.getPack('com.example.p', '1.0.0')?.label).toBe('翻译')
    expect(s.getPack('com.example.p', '1.0.0')?.trialEntries).toEqual(['meta'])
    expect(s.getPack('com.example.p', '2.0.0')).toBeUndefined()
    s.close()
  })

  it('treats a repeated trial as a conflict', () => {
    const s = store()
    s.putTrial('dev1', 'p', '1', 'lic_t1')
    expect(() => s.putTrial('dev1', 'p', '1', 'lic_t2')).toThrow(ServerError)
    expect(s.getTrial('dev1', 'p', '1')?.licenseId).toBe('lic_t1')
    s.close()
  })

  it('reports a replayed nonce as a conflict', () => {
    const s = store()
    expect(s.insertNonce('lic_1', 'n1', 1000)).toBe(true)
    expect(s.insertNonce('lic_1', 'n1', 1001)).toBe(false)
    expect(s.insertNonce('lic_1', 'n2', 1002)).toBe(true)
    s.close()
  })

  it('counts seats per subject+pack and releases them', () => {
    const s = store()
    s.putSeat({ sub: 'cust', packId: 'p', version: '1', devicePub: 'd1', licenseId: 'l1' })
    s.putSeat({ sub: 'cust', packId: 'p', version: '1', devicePub: 'd2', licenseId: 'l2' })
    s.putSeat({ sub: 'other', packId: 'p', version: '1', devicePub: 'd3', licenseId: 'l3' })
    expect(s.countSeats('cust', 'p', '1')).toBe(2)
    s.deleteSeat('cust', 'p', '1', 'd1')
    expect(s.countSeats('cust', 'p', '1')).toBe(1)
    s.deleteSeatsForSubject('cust')
    expect(s.countSeats('cust', 'p', '1')).toBe(0)
    s.close()
  })

  it('stores licenses and flips the revoked flag', () => {
    const s = store()
    s.putLicense({ licenseId: 'l1', sub: 'cust', packId: 'p', version: '1', devicePub: 'd1', caps: ['full'], plan: 'pro', seatLimit: 2, iat: 1, exp: 2, graceUntil: 3, revoked: false })
    expect(s.getLicenseForDevice('p', '1', 'd1')?.licenseId).toBe('l1')
    s.markRevoked('l1')
    expect(s.getLicense('l1')?.revoked).toBe(true)
    expect(s.getLicenseForDevice('p', '1', 'd1')).toBeUndefined()
    s.close()
  })

  it('appends audit entries and expires nonces', () => {
    const s = store()
    s.appendAudit({ at: 5, action: 'activate', actor: 'server', subject: 'l1', detail: 'ok' })
    s.insertNonce('l1', 'old', 1)
    s.pruneNonces(0, 999)
    expect(s.listAudit().length).toBe(1)
    expect(s.insertNonce('l1', 'old', 1000)).toBe(true)
    s.close()
  })
})
```

- [ ] **Step 3: 运行测试确认失败**

Run: `corepack pnpm -C packages/license-server test`
Expected: FAIL —— `../src/index.js` 不存在。

- [ ] **Step 4: 实现**

`packages/license-server/src/server-errors.ts`：
```ts
import type { ProtocolErrorCode } from '@sealed/license-format'

export class ServerError extends Error {
  constructor(readonly code: ProtocolErrorCode, message: string) {
    super(message)
    this.name = 'ServerError'
  }
}
```

`packages/license-server/src/store.ts`：
```ts
import { DatabaseSync } from 'node:sqlite'
import { ServerError } from './server-errors.js'

export interface PackRecord {
  packId: string; version: string; label: string; authorPub: string
  masterWrapped: string; trialEntries: string[]; entries: { id: string; type: string; size: number }[]
}
export interface LicenseRecord {
  licenseId: string; sub: string; packId: string; version: string; devicePub: string
  caps: string[]; plan: string; seatLimit: number; iat: number; exp: number; graceUntil: number; revoked: boolean
}
export interface PurchaseRecord { token: string; sub: string; packId: string; version: string; plan: string; seats: number; expiresAt?: number }
export interface SeatRecord { sub: string; packId: string; version: string; devicePub: string; licenseId: string }
export interface AuditRecord { at: number; action: string; actor: string; subject: string; detail: string }

const SCHEMA = `
CREATE TABLE IF NOT EXISTS packs (
  pack_id TEXT NOT NULL, version TEXT NOT NULL, label TEXT NOT NULL, author_pub TEXT NOT NULL,
  master_wrapped TEXT NOT NULL, trial_entries TEXT NOT NULL, entries TEXT NOT NULL,
  created_at INTEGER NOT NULL, PRIMARY KEY (pack_id, version));
CREATE TABLE IF NOT EXISTS purchases (
  token TEXT PRIMARY KEY, sub TEXT NOT NULL, pack_id TEXT NOT NULL, version TEXT NOT NULL,
  plan TEXT NOT NULL, seats INTEGER NOT NULL, expires_at INTEGER);
CREATE TABLE IF NOT EXISTS devices (
  device_pub TEXT PRIMARY KEY, sub TEXT NOT NULL, created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS seats (
  sub TEXT NOT NULL, pack_id TEXT NOT NULL, version TEXT NOT NULL, device_pub TEXT NOT NULL,
  license_id TEXT NOT NULL, created_at INTEGER NOT NULL,
  PRIMARY KEY (sub, pack_id, version, device_pub));
CREATE TABLE IF NOT EXISTS licenses (
  license_id TEXT PRIMARY KEY, sub TEXT NOT NULL, pack_id TEXT NOT NULL, version TEXT NOT NULL,
  device_pub TEXT NOT NULL, caps TEXT NOT NULL, plan TEXT NOT NULL, seat_limit INTEGER NOT NULL,
  iat INTEGER NOT NULL, exp INTEGER NOT NULL, grace_until INTEGER NOT NULL,
  revoked INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS trials (
  device_pub TEXT NOT NULL, pack_id TEXT NOT NULL, version TEXT NOT NULL, license_id TEXT NOT NULL,
  created_at INTEGER NOT NULL, PRIMARY KEY (device_pub, pack_id, version));
CREATE TABLE IF NOT EXISTS nonces (
  license_id TEXT NOT NULL, nonce TEXT NOT NULL, seen_at INTEGER NOT NULL,
  PRIMARY KEY (license_id, nonce));
CREATE TABLE IF NOT EXISTS audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT, at INTEGER NOT NULL, action TEXT NOT NULL,
  actor TEXT NOT NULL, subject TEXT NOT NULL, detail TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS idempotency (
  key TEXT PRIMARY KEY, response TEXT NOT NULL, created_at INTEGER NOT NULL);
`

interface PackDbRow { pack_id: string; version: string; label: string; author_pub: string; master_wrapped: string; trial_entries: string; entries: string }
interface LicenseDbRow {
  license_id: string; sub: string; pack_id: string; version: string; device_pub: string
  caps: string; plan: string; seat_limit: number; iat: number; exp: number; grace_until: number; revoked: number
}

export class Store {
  private readonly db: DatabaseSync
  constructor(path: string) {
    this.db = new DatabaseSync(path)
    this.db.exec(SCHEMA)
  }

  close(): void { this.db.close() }

  putPack(record: PackRecord, now = Date.now()): void {
    this.db.prepare(
      `INSERT INTO packs (pack_id, version, label, author_pub, master_wrapped, trial_entries, entries, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(pack_id, version) DO UPDATE SET label=excluded.label, author_pub=excluded.author_pub,
         master_wrapped=excluded.master_wrapped, trial_entries=excluded.trial_entries, entries=excluded.entries`,
    ).run(record.packId, record.version, record.label, record.authorPub, record.masterWrapped,
      JSON.stringify(record.trialEntries), JSON.stringify(record.entries), now)
  }

  getPack(packId: string, version: string): PackRecord | undefined {
    const row = this.db.prepare('SELECT * FROM packs WHERE pack_id = ? AND version = ?').get(packId, version) as PackDbRow | undefined
    if (!row) return undefined
    return {
      packId: row.pack_id, version: row.version, label: row.label, authorPub: row.author_pub,
      masterWrapped: row.master_wrapped, trialEntries: JSON.parse(row.trial_entries) as string[],
      entries: JSON.parse(row.entries) as { id: string; type: string; size: number }[],
    }
  }

  putPurchase(record: PurchaseRecord): void {
    this.db.prepare('INSERT INTO purchases (token, sub, pack_id, version, plan, seats, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)')
      .run(record.token, record.sub, record.packId, record.version, record.plan, record.seats, record.expiresAt ?? null)
  }

  getPurchase(token: string): PurchaseRecord | undefined {
    const row = this.db.prepare('SELECT * FROM purchases WHERE token = ?').get(token) as
      | { token: string; sub: string; pack_id: string; version: string; plan: string; seats: number; expires_at: number | null }
      | undefined
    if (!row) return undefined
    return { token: row.token, sub: row.sub, packId: row.pack_id, version: row.version, plan: row.plan, seats: row.seats, ...(row.expires_at !== null ? { expiresAt: row.expires_at } : {}) }
  }

  upsertDevice(devicePub: string, sub: string, now = Date.now()): void {
    this.db.prepare('INSERT INTO devices (device_pub, sub, created_at) VALUES (?, ?, ?) ON CONFLICT(device_pub) DO UPDATE SET sub=excluded.sub')
      .run(devicePub, sub, now)
  }

  countSeats(sub: string, packId: string, version: string): number {
    const row = this.db.prepare('SELECT COUNT(*) AS n FROM seats WHERE sub = ? AND pack_id = ? AND version = ?').get(sub, packId, version) as { n: number }
    return row.n
  }

  putSeat(seat: SeatRecord, now = Date.now()): void {
    this.db.prepare('INSERT OR REPLACE INTO seats (sub, pack_id, version, device_pub, license_id, created_at) VALUES (?, ?, ?, ?, ?, ?)')
      .run(seat.sub, seat.packId, seat.version, seat.devicePub, seat.licenseId, now)
  }

  deleteSeat(sub: string, packId: string, version: string, devicePub: string): void {
    this.db.prepare('DELETE FROM seats WHERE sub = ? AND pack_id = ? AND version = ? AND device_pub = ?').run(sub, packId, version, devicePub)
  }

  deleteSeatsForSubject(sub: string): void { this.db.prepare('DELETE FROM seats WHERE sub = ?').run(sub) }

  putLicense(record: LicenseRecord): void {
    this.db.prepare(
      `INSERT OR REPLACE INTO licenses (license_id, sub, pack_id, version, device_pub, caps, plan, seat_limit, iat, exp, grace_until, revoked)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run(record.licenseId, record.sub, record.packId, record.version, record.devicePub,
      JSON.stringify(record.caps), record.plan, record.seatLimit, record.iat, record.exp, record.graceUntil, record.revoked ? 1 : 0)
  }

  private toLicense(row: LicenseDbRow): LicenseRecord {
    return {
      licenseId: row.license_id, sub: row.sub, packId: row.pack_id, version: row.version, devicePub: row.device_pub,
      caps: JSON.parse(row.caps) as string[], plan: row.plan, seatLimit: row.seat_limit,
      iat: row.iat, exp: row.exp, graceUntil: row.grace_until, revoked: row.revoked === 1,
    }
  }

  getLicense(licenseId: string): LicenseRecord | undefined {
    const row = this.db.prepare('SELECT * FROM licenses WHERE license_id = ?').get(licenseId) as LicenseDbRow | undefined
    return row ? this.toLicense(row) : undefined
  }

  getLicenseForDevice(packId: string, version: string, devicePub: string): LicenseRecord | undefined {
    const row = this.db.prepare('SELECT * FROM licenses WHERE pack_id = ? AND version = ? AND device_pub = ? AND revoked = 0').get(packId, version, devicePub) as LicenseDbRow | undefined
    return row ? this.toLicense(row) : undefined
  }

  markRevoked(licenseId: string): boolean {
    const result = this.db.prepare('UPDATE licenses SET revoked = 1 WHERE license_id = ?').run(licenseId)
    return Number(result.changes) > 0
  }

  getTrial(devicePub: string, packId: string, version: string): { licenseId: string } | undefined {
    const row = this.db.prepare('SELECT license_id FROM trials WHERE device_pub = ? AND pack_id = ? AND version = ?').get(devicePub, packId, version) as { license_id: string } | undefined
    return row ? { licenseId: row.license_id } : undefined
  }

  putTrial(devicePub: string, packId: string, version: string, licenseId: string, now = Date.now()): void {
    try {
      this.db.prepare('INSERT INTO trials (device_pub, pack_id, version, license_id, created_at) VALUES (?, ?, ?, ?, ?)').run(devicePub, packId, version, licenseId, now)
    } catch {
      throw new ServerError('TRIAL_ALREADY_USED', 'this device already used the trial for this pack')
    }
  }

  insertNonce(licenseId: string, nonce: string, seenAt: number): boolean {
    try {
      this.db.prepare('INSERT INTO nonces (license_id, nonce, seen_at) VALUES (?, ?, ?)').run(licenseId, nonce, seenAt)
      return true
    } catch {
      return false
    }
  }

  pruneNonces(minSeenAt: number, maxSeenAt: number): void {
    this.db.prepare('DELETE FROM nonces WHERE seen_at >= ? AND seen_at < ?').run(minSeenAt, maxSeenAt)
  }

  appendAudit(record: AuditRecord): void {
    this.db.prepare('INSERT INTO audit (at, action, actor, subject, detail) VALUES (?, ?, ?, ?, ?)').run(record.at, record.action, record.actor, record.subject, record.detail)
  }

  listAudit(): AuditRecord[] {
    const rows = this.db.prepare('SELECT at, action, actor, subject, detail FROM audit ORDER BY id').all() as AuditRecord[]
    return rows.map((row) => ({ at: row.at, action: row.action, actor: row.actor, subject: row.subject, detail: row.detail }))
  }

  putIdempotent(key: string, response: string, now = Date.now()): void {
    this.db.prepare('INSERT OR REPLACE INTO idempotency (key, response, created_at) VALUES (?, ?, ?)').run(key, response, now)
  }

  getIdempotent(key: string): string | undefined {
    const row = this.db.prepare('SELECT response FROM idempotency WHERE key = ?').get(key) as { response: string } | undefined
    return row?.response
  }
}

export function openStore(path: string): Store {
  return new Store(path)
}
```

`packages/license-server/src/index.ts`：
```ts
export * from './server-errors.js'
export * from './store.js'
```

- [ ] **Step 5: 运行测试确认通过**

Run: `corepack pnpm -C packages/license-server test`
Expected: PASS（6 passed）。

- [ ] **Step 6: 提交**

```bash
git add packages/license-server pnpm-workspace.yaml pnpm-lock.yaml
git commit -m "feat(license-server): add sqlite-backed store for packs, seats and licenses"
```
---

### Task 3: 服务端密钥、master 静态加密与签发核心

**Files:**
- Create: `packages/license-server/src/{keys.ts,master-store.ts,issue.ts,http.ts}`
- Modify: `packages/license-server/src/index.ts`（追加 4 个 export）
- Test: `packages/license-server/test/issue.test.ts`

**Interfaces:**
- Consumes: `deriveEntryKey`、`PackManifest`（`@sealed/pack-format`）；`signLicense`、`wrapEntryKey`、`b64u`、`unb64u`、`rawPublicBytes`、`x25519PublicFromRaw`、`LICENSE_TTL_SECONDS`、`LICENSE_GRACE_SECONDS`（`@sealed/license-format`）；`Store`/`PackRecord`/`ServerError`（Task 2）。
- Produces:
  - `interface ServerKeys { licensePrivateKey: KeyObject; proofPrivateKey: Buffer; proofPublicB64: string; masterWrapKey: Buffer }`
  - `loadServerKeys(env: NodeJS.ProcessEnv): ServerKeys`（缺变量或长度不对 → `ServerError('INTERNAL', …)`）
  - `wrapMaster(master: Buffer, masterWrapKey: Buffer): string`；`unwrapMaster(wrapped: string, masterWrapKey: Buffer): Buffer`
  - `interface IssueInput { licenseId: string; sub: string; pack: PackRecord; devicePubB64: string; caps: ('trial'|'full')[]; plan: string; seatLimit: number; now: number; entryFilter?: (id: string) => boolean }`
  - `issueLicense(input: IssueInput, master: Buffer, signingKey: KeyObject): string`
  - `createApp(opts: AppOptions): http.Server`（Task 4 起填充路由；Task 3 只要求 `http.ts` 提供 `readJsonBody` / `sendJson` / `HttpError` / `Router`）

- [ ] **Step 1: 写失败测试**

`packages/license-server/test/issue.test.ts`：
```ts
import { generateKeyPairSync } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import { deriveEntryKey, entryAad, openEntry, sealEntry } from '@sealed/pack-format'
import { b64u, unwrapEntryKey, verifyLicense, x25519PrivateFromRaw } from '@sealed/license-format'
import { ServerError, issueLicense, loadServerKeys, unwrapMaster, wrapMaster, type PackRecord } from '../src/index.js'

const env = {
  SEALED_SERVER_LICENSE_KEY: b64u(generateKeyPairSync('ed25519').privateKey.export({ format: 'jwk' }).d
    ? Buffer.from(generateKeyPairSync('ed25519').privateKey.export({ format: 'jwk' }).d!, 'base64url')
    : Buffer.alloc(32)),
}

function testEnv() {
  const licenseKey = generateKeyPairSync('ed25519')
  const license = licenseKey.privateKey.export({ format: 'jwk' }) as { d: string }
  const proof = generateKeyPairSync('x25519')
  const proofRaw = proof.privateKey.export({ format: 'jwk' }) as { d: string }
  return {
    licenseKey,
    env: {
      SEALED_SERVER_LICENSE_KEY: license.d,
      SEALED_SERVER_PROOF_KEY: proofRaw.d,
      SEALED_SERVER_MASTER_KEY: b64u(Buffer.alloc(32, 9)),
    } as NodeJS.ProcessEnv,
  }
}

const pack: PackRecord = {
  packId: 'com.example.p', version: '1.0.0', label: '翻译', authorPub: 'A'.repeat(43),
  masterWrapped: '', trialEntries: ['meta'],
  entries: [{ id: 'meta', type: 'meta', size: 1 }, { id: 'skill:translate:body', type: 'text', size: 1 }, { id: 'data:x', type: 'data', size: 1 }],
}

describe('server keys and master wrapping', () => {
  it('loads keys from the environment and derives the proof public key', () => {
    const { env: e } = testEnv()
    const keys = loadServerKeys(e)
    expect(keys.masterWrapKey.length).toBe(32)
    expect(keys.proofPrivateKey.length).toBe(32)
    expect(keys.proofPublicB64).toMatch(/^[A-Za-z0-9_-]{43}$/)
  })

  it('rejects a missing or malformed key', () => {
    expect(() => loadServerKeys({} as NodeJS.ProcessEnv)).toThrow(ServerError)
    const { env: e } = testEnv()
    expect(() => loadServerKeys({ ...e, SEALED_SERVER_MASTER_KEY: 'nope' })).toThrow('INTERNAL')
  })

  it('round-trips the master and detects tampering', () => {
    const key = Buffer.alloc(32, 3)
    const master = Buffer.alloc(32, 5)
    const wrapped = wrapMaster(master, key)
    expect(unwrapMaster(wrapped, key).equals(master)).toBe(true)
    const tampered = wrapped.slice(0, -2) + (wrapped.endsWith('AA') ? 'BB' : 'AA')
    expect(() => unwrapMaster(tampered, key)).toThrow(ServerError)
  })
})

describe('issueLicense', () => {
  it('issues a verifiable license bound to the device, the pack author key and the pack version', () => {
    const { licenseKey, env: e } = testEnv()
    const keys = loadServerKeys(e)
    const device = generateKeyPairSync('x25519')
    const devicePubB64 = b64u(rawPublicBytesOf(device.publicKey))
    const token = issueLicense({
      licenseId: 'lic_1', sub: 'cust', pack, devicePubB64, caps: ['full'], plan: 'pro', seatLimit: 2, now: 1_700_000_000,
    }, Buffer.alloc(32, 5), keys.licensePrivateKey)
    const payload = verifyLicense(token, [licenseKey.publicKey])
    expect(payload.lid).toBe('lic_1')
    expect(payload.dev).toBe(devicePubB64)
    expect(payload.pack).toEqual({ id: pack.packId, version: pack.version, author_pub: pack.authorPub })
    expect(payload.exp).toBe(1_700_000_000 + 604800)
    expect(payload.grace_until).toBe(1_700_000_000 + 604800 + 259200)
    expect(payload.keys.map((k) => k.eid).sort()).toEqual(['data:x', 'meta', 'skill:translate:body'])
  })

  it('grants only the entries the filter allows and unwraps to the real content key', () => {
    const { env: e } = testEnv()
    const keys = loadServerKeys(e)
    const device = generateKeyPairSync('x25519')
    const devicePubB64 = b64u(rawPublicBytesOf(device.publicKey))
    const master = Buffer.alloc(32, 7)
    const token = issueLicense({
      licenseId: 'lic_t', sub: 'trial', pack, devicePubB64, caps: ['trial'], plan: 'trial', seatLimit: 1, now: 100,
      entryFilter: (id) => id === 'meta',
    }, master, keys.licensePrivateKey)
    const payload = verifyLicense(token, [keys.licensePrivateKey])
    expect(payload.keys.map((k) => k.eid)).toEqual(['meta'])
    const ck = unwrapEntryKey(payload, 'meta', x25519PrivateFromRaw(rawPrivateBytesOf(device.privateKey)))
    expect(ck.equals(deriveEntryKey(master, pack.packId, pack.version, 'meta'))).toBe(true)
    const sealed = sealEntry(ck, entryAad(pack.packId, pack.version, 'meta'), Buffer.from('{"skills":[]}'))
    expect(openEntry(ck, entryAad(pack.packId, pack.version, 'meta'), sealed.nonce, sealed.ct).toString('utf8')).toBe('{"skills":[]}')
    expect(() => unwrapEntryKey(payload, 'data:x', x25519PrivateFromRaw(rawPrivateBytesOf(device.privateKey)))).toThrow('LICENSE_NO_GRANT')
  })
})
```
（测试辅助函数 `rawPublicBytesOf` / `rawPrivateBytesOf` 直接 re-export 自 `@sealed/license-format`，在测试文件顶部写
`import { rawPrivateBytes as rawPrivateBytesOf, rawPublicBytes as rawPublicBytesOf } from '@sealed/license-format'`；上文的 `env` 常量是写测试时的残留草稿，实现时删掉它，只保留 `testEnv()`。）

- [ ] **Step 2: 运行测试确认失败**

Run: `corepack pnpm -C packages/license-server test`
Expected: FAIL —— `../src/keys.js` 等不存在。

- [ ] **Step 3: 实现**

`packages/license-server/src/keys.ts`：
```ts
import { createPublicKey, type KeyObject } from 'node:crypto'
import { unb64u, x25519PrivateFromRaw } from '@sealed/license-format'
import { ServerError } from './server-errors.js'

export interface ServerKeys {
  licensePrivateKey: KeyObject
  proofPrivateKey: Buffer
  proofPublicB64: string
  masterWrapKey: Buffer
}

function require32(env: NodeJS.ProcessEnv, name: string): Buffer {
  const value = env[name]
  if (!value) throw new ServerError('INTERNAL', name + ' is not configured')
  const raw = unb64u(value)
  if (raw.length !== 32) throw new ServerError('INTERNAL', name + ' must decode to 32 bytes')
  return raw
}

export function loadServerKeys(env: NodeJS.ProcessEnv): ServerKeys {
  const licenseRaw = require32(env, 'SEALED_SERVER_LICENSE_KEY')
  const proofPrivateKey = require32(env, 'SEALED_SERVER_PROOF_KEY')
  const masterWrapKey = require32(env, 'SEALED_SERVER_MASTER_KEY')
  const licensePrivateKey = createPublicKey
    ? requireKey(licenseRaw)
    : requireKey(licenseRaw)
  return {
    licensePrivateKey,
    proofPrivateKey,
    proofPublicB64: publicB64FromPrivate(proofPrivateKey),
    masterWrapKey,
  }
}

function requireKey(raw: Buffer): KeyObject {
  const jwk = { kty: 'OKP', crv: 'Ed25519', d: raw.toString('base64url'), x: '' }
  const derived = deriveEd25519Public(raw)
  return (require('node:crypto') as typeof import('node:crypto')).createPrivateKey({ key: { ...jwk, x: derived }, format: 'jwk' })
}
```

> **实现者注意（上面这段是错误示范，必须按下面写）**：Ed25519 私钥从 raw 32 字节构造时，JWK 的 `x`（公钥）是必填的。请用 Node 的 `createPrivateKey({ key: { kty:'OKP', crv:'Ed25519', d: b64u(raw) }, format: 'jwk' })`——Node 对 Ed25519 允许省略 `x`；若你的 Node 版本要求 `x`，则改为在环境里直接提供 PKCS8 PEM（`SEALED_SERVER_LICENSE_KEY_PEM`），并在测试里用 `generateKeyPairSync('ed25519')` 的 `privateKey.export({ format:'pem', type:'pkcs8' })`。**不要**自己拼 DER。最终实现如下：

```ts
import { createPrivateKey, createPublicKey, type KeyObject } from 'node:crypto'
import { b64u, rawPublicBytes, unb64u, x25519PrivateFromRaw } from '@sealed/license-format'
import { ServerError } from './server-errors.js'

export interface ServerKeys {
  licensePrivateKey: KeyObject
  proofPrivateKey: Buffer
  proofPublicB64: string
  masterWrapKey: Buffer
}

function require32(env: NodeJS.ProcessEnv, name: string): Buffer {
  const value = env[name]
  if (!value) throw new ServerError('INTERNAL', name + ' is not configured')
  const raw = unb64u(value)
  if (raw.length !== 32) throw new ServerError('INTERNAL', name + ' must decode to 32 bytes')
  return raw
}

export function loadServerKeys(env: NodeJS.ProcessEnv): ServerKeys {
  const licenseRaw = require32(env, 'SEALED_SERVER_LICENSE_KEY')
  const proofPrivateKey = require32(env, 'SEALED_SERVER_PROOF_KEY')
  const masterWrapKey = require32(env, 'SEALED_SERVER_MASTER_KEY')
  let licensePrivateKey: KeyObject
  try {
    licensePrivateKey = createPrivateKey({ key: { kty: 'OKP', crv: 'Ed25519', d: b64u(licenseRaw) }, format: 'jwk' })
  } catch {
    throw new ServerError('INTERNAL', 'SEALED_SERVER_LICENSE_KEY is not a valid Ed25519 private key')
  }
  return {
    licensePrivateKey,
    proofPrivateKey,
    proofPublicB64: b64u(rawPublicBytes(createPublicKey(x25519PrivateFromRaw(proofPrivateKey)))),
    masterWrapKey,
  }
}

export function serverLicensePublicB64(keys: ServerKeys): string {
  return b64u(rawPublicBytes(createPublicKey(keys.licensePrivateKey)))
}
```

`packages/license-server/src/master-store.ts`：
```ts
import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto'
import { b64u, unb64u } from '@sealed/license-format'
import { ServerError } from './server-errors.js'

const NONCE_BYTES = 12

/** master key 静态加密：`v1.<b64u nonce>.<b64u ciphertext||tag>`。 */
export function wrapMaster(master: Buffer, masterWrapKey: Buffer): string {
  const nonce = randomBytes(NONCE_BYTES)
  const cipher = createCipheriv('aes-256-gcm', masterWrapKey, nonce)
  const ct = Buffer.concat([cipher.update(master), cipher.final(), cipher.getAuthTag()])
  return 'v1.' + b64u(nonce) + '.' + b64u(ct)
}

export function unwrapMaster(wrapped: string, masterWrapKey: Buffer): Buffer {
  const parts = wrapped.split('.')
  if (parts.length !== 3 || parts[0] !== 'v1') throw new ServerError('INTERNAL', 'stored master key is malformed')
  const nonce = unb64u(parts[1])
  const ct = unb64u(parts[2])
  if (nonce.length !== NONCE_BYTES || ct.length < 16) throw new ServerError('INTERNAL', 'stored master key is malformed')
  const tag = ct.subarray(ct.length - 16)
  const body = ct.subarray(0, ct.length - 16)
  const decipher = createDecipheriv('aes-256-gcm', masterWrapKey, nonce)
  decipher.setAuthTag(tag)
  try {
    return Buffer.concat([decipher.update(body), decipher.final()])
  } catch {
    throw new ServerError('INTERNAL', 'could not decrypt the stored master key')
  }
}
```

`packages/license-server/src/issue.ts`：
```ts
import type { KeyObject } from 'node:crypto'
import { deriveEntryKey } from '@sealed/pack-format'
import {
  LICENSE_GRACE_SECONDS, LICENSE_TTL_SECONDS, signLicense, wrapEntryKey,
  type LicenseGrant, type LicensePayload,
} from '@sealed/license-format'
import type { PackRecord } from './store.js'

export interface IssueInput {
  licenseId: string
  sub: string
  pack: PackRecord
  devicePubB64: string
  caps: ('trial' | 'full')[]
  plan: string
  seatLimit: number
  now: number
  entryFilter?: (id: string) => boolean
}

export function issueLicense(input: IssueInput, master: Buffer, signingKey: KeyObject): string {
  const { pack } = input
  const payload: LicensePayload = {
    v: 1,
    lid: input.licenseId,
    sub: input.sub,
    pack: { id: pack.packId, version: pack.version, author_pub: pack.authorPub },
    dev: input.devicePubB64,
    iat: input.now,
    exp: input.now + LICENSE_TTL_SECONDS,
    grace_until: input.now + LICENSE_TTL_SECONDS + LICENSE_GRACE_SECONDS,
    caps: input.caps,
    groups: [input.plan],
    keys: [],
    seats: { plan: input.plan, limit: input.seatLimit },
  }
  for (const entry of pack.entries) {
    if (input.entryFilter && !input.entryFilter(entry.id)) continue
    const ck = deriveEntryKey(master, pack.packId, pack.version, entry.id)
    try {
      payload.keys.push(wrapEntryKey(payload, entry.id, ck, devicePubKey))
    } finally {
      ck.fill(0)
    }
  }
  return signLicense(payload, signingKey)
}
```
其中 `devicePubKey` 用 `x25519PublicFromRaw(unb64u(input.devicePubB64))` 构造（在 `issue.ts` 顶部 import）。`LicenseGrant` 类型仅在需要显式标注时 import，若未使用请删掉该 import。

`packages/license-server/src/http.ts`：
```ts
import type { IncomingMessage, ServerResponse } from 'node:http'
import type { ProtocolErrorCode } from '@sealed/license-format'

export class HttpError extends Error {
  constructor(readonly status: number, readonly code: ProtocolErrorCode, message: string) {
    super(message)
    this.name = 'HttpError'
  }
}

export const MAX_BODY_BYTES = 1_048_576

export async function readJsonBody(req: IncomingMessage, limit = MAX_BODY_BYTES): Promise<unknown> {
  const chunks: Buffer[] = []
  let size = 0
  for await (const chunk of req) {
    const buf = chunk as Buffer
    size += buf.length
    if (size > limit) throw new HttpError(413, 'BAD_REQUEST', 'request body is too large')
    chunks.push(buf)
  }
  if (size === 0) return undefined
  try {
    return JSON.parse(Buffer.concat(chunks).toString('utf8'))
  } catch {
    throw new HttpError(400, 'BAD_REQUEST', 'request body is not valid JSON')
  }
}

export function sendJson(res: ServerResponse, status: number, body: unknown): void {
  const payload = Buffer.from(JSON.stringify(body), 'utf8')
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'content-length': String(payload.length) })
  res.end(payload)
}

export function sendError(res: ServerResponse, status: number, code: ProtocolErrorCode, message: string): void {
  sendJson(res, status, { error: { code, message } })
}
```

`packages/license-server/src/index.ts`：
```ts
export * from './server-errors.js'
export * from './store.js'
export * from './keys.js'
export * from './master-store.js'
export * from './issue.js'
export * from './http.js'
```

- [ ] **Step 4: 运行测试确认通过**

Run: `corepack pnpm -C packages/license-server test`
Expected: PASS（store 6 + issue 5 = 11 passed）。

- [ ] **Step 5: 提交**

```bash
git add packages/license-server
git commit -m "feat(license-server): add server keys, master encryption and license issuance"
```

---

### Task 4: `/v1/health`、`/v1/trial` 与 `/v1/activate`

**Files:**
- Create: `packages/license-server/src/{app.ts,routes.ts}`
- Create: `packages/license-server/src/bin.ts`（`node dist/bin.js` 启动入口，从 env 读配置）
- Modify: `packages/license-server/src/index.ts`（追加 `export * from './app.js'`、`export * from './routes.js'`）
- Modify: `packages/license-server/package.json`（`"bin": { "sealed-license-server": "dist/bin.js" }`）
- Test: `packages/license-server/test/routes-activate.test.ts`

**Interfaces:**
- Consumes: Task 1 的校验器与常量、Task 2 的 `Store`、Task 3 的 `ServerKeys`/`issueLicense`/`wrapMaster`/`unwrapMaster`、`HttpError`/`readJsonBody`/`sendJson`/`sendError`。
- Produces:
  - `interface AppOptions { store: Store; keys: ServerKeys; now?: () => number; adminToken: string; rateLimit?: { windowMs: number; max: number } }`
  - `createApp(opts: AppOptions): http.Server`（对 `ENDPOINTS` 路由；未匹配 → 404 `BAD_REQUEST`）
  - `handleTrial(store, keys, body, now)`、`handleActivate(...)`（纯函数式 handler，便于单测；返回 `{ status, body }`）
  - `generateLicenseId(prefix: string, now: number): string`（`lic_<prefix>_<ts>_<8 hex>`）

- [ ] **Step 1: 写失败测试**

`packages/license-server/test/routes-activate.test.ts`：
```ts
import { generateKeyPairSync, type KeyObject } from 'node:crypto'
import { afterEach, describe, expect, it } from 'vitest'
import { b64u, rawPublicBytes, verifyLicense, LICENSE_TTL_SECONDS } from '@sealed/license-format'
import { createApp, loadServerKeys, openStore, wrapMaster, type Store } from '../src/index.js'

function keysFromEnv() {
  const licenseKey = generateKeyPairSync('ed25519')
  const proof = generateKeyPairSync('x25519')
  const env = {
    SEALED_SERVER_LICENSE_KEY: (licenseKey.privateKey.export({ format: 'jwk' }) as { d: string }).d,
    SEALED_SERVER_PROOF_KEY: (proof.privateKey.export({ format: 'jwk' }) as { d: string }).d,
    SEALED_SERVER_MASTER_KEY: b64u(Buffer.alloc(32, 9)),
  }
  return { licenseKey, keys: loadServerKeys(env as NodeJS.ProcessEnv) }
}

const master = Buffer.alloc(32, 5)
const entries = [{ id: 'meta', type: 'meta', size: 1 }, { id: 'skill:translate:body', type: 'text', size: 1 }, { id: 'data:x', type: 'data', size: 1 }]

function seededStore(keys: ReturnType<typeof keysFromEnv>['keys']): Store {
  const store = openStore(':memory:')
  store.putPack({
    packId: 'com.example.p', version: '1.0.0', label: '翻译', authorPub: 'A'.repeat(43),
    masterWrapped: wrapMaster(master, keys.masterWrapKey), trialEntries: ['meta', 'skill:translate:body'], entries,
  })
  return store
}

async function post(server: import('node:http').Server, path: string, body: unknown, headers: Record<string, string> = {}) {
  const address = server.address()
  if (address === null || typeof address === 'string') throw new Error('server not listening')
  const res = await fetch('http://127.0.0.1:' + address.port + path, {
    method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body: JSON.stringify(body),
  })
  return { status: res.status, body: await res.json() as Record<string, unknown> }
}

const servers: import('node:http').Server[] = []
afterEach(() => { for (const s of servers.splice(0)) s.close() })

async function listen(app: import('node:http').Server) {
  servers.push(app)
  await new Promise<void>((resolve) => app.listen(0, '127.0.0.1', resolve))
  return app
}

const devicePub = (() => { const d = generateKeyPairSync('x25519'); return { pair: d, b64: b64u(rawPublicBytes(d.publicKey)) } })()

describe('POST /v1/trial', () => {
  it('issues a trial license granting only the pack trial entries', async () => {
    const { licenseKey, keys } = keysFromEnv()
    const store = seededStore(keys)
    const app = await listen(createApp({ store, keys, adminToken: 'admin' }))
    const res = await post(app, '/v1/trial', { device_pub: devicePub.b64, pack: { id: 'com.example.p', version: '1.0.0' } })
    expect(res.status).toBe(200)
    const payload = verifyLicense(res.body.license as string, [licenseKey.publicKey])
    expect(payload.caps).toEqual(['trial'])
    expect(payload.keys.map((k) => k.eid).sort()).toEqual(['meta', 'skill:translate:body'])
    expect(payload.exp - payload.iat).toBe(LICENSE_TTL_SECONDS)
  })

  it('refuses a second trial for the same device and pack', async () => {
    const { keys } = keysFromEnv()
    const app = await listen(createApp({ store: seededStore(keys), keys, adminToken: 'admin' }))
    const body = { device_pub: devicePub.b64, pack: { id: 'com.example.p', version: '1.0.0' } }
    expect((await post(app, '/v1/trial', body)).status).toBe(200)
    const second = await post(app, '/v1/trial', body)
    expect(second.status).toBe(409)
    expect((second.body.error as { code: string }).code).toBe('TRIAL_ALREADY_USED')
  })

  it('returns a structured 404 for an unknown pack and 400 for a malformed body', async () => {
    const { keys } = keysFromEnv()
    const app = await listen(createApp({ store: seededStore(keys), keys, adminToken: 'admin' }))
    const unknown = await post(app, '/v1/trial', { device_pub: devicePub.b64, pack: { id: 'nope', version: '1' } })
    expect(unknown.status).toBe(404)
    expect((unknown.body.error as { code: string }).code).toBe('PACK_NOT_FOUND')
    const malformed = await post(app, '/v1/trial', { device_pub: 'x', pack: { id: 'p', version: '1' } })
    expect(malformed.status).toBe(400)
    expect((malformed.body.error as { code: string }).code).toBe('BAD_REQUEST')
  })
})

describe('POST /v1/activate', () => {
  it('issues a full license within the seat limit and is idempotent for the same device', async () => {
    const { licenseKey, keys } = keysFromEnv()
    const store = seededStore(keys)
    store.putPurchase({ token: 'tok', sub: 'cust', packId: 'com.example.p', version: '1.0.0', plan: 'pro', seats: 1 })
    const app = await listen(createApp({ store, keys, adminToken: 'admin' }))
    const body = { device_pub: devicePub.b64, purchase_token: 'tok', pack: { id: 'com.example.p', version: '1.0.0' } }
    const first = await post(app, '/v1/activate', body)
    expect(first.status).toBe(200)
    const payload = verifyLicense(first.body.license as string, [licenseKey.publicKey])
    expect(payload.caps).toEqual(['full'])
    expect(payload.keys.length).toBe(3)
    const again = await post(app, '/v1/activate', body)
    expect(again.status).toBe(200)
    expect(verifyLicense(again.body.license as string, [licenseKey.publicKey]).lid).toBe(payload.lid)
    expect(store.countSeats('cust', 'com.example.p', '1.0.0')).toBe(1)
  })

  it('refuses activation beyond the seat limit and for a bad token', async () => {
    const { keys } = keysFromEnv()
    const store = seededStore(keys)
    store.putPurchase({ token: 'tok', sub: 'cust', packId: 'com.example.p', version: '1.0.0', plan: 'pro', seats: 1 })
    const other = generateKeyPairSync('x25519')
    const app = await listen(createApp({ store, keys, adminToken: 'admin' }))
    await post(app, '/v1/activate', { device_pub: devicePub.b64, purchase_token: 'tok', pack: { id: 'com.example.p', version: '1.0.0' } })
    const second = await post(app, '/v1/activate', { device_pub: b64u(rawPublicBytes(other.publicKey)), purchase_token: 'tok', pack: { id: 'com.example.p', version: '1.0.0' } })
    expect(second.status).toBe(409)
    expect((second.body.error as { code: string }).code).toBe('SEAT_LIMIT')
    const bad = await post(app, '/v1/activate', { device_pub: devicePub.b64, purchase_token: 'nope', pack: { id: 'com.example.p', version: '1.0.0' } })
    expect(bad.status).toBe(401)
    expect((bad.body.error as { code: string }).code).toBe('BAD_PURCHASE_TOKEN')
  })
})
```

- [ ] **Step 2: 运行测试确认失败**

Run: `corepack pnpm -C packages/license-server test`
Expected: FAIL —— `../src/app.js` 不存在（`createApp` 未定义）。

- [ ] **Step 3: 实现**

`packages/license-server/src/routes.ts`：（先写 trial 与 activate，renew/revoke 在 Task 5 追加）
```ts
import { randomBytes } from 'node:crypto'
import {
  LICENSE_TTL_SECONDS, LICENSE_GRACE_SECONDS, validateActivateRequest, validateTrialRequest,
  type ProtocolErrorCode,
} from '@sealed/license-format'
import { issueLicense } from './issue.js'
import { unwrapMaster } from './master-store.js'
import { HttpError } from './http.js'
import type { ServerKeys } from './keys.js'
import type { Store } from './store.js'

export function generateLicenseId(prefix: string, now: number): string {
  return 'lic_' + prefix + '_' + now + '_' + randomBytes(4).toString('hex')
}

export interface RouteResult { status: number; body: unknown }

function requirePack(store: Store, packId: string, version: string) {
  const pack = store.getPack(packId, version)
  if (!pack) throw new HttpError(404, 'PACK_NOT_FOUND', 'unknown pack or version')
  return pack
}

function unwrapPackMaster(store: Store, keys: ServerKeys, packId: string, version: string): Buffer {
  const record = requirePack(store, packId, version)
  const master = unwrapMaster(record.masterWrapped, keys.masterWrapKey)
  if (master.length !== 32) throw new HttpError(500, 'INTERNAL', 'stored master key is malformed')
  return master
}

export function handleTrial(store: Store, keys: ServerKeys, body: unknown, now: number): RouteResult {
  const request = validateTrialRequest(body)
  const pack = requirePack(store, request.pack.id, request.pack.version)
  const existing = store.getTrial(request.device_pub, pack.packId, pack.version)
  if (existing) throw new HttpError(409, 'TRIAL_ALREADY_USED', 'this device already used the trial for this pack')
  const master = unwrapPackMaster(store, keys, pack.packId, pack.version)
  const trialSet = new Set(pack.trialEntries)
  const licenseId = generateLicenseId('trial', now)
  let token: string
  try {
    token = issueLicense({
      licenseId, sub: 'trial:' + request.device_pub.slice(0, 8), pack, devicePubB64: request.device_pub,
      caps: ['trial'], plan: 'trial', seatLimit: 1, now, entryFilter: (id) => trialSet.has(id),
    }, master, keys.licensePrivateKey)
  } finally {
    master.fill(0)
  }
  store.putTrial(request.device_pub, pack.packId, pack.version, licenseId, now)
  store.appendAudit({ at: now, action: 'trial', actor: 'client', subject: licenseId, detail: pack.packId + '@' + pack.version })
  return { status: 200, body: { license: token } }
}

export function handleActivate(store: Store, keys: ServerKeys, body: unknown, now: number): RouteResult {
  const request = validateActivateRequest(body)
  const purchase = store.getPurchase(request.purchase_token)
  if (!purchase) throw new HttpError(401, 'BAD_PURCHASE_TOKEN', 'purchase token is unknown')
  if (purchase.expiresAt !== undefined && purchase.expiresAt <= now) throw new HttpError(401, 'BAD_PURCHASE_TOKEN', 'purchase token has expired')
  if (purchase.packId !== request.pack.id || purchase.version !== request.pack.version) throw new HttpError(404, 'PACK_NOT_FOUND', 'purchase token is for a different pack')
  const pack = requirePack(store, purchase.packId, purchase.version)
  const existing = store.getLicenseForDevice(pack.packId, pack.version, request.device_pub)
  if (existing) {
    const master = unwrapPackMaster(store, keys, pack.packId, pack.version)
    try {
      const token = issueLicense({
        licenseId: existing.licenseId, sub: existing.sub, pack, devicePubB64: request.device_pub,
        caps: ['full'], plan: purchase.plan, seatLimit: purchase.seats, now,
      }, master, keys.licensePrivateKey)
      return { status: 200, body: { license: token } }
    } finally { master.fill(0) }
  }
  if (store.countSeats(purchase.sub, pack.packId, pack.version) >= purchase.seats) {
    throw new HttpError(409, 'SEAT_LIMIT', 'all seats for this purchase are in use')
  }
  const master = unwrapPackMaster(store, keys, pack.packId, pack.version)
  const licenseId = generateLicenseId('full', now)
  let token: string
  try {
    token = issueLicense({
      licenseId, sub: purchase.sub, pack, devicePubB64: request.device_pub,
      caps: ['full'], plan: purchase.plan, seatLimit: purchase.seats, now,
    }, master, keys.licensePrivateKey)
  } finally { master.fill(0) }
  store.upsertDevice(request.device_pub, purchase.sub, now)
  store.putSeat({ sub: purchase.sub, packId: pack.packId, version: pack.version, devicePub: request.device_pub, licenseId }, now)
  store.putLicense({
    licenseId, sub: purchase.sub, packId: pack.packId, version: pack.version, devicePub: request.device_pub,
    caps: ['full'], plan: purchase.plan, seatLimit: purchase.seats,
    iat: now, exp: now + LICENSE_TTL_SECONDS, graceUntil: now + LICENSE_TTL_SECONDS + LICENSE_GRACE_SECONDS, revoked: false,
  })
  store.appendAudit({ at: now, action: 'activate', actor: 'client', subject: licenseId, detail: pack.packId + '@' + pack.version })
  return { status: 200, body: { license: token } }
}
```

`packages/license-server/src/app.ts`：
```ts
import { createServer, type IncomingMessage, type Server } from 'node:http'
import { ENDPOINTS, PROTOCOL_VERSION, ProtocolRequestError } from '@sealed/license-format'
import { HttpError, readJsonBody, sendError, sendJson } from './http.js'
import type { ServerKeys } from './keys.js'
import { handleActivate, handleTrial, type RouteResult } from './routes.js'
import type { Store } from './store.js'

export interface AppOptions {
  store: Store
  keys: ServerKeys
  adminToken: string
  now?: () => number
  rateLimit?: { windowMs: number; max: number }
}

type Handler = (body: unknown, now: number) => RouteResult | Promise<RouteResult>

export function createApp(opts: AppOptions): Server {
  const now = opts.now ?? (() => Math.floor(Date.now() / 1000))
  const routes: Record<string, Handler> = {
    [ENDPOINTS.health]: () => ({ status: 200, body: { ok: true, version: String(PROTOCOL_VERSION) } }),
    [ENDPOINTS.trial]: (body, t) => handleTrial(opts.store, opts.keys, body, t),
    [ENDPOINTS.activate]: (body, t) => handleActivate(opts.store, opts.keys, body, t),
  }

  return createServer(async (req: IncomingMessage, res) => {
    try {
      const path = (req.url ?? '').split('?')[0]
      const handler = req.method === 'POST' || path === ENDPOINTS.health ? routes[path] : undefined
      if (!handler) { sendError(res, 404, 'BAD_REQUEST', 'no such endpoint'); return }
      const body = path === ENDPOINTS.health ? undefined : await readJsonBody(req)
      const result = await handler(body, now())
      sendJson(res, result.status, result.body)
    } catch (error) {
      if (error instanceof HttpError) { sendError(res, error.status, error.code, error.message); return }
      if (error instanceof ProtocolRequestError) { sendError(res, 400, error.code, error.message); return }
      sendError(res, 500, 'INTERNAL', 'internal error')
    }
  })
}
```

`packages/license-server/src/bin.ts`：
```ts
import { openStore } from './store.js'
import { loadServerKeys } from './keys.js'
import { createApp } from './app.js'

const port = Number(process.env.SEALED_SERVER_PORT ?? '8787')
const dbPath = process.env.SEALED_SERVER_DB ?? 'sealed-license-server.sqlite'
const adminToken = process.env.SEALED_SERVER_ADMIN_TOKEN
if (!adminToken) { console.error('SEALED_SERVER_ADMIN_TOKEN is required'); process.exit(1) }
const store = openStore(dbPath)
const keys = loadServerKeys(process.env)
createApp({ store, keys, adminToken }).listen(port, () => console.log('sealed license server listening on ' + port))
```

- [ ] **Step 4: 运行测试确认通过**

Run: `corepack pnpm -C packages/license-server test`
Expected: PASS（store 6 + issue 5 + routes 5 = 16 passed）。

- [ ] **Step 5: 提交**

```bash
git add packages/license-server
git commit -m "feat(license-server): serve health, trial and activate endpoints"
```

---

### Task 5: 续期与吊销（`/v1/renew`、`/v1/revoke`）

**Files:**
- Modify: `packages/license-format/src/protocol.ts`（追加 `validateRevokeRequest`）
- Modify: `packages/license-format/test/protocol.test.ts`（追加 2 个用例）
- Modify: `packages/license-server/src/http.ts`（追加 `isAuthorized`）
- Modify: `packages/license-server/src/store.ts`（追加 `getLicensesForDevice`）
- Modify: `packages/license-server/src/routes.ts`（追加 `handleRenew` / `handleRevoke`）
- Modify: `packages/license-server/src/app.ts`（路由改为 `{ handler, admin? }`，透传 `req`）
- Modify: `packages/license-server/src/index.ts`（追加 `export * from './app.js'`、`export * from './routes.js'`）
- Test: `packages/license-server/test/renew-revoke.test.ts`

**Interfaces:**
- Consumes: `validateRenewRequest`、`deviceProofKey`、`deviceProofMessage`、`deviceProofMac`、`MAX_CLOCK_SKEW_SECONDS`、`NONCE_TTL_SECONDS`、`LICENSE_TTL_SECONDS`、`LICENSE_GRACE_SECONDS`、`x25519PrivateFromRaw`、`x25519PublicFromRaw`、`unb64u`（Task 1）；`Store`/`LicenseRecord`（Task 2）；`ServerKeys`、`issueLicense`、`unwrapMaster`、`HttpError`（Task 3）；`handleTrial`/`handleActivate`/`requirePack`/`unwrapPackMaster`/`generateLicenseId`（Task 4）。
- Produces:
  - `validateRevokeRequest(v: unknown): RevokeRequest`（三者全空 → `ProtocolRequestError('BAD_REQUEST', …)`）
  - `isAuthorized(req: IncomingMessage, adminToken: string): boolean`（常量时间比较 `Authorization: Bearer <token>`）
  - `Store.getLicensesForDevice(devicePub: string): LicenseRecord[]`
  - `handleRenew(store: Store, keys: ServerKeys, body: unknown, now: number): RouteResult`
  - `handleRevoke(store: Store, body: unknown, now: number): RouteResult`
  - 续期状态机（服务端侧）：`UNKNOWN_LICENSE`(404) → `REVOKED`(403) → 设备公钥不符 `BAD_DEVICE_PROOF`(401) → 时间戳超窗 `BAD_REQUEST`(400) → MAC 不符 `BAD_DEVICE_PROOF`(401) → nonce 重放 `REPLAY`(409) → 重签 200。

- [ ] **Step 1: 写失败测试**

`packages/license-format/test/protocol.test.ts` 追加：

```ts
import { validateRevokeRequest } from '../src/index.js'

describe('validateRevokeRequest', () => {
  it('accepts each identifier and rejects an empty request', () => {
    expect(validateRevokeRequest({ license_id: 'lic_x' })).toEqual({ license_id: 'lic_x' })
    expect(validateRevokeRequest({ device_pub: 'A'.repeat(43) })).toEqual({ device_pub: 'A'.repeat(43) })
    expect(validateRevokeRequest({ seat: 'lic_y' })).toEqual({ seat: 'lic_y' })
    expect(() => validateRevokeRequest({})).toThrowError(/at least one/)
    expect(() => validateRevokeRequest({ license_id: 7 })).toThrowError(/license_id/)
  })
})
```

`packages/license-server/test/renew-revoke.test.ts`：

```ts
import { diffieHellman, generateKeyPairSync } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import {
  b64u, deviceProofKey, deviceProofMac, deviceProofMessage, rawPrivateBytes, rawPublicBytes,
  x25519PrivateFromRaw, x25519PublicFromRaw,
} from '@sealed/license-format'
import {
  HttpError, handleRenew, handleRevoke, issueLicense, loadServerKeys, openStore, wrapMaster,
  type PackRecord, type ServerKeys, type Store,
} from '../src/index.js'

const MASTER = Buffer.alloc(32, 7)

function fixture() {
  const licenseKey = generateKeyPairSync('ed25519')
  const proofKey = generateKeyPairSync('x25519')
  const keys = loadServerKeys({
    SEALED_SERVER_LICENSE_KEY: (licenseKey.privateKey.export({ format: 'jwk' }) as { d: string }).d,
    SEALED_SERVER_PROOF_KEY: rawPrivateBytes(proofKey.privateKey).toString('base64url'),
    SEALED_SERVER_MASTER_KEY: b64u(Buffer.alloc(32, 5)),
  } as NodeJS.ProcessEnv)
  const store = openStore(':memory:')
  const pack: PackRecord = {
    packId: 'com.example.p', version: '1.0.0', label: 'p', authorPub: 'A'.repeat(43),
    masterWrapped: wrapMaster(MASTER, keys.masterWrapKey), trialEntries: [],
    entries: [{ id: 'meta', type: 'meta', size: 1 }],
  }
  store.putPack(pack)
  const device = generateKeyPairSync('x25519')
  const devicePub = rawPublicBytes(device.publicKey).toString('base64url')
  const license = issueLicense({
    licenseId: 'lic_full_1', sub: 'cust', pack, devicePubB64: devicePub,
    caps: ['full'], plan: 'pro', seatLimit: 2, now: 1000,
  }, MASTER, keys.licensePrivateKey)
  store.putLicense({
    licenseId: 'lic_full_1', sub: 'cust', packId: pack.packId, version: pack.version,
    devicePub, caps: ['full'], plan: 'pro', seatLimit: 2, iat: 1000, exp: 1000 + 604800,
    graceUntil: 1000 + 604800 + 259200, revoked: false,
  })
  return { store, keys, pack, device, devicePub, license }
}

function proof(keys: ServerKeys, device: ReturnType<typeof generateKeyPairSync>['privateKey'], lid: string, nonce: string, ts: number): string {
  const shared = diffieHellman({ privateKey: device, publicKey: x25519PublicFromRaw(unb64u(keys.proofPublicB64)) })
  return deviceProofMac(deviceProofKey(shared, lid), deviceProofMessage(lid, nonce, ts))
}
```

`unb64u` 需从 `@sealed/license-format` import；`x25519PrivateFromRaw` 在同文件未用到则删掉 import。

用例：

```ts
describe('handleRenew', () => {
  it('re-issues for a fresh nonce inside the skew window', () => {
    const f = fixture()
    const mac = proof(f.keys, f.device.privateKey, 'lic_full_1', 'n1', 1001)
    const result = handleRenew(f.store, f.keys, { license_id: 'lic_full_1', device_pub: f.devicePub, nonce: 'n1', ts: 1001, mac }, 1001)
    expect(result.status).toBe(200)
    expect(typeof (result.body as { license: string }).license).toBe('string')
    expect(f.store.getLicense('lic_full_1')?.iat).toBe(1001)
    expect(f.store.listAudit().at(-1)?.action).toBe('renew')
  })

  it('rejects a replayed nonce and an out-of-window timestamp', () => {
    const f = fixture()
    const mac = proof(f.keys, f.device.privateKey, 'lic_full_1', 'n1', 1001)
    handleRenew(f.store, f.keys, { license_id: 'lic_full_1', device_pub: f.devicePub, nonce: 'n1', ts: 1001, mac }, 1001)
    expect(() => handleRenew(f.store, f.keys, { license_id: 'lic_full_1', device_pub: f.devicePub, nonce: 'n1', ts: 1001, mac }, 1001))
      .toThrowError(expect.objectContaining({ code: 'REPLAY' }))
    const stale = proof(f.keys, f.device.privateKey, 'lic_full_1', 'n2', 1)
    expect(() => handleRenew(f.store, f.keys, { license_id: 'lic_full_1', device_pub: f.devicePub, nonce: 'n2', ts: 1, mac: stale }, 1001))
      .toThrowError(expect.objectContaining({ code: 'BAD_REQUEST' }))
  })

  it('rejects a bad device proof, an unknown license and a revoked license', () => {
    const f = fixture()
    expect(() => handleRenew(f.store, f.keys, { license_id: 'lic_full_1', device_pub: f.devicePub, nonce: 'n', ts: 1001, mac: 'AAAA' }, 1001))
      .toThrowError(expect.objectContaining({ code: 'BAD_DEVICE_PROOF' }))
    expect(() => handleRenew(f.store, f.keys, { license_id: 'lic_nope', device_pub: f.devicePub, nonce: 'n', ts: 1001, mac: 'AAAA' }, 1001))
      .toThrowError(expect.objectContaining({ code: 'UNKNOWN_LICENSE' }))
    f.store.markRevoked('lic_full_1')
    expect(() => handleRenew(f.store, f.keys, { license_id: 'lic_full_1', device_pub: f.devicePub, nonce: 'n', ts: 1001, mac: 'AAAA' }, 1001))
      .toThrowError(expect.objectContaining({ code: 'REVOKED' }))
  })
})

describe('handleRevoke', () => {
  it('revokes by license id, releases the seat and audits the action', () => {
    const f = fixture()
    f.store.putSeat({ sub: 'cust', packId: f.pack.packId, version: f.pack.version, devicePub: f.devicePub, licenseId: 'lic_full_1' })
    expect(handleRevoke(f.store, { license_id: 'lic_full_1' }, 2000)).toEqual({ status: 200, body: { revoked: 1 } })
    expect(f.store.getLicense('lic_full_1')?.revoked).toBe(true)
    expect(f.store.countSeats('cust', f.pack.packId, f.pack.version)).toBe(0)
    expect(f.store.listAudit().at(-1)).toMatchObject({ action: 'revoke', actor: 'admin' })
  })

  it('is idempotent and 404s when nothing matches', () => {
    const f = fixture()
    handleRevoke(f.store, { license_id: 'lic_full_1' }, 2000)
    expect(handleRevoke(f.store, { license_id: 'lic_full_1' }, 2001)).toEqual({ status: 200, body: { revoked: 0 } })
    expect(() => handleRevoke(f.store, { license_id: 'lic_nope' }, 2002))
      .toThrowError(expect.objectContaining({ status: 404, code: 'UNKNOWN_LICENSE' }))
  })
})
```

- [ ] **Step 2: 运行测试确认失败**

Run: `corepack pnpm -C packages/license-format test; corepack pnpm -C packages/license-server test`
Expected: FAIL —— `validateRevokeRequest`、`handleRenew`、`handleRevoke` 未导出。

- [ ] **Step 3: 实现**

`packages/license-format/src/protocol.ts` 追加：

```ts
export function validateRevokeRequest(value: unknown): RevokeRequest {
  const record = requireObject(value, 'revoke request')
  const request: RevokeRequest = {}
  if (record.license_id !== undefined) request.license_id = requireString(record.license_id, 'license_id')
  if (record.device_pub !== undefined) request.device_pub = requireString(record.device_pub, 'device_pub')
  if (record.seat !== undefined) request.seat = requireString(record.seat, 'seat')
  if (!request.license_id && !request.device_pub && !request.seat) {
    bad('revoke request needs at least one of license_id, device_pub or seat')
  }
  return request
}
```

（`requireObject` / `requireString` / `bad` 都是 Task 1 `protocol.ts` 里已有的私有助手，同文件直接使用。）

`packages/license-server/src/http.ts` 追加：

```ts
import { timingSafeEqual } from 'node:crypto'

/** 常量时间比较 `Authorization: Bearer <adminToken>`；缺失或不符返回 false。 */
export function isAuthorized(req: IncomingMessage, adminToken: string): boolean {
  const header = req.headers.authorization
  if (typeof header !== 'string' || !header.startsWith('Bearer ')) return false
  const provided = Buffer.from(header.slice('Bearer '.length), 'utf8')
  const expected = Buffer.from(adminToken, 'utf8')
  if (provided.length !== expected.length) return false
  return timingSafeEqual(provided, expected)
}
```

`packages/license-server/src/store.ts` 追加到 `Store` 类：

```ts
getLicensesForDevice(devicePub: string): LicenseRecord[] {
  const rows = this.db.prepare('SELECT * FROM licenses WHERE device_pub = ? ORDER BY iat').all(devicePub) as LicenseDbRow[]
  return rows.map((row) => this.toLicense(row))
}
```

`packages/license-server/src/routes.ts` 追加：

```ts
import { createPrivateKey, diffieHellman, timingSafeEqual } from 'node:crypto'
import {
  LICENSE_GRACE_SECONDS, LICENSE_TTL_SECONDS, MAX_CLOCK_SKEW_SECONDS, NONCE_TTL_SECONDS,
  deviceProofKey, deviceProofMac, deviceProofMessage, unb64u, validateRenewRequest,
  validateRevokeRequest, x25519PrivateFromRaw, x25519PublicFromRaw,
} from '@sealed/license-format'
import type { LicenseRecord } from './store.js'

function verifyDeviceProof(keys: ServerKeys, request: { license_id: string; device_pub: string; nonce: string; ts: number; mac: string }): void {
  let shared: Buffer
  try {
    shared = diffieHellman({
      privateKey: x25519PrivateFromRaw(keys.proofPrivateKey),
      publicKey: x25519PublicFromRaw(unb64u(request.device_pub)),
    })
  } catch {
    throw new HttpError(401, 'BAD_DEVICE_PROOF', 'device public key is not usable')
  }
  const expected = Buffer.from(deviceProofMac(deviceProofKey(shared, request.license_id), deviceProofMessage(request.license_id, request.nonce, request.ts)), 'base64url')
  const provided = Buffer.from(request.mac, 'base64url')
  if (provided.length !== expected.length || !timingSafeEqual(provided, expected)) {
    throw new HttpError(401, 'BAD_DEVICE_PROOF', 'device proof is not valid')
  }
}

export function handleRenew(store: Store, keys: ServerKeys, body: unknown, now: number): RouteResult {
  const request = validateRenewRequest(body)
  const record = store.getLicense(request.license_id)
  if (!record) throw new HttpError(404, 'UNKNOWN_LICENSE', 'unknown license')
  if (record.revoked) throw new HttpError(403, 'REVOKED', 'this license has been revoked')
  if (record.devicePub !== request.device_pub) throw new HttpError(401, 'BAD_DEVICE_PROOF', 'device proof does not match the license')
  if (Math.abs(now - request.ts) > MAX_CLOCK_SKEW_SECONDS) throw new HttpError(400, 'BAD_REQUEST', 'timestamp is outside the allowed clock skew window')
  verifyDeviceProof(keys, request)
  if (!store.insertNonce(request.license_id, request.nonce, now)) throw new HttpError(409, 'REPLAY', 'this nonce was already used')
  store.pruneNonces(0, now - NONCE_TTL_SECONDS)
  const pack = requirePack(store, record.packId, record.version)
  const master = unwrapPackMaster(store, keys, pack.packId, pack.version)
  let token: string
  try {
    token = issueLicense({
      licenseId: record.licenseId, sub: record.sub, pack, devicePubB64: record.devicePub,
      caps: record.caps as ('trial' | 'full')[], plan: record.plan, seatLimit: record.seatLimit, now,
    }, master, keys.licensePrivateKey)
  } finally {
    master.fill(0)
  }
  store.putLicense({
    ...record, iat: now, exp: now + LICENSE_TTL_SECONDS, graceUntil: now + LICENSE_TTL_SECONDS + LICENSE_GRACE_SECONDS,
  })
  store.appendAudit({ at: now, action: 'renew', actor: 'client', subject: record.licenseId, detail: record.packId + '@' + record.version })
  return { status: 200, body: { license: token } }
}

export function handleRevoke(store: Store, body: unknown, now: number): RouteResult {
  const request = validateRevokeRequest(body)
  const targets: LicenseRecord[] = []
  if (request.license_id) {
    const record = store.getLicense(request.license_id)
    if (record) targets.push(record)
  } else if (request.device_pub) {
    targets.push(...store.getLicensesForDevice(request.device_pub))
  } else if (request.seat) {
    const record = store.getLicense(request.seat)
    if (record) targets.push(record)
  }
  if (targets.length === 0) throw new HttpError(404, 'UNKNOWN_LICENSE', 'no license matched the revoke request')
  let revoked = 0
  for (const record of targets) {
    if (store.markRevoked(record.licenseId)) revoked++
    store.deleteSeat(record.sub, record.packId, record.version, record.devicePub)
    store.appendAudit({ at: now, action: 'revoke', actor: 'admin', subject: record.licenseId, detail: record.packId + '@' + record.version })
  }
  return { status: 200, body: { revoked } }
}
```

`packages/license-server/src/app.ts` 改为按路由声明鉴权（替换 Task 4 的 `Handler`/`routes` 部分）：

```ts
interface Route {
  handler: (body: unknown, now: number) => RouteResult | Promise<RouteResult>
  admin?: boolean
}

const routes: Record<string, Route> = {
  [ENDPOINTS.health]: { handler: () => ({ status: 200, body: { ok: true, version: String(PROTOCOL_VERSION) } }) },
  [ENDPOINTS.trial]: { handler: (body, t) => handleTrial(opts.store, opts.keys, body, t) },
  [ENDPOINTS.activate]: { handler: (body, t) => handleActivate(opts.store, opts.keys, body, t) },
  [ENDPOINTS.renew]: { handler: (body, t) => handleRenew(opts.store, opts.keys, body, t) },
  [ENDPOINTS.revoke]: { handler: (body, t) => handleRevoke(opts.store, body, t), admin: true },
}
```

请求分发替换为：

```ts
const path = (req.url ?? '').split('?')[0]
const route = routes[path]
if (!route || (req.method !== 'POST' && path !== ENDPOINTS.health)) { sendError(res, 404, 'BAD_REQUEST', 'no such endpoint'); return }
if (route.admin && !isAuthorized(req, opts.adminToken)) { sendError(res, 401, 'UNAUTHORIZED', 'admin token is missing or invalid'); return }
const body = path === ENDPOINTS.health ? undefined : await readJsonBody(req)
const result = await route.handler(body, now())
sendJson(res, result.status, result.body)
```

`packages/license-server/src/index.ts` 追加：

```ts
export * from './app.js'
export * from './routes.js'
```

- [ ] **Step 4: 运行测试确认通过**

Run: `corepack pnpm -C packages/license-format test; corepack pnpm -C packages/license-server test`
Expected: PASS（license-format 15；license-server 20 = store 6 + issue 5 + routes 5 + renew-revoke 4）。

- [ ] **Step 5: 提交**

```bash
git add packages/license-format packages/license-server
git commit -m "feat(license-server): add device-proof renew and admin revoke endpoints"
```
---

### Task 6: `/v1/admin/packs` 发布、幂等、限流与对抗输入

**Files:**
- Modify: `packages/license-server/src/http.ts`（追加 `createRateLimiter`）
- Modify: `packages/license-server/src/routes.ts`（追加 `handlePublishPack`）
- Modify: `packages/license-server/src/app.ts`（挂载 publish、限流、`AppOptions.rateLimit`）
- Modify: `packages/license-server/src/index.ts`（追加 `export * from './app.js'` 如未加）
- Test: `packages/license-server/test/publish.test.ts`
- Test: `packages/license-server/test/http.test.ts`

**Interfaces:**
- Consumes: `validatePublishPackRequest`、`unb64u`、`isRawEd25519Pub`（Task 1）；`Store`/`PackRecord`（Task 2）；`ServerKeys`、`wrapMaster`（Task 3）；`HttpError`、`isAuthorized`、`readJsonBody`（Task 3/5）。
- Produces:
  - `createRateLimiter(opts: { windowMs: number; max: number; now?: () => number }): { check(key: string): boolean }`
  - `handlePublishPack(store: Store, keys: ServerKeys, body: unknown, now: number): RouteResult`（幂等键 `publish:<packId>@<version>`，重复发布返回缓存响应，不重复写审计）
  - `AppOptions.rateLimit?: { windowMs: number; max: number }`（默认 `{ windowMs: 60000, max: 60 }`；超出 → 429 `RATE_LIMITED`）

- [ ] **Step 1: 写失败测试**

`packages/license-server/test/publish.test.ts`：

```ts
import { generateKeyPairSync } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import { b64u, rawPrivateBytes } from '@sealed/license-format'
import { handlePublishPack, loadServerKeys, openStore } from '../src/index.js'

function fixture() {
  const proof = generateKeyPairSync('x25519')
  const keys = loadServerKeys({
    SEALED_SERVER_LICENSE_KEY: (generateKeyPairSync('ed25519').privateKey.export({ format: 'jwk' }) as { d: string }).d,
    SEALED_SERVER_PROOF_KEY: rawPrivateBytes(proof.privateKey).toString('base64url'),
    SEALED_SERVER_MASTER_KEY: b64u(Buffer.alloc(32, 1)),
  } as NodeJS.ProcessEnv)
  return { keys, store: openStore(':memory:') }
}

const body = {
  pack: { id: 'com.example.p', version: '1.0.0' },
  author_pub: 'A'.repeat(43),
  label: '翻译',
  master_b64: Buffer.alloc(32, 3).toString('base64url'),
  trial_entries: ['meta'],
  entries: [{ id: 'meta', type: 'meta', size: 10 }, { id: 'skill:translate:body', type: 'text', size: 20 }],
}

describe('handlePublishPack', () => {
  it('stores the pack and returns a summary', () => {
    const f = fixture()
    const result = handlePublishPack(f.store, f.keys, body, 1000)
    expect(result.status).toBe(200)
    expect(f.store.getPack('com.example.p', '1.0.0')?.trialEntries).toEqual(['meta'])
    expect(f.store.getPack('com.example.p', '1.0.0')?.masterWrapped.startsWith('v1.')).toBe(true)
  })

  it('is idempotent: a repeated publish returns the cached response without a second audit row', () => {
    const f = fixture()
    const first = handlePublishPack(f.store, f.keys, body, 1000)
    const second = handlePublishPack(f.store, f.keys, body, 1001)
    expect(second).toEqual(first)
    expect(f.store.listAudit().filter((a) => a.action === 'publish').length).toBe(1)
  })

  it('rejects a malformed request and a bad master key with a structured 4xx', () => {
    const f = fixture()
    expect(() => handlePublishPack(f.store, f.keys, { ...body, author_pub: 'short' }, 1))
      .toThrowError(expect.objectContaining({ status: 400, code: 'BAD_REQUEST' }))
    expect(() => handlePublishPack(f.store, f.keys, { ...body, master_b64: 'AAAA' }, 1))
      .toThrowError(expect.objectContaining({ status: 400, code: 'BAD_REQUEST' }))
  })
})
```

`packages/license-server/test/http.test.ts`（真实 `http` 服务器 + `fetch`）：

```ts
import { generateKeyPairSync } from 'node:crypto'
import type { AddressInfo } from 'node:net'
import { afterEach, describe, expect, it } from 'vitest'
import { b64u, rawPrivateBytes } from '@sealed/license-format'
import { createApp, loadServerKeys, openStore, type Store } from '../src/index.js'

const ADMIN = 'test-admin-token'
const servers: { close: () => void }[] = []
const stores: Store[] = []

function start(opts: { rateLimit?: { windowMs: number; max: number } } = {}) {
  const proof = generateKeyPairSync('x25519')
  const keys = loadServerKeys({
    SEALED_SERVER_LICENSE_KEY: (generateKeyPairSync('ed25519').privateKey.export({ format: 'jwk' }) as { d: string }).d,
    SEALED_SERVER_PROOF_KEY: rawPrivateBytes(proof.privateKey).toString('base64url'),
    SEALED_SERVER_MASTER_KEY: b64u(Buffer.alloc(32, 1)),
  } as NodeJS.ProcessEnv)
  const store = openStore(':memory:')
  stores.push(store)
  const server = createApp({ store, keys, adminToken: ADMIN, ...opts })
  server.listen(0)
  servers.push(server)
  return new Promise<{ url: string; store: Store }>((resolve) => {
    server.once('listening', () => resolve({ url: 'http://127.0.0.1:' + (server.address() as AddressInfo).port, store }))
  })
}

afterEach(() => { for (const s of servers.splice(0)) s.close(); for (const s of stores.splice(0)) s.close() })

const pack = { pack: { id: 'com.example.p', version: '1' }, author_pub: 'A'.repeat(43), label: 'p', master_b64: b64u(Buffer.alloc(32, 3)), trial_entries: [], entries: [{ id: 'meta', type: 'meta', size: 1 }] }

describe('http app', () => {
  it('serves health and rejects unknown routes with a structured 404', async () => {
    const { url } = await start()
    expect(await (await fetch(url + '/v1/health')).json()).toMatchObject({ ok: true })
    const res = await fetch(url + '/v1/nope')
    expect(res.status).toBe(404)
    expect((await res.json()).error.code).toBe('BAD_REQUEST')
  })

  it('requires the admin bearer token for publishing', async () => {
    const { url } = await start()
    const unauthorized = await fetch(url + '/v1/admin/packs', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(pack) })
    expect(unauthorized.status).toBe(401)
    expect((await unauthorized.json()).error.code).toBe('UNAUTHORIZED')
    const ok = await fetch(url + '/v1/admin/packs', { method: 'POST', headers: { 'content-type': 'application/json', authorization: 'Bearer ' + ADMIN }, body: JSON.stringify(pack) })
    expect(ok.status).toBe(200)
  })

  it('answers malformed JSON, oversized bodies and bad input with 4xx, never 500', async () => {
    const { url } = await start()
    const headers = { 'content-type': 'application/json', authorization: 'Bearer ' + ADMIN }
    expect((await fetch(url + '/v1/admin/packs', { method: 'POST', headers, body: '{not json' })).status).toBe(400)
    const huge = await fetch(url + '/v1/admin/packs', { method: 'POST', headers, body: 'x'.repeat(1_048_577) })
    expect(huge.status).toBe(413)
    const res = await fetch(url + '/v1/admin/packs', { method: 'POST', headers, body: JSON.stringify({ pack: { id: 'p' } }) })
    expect(res.status).toBe(400)
    expect((await res.json()).error.code).toBe('BAD_REQUEST')
  })

  it('rate-limits a burst with 429 RATE_LIMITED', async () => {
    const { url } = await start({ rateLimit: { windowMs: 60000, max: 3 } })
    const headers = { 'content-type': 'application/json', authorization: 'Bearer ' + ADMIN }
    const codes: number[] = []
    for (let i = 0; i < 5; i++) codes.push((await fetch(url + '/v1/admin/packs', { method: 'POST', headers, body: JSON.stringify(pack) })).status)
    expect(codes.filter((c) => c === 200).length).toBe(3)
    expect(codes.at(-1)).toBe(429)
  })
})
```

- [ ] **Step 2: 运行测试确认失败**

Run: `corepack pnpm -C packages/license-server test`
Expected: FAIL —— `handlePublishPack` / `createApp` 的 `rateLimit` 未实现，`/v1/admin/packs` 返回 404。

- [ ] **Step 3: 实现**

`packages/license-server/src/http.ts` 追加：

```ts
/** 进程内滑动窗口限流；键通常是 `remoteAddress`。窗口外的时间戳会被裁剪。 */
export function createRateLimiter(opts: { windowMs: number; max: number; now?: () => number }): { check(key: string): boolean } {
  const now = opts.now ?? Date.now
  const hits = new Map<string, number[]>()
  return {
    check(key: string): boolean {
      const t = now()
      const recent = (hits.get(key) ?? []).filter((at) => t - at < opts.windowMs)
      if (recent.length >= opts.max) { hits.set(key, recent); return false }
      recent.push(t)
      hits.set(key, recent)
      if (hits.size > 10_000) for (const [k, v] of hits) if (v.every((at) => t - at >= opts.windowMs)) hits.delete(k)
      return true
    },
  }
}
```

`packages/license-server/src/routes.ts` 追加：

```ts
import { isRawEd25519Pub, validatePublishPackRequest } from '@sealed/license-format'
import { wrapMaster } from './master-store.js'
import type { PackRecord } from './store.js'

export function handlePublishPack(store: Store, keys: ServerKeys, body: unknown, now: number): RouteResult {
  const request = validatePublishPackRequest(body)
  if (!isRawEd25519Pub(request.author_pub)) throw new HttpError(400, 'BAD_REQUEST', 'author_pub must be a raw Ed25519 public key')
  const master = unb64u(request.master_b64)
  if (master.length !== 32) { master.fill(0); throw new HttpError(400, 'BAD_REQUEST', 'master_b64 must decode to exactly 32 bytes') }
  const idempotencyKey = 'publish:' + request.pack.id + '@' + request.pack.version
  const cached = store.getIdempotent(idempotencyKey)
  if (cached) return { status: 200, body: JSON.parse(cached) as unknown }
  let record: PackRecord
  try {
    record = {
      packId: request.pack.id, version: request.pack.version, label: request.label,
      authorPub: request.author_pub, masterWrapped: wrapMaster(master, keys.masterWrapKey),
      trialEntries: request.trial_entries, entries: request.entries,
    }
  } finally {
    master.fill(0)
  }
  store.putPack(record, now)
  store.appendAudit({ at: now, action: 'publish', actor: 'admin', subject: record.packId + '@' + record.version, detail: record.label })
  const response = { pack: { id: record.packId, version: record.version }, entries: record.entries.length }
  store.putIdempotent(idempotencyKey, JSON.stringify(response), now)
  return { status: 200, body: response }
}
```

`packages/license-server/src/app.ts`：`AppOptions` 增加 `rateLimit?: { windowMs: number; max: number }`；`createApp` 内构造 `const limiter = createRateLimiter(opts.rateLimit ?? { windowMs: 60_000, max: 60 })`；路由表追加 `[ENDPOINTS.publishPack]: { handler: (body, t) => handlePublishPack(opts.store, opts.keys, body, t), admin: true }`；在 admin 校验之后、读 body 之前插入限流：

```ts
if (req.method === 'POST' && path !== ENDPOINTS.health) {
  const key = req.socket.remoteAddress ?? 'unknown'
  if (!limiter.check(key)) { sendError(res, 429, 'RATE_LIMITED', 'too many requests'); return }
}
```

- [ ] **Step 4: 运行测试确认通过**

Run: `corepack pnpm -C packages/license-server test`
Expected: PASS（24 = store 6 + issue 5 + routes 5 + renew-revoke 4 + publish 3 + http 4，其中 http 的 `start` 会额外占用 4 个用例）。

- [ ] **Step 5: 提交**

```bash
git add packages/license-server
git commit -m "feat(license-server): publish packs with admin auth, idempotency and rate limiting"
```
---

### Task 7: 客户端授权状态机（`dsh-sealed-skills/src/license-client.ts`）

**Files:**
- Create: `packages/dsh-sealed-skills/src/license-client.ts`
- Modify: `packages/dsh-sealed-skills/src/index.ts`（追加 `export * from './license-client.js'`）
- Test: `packages/dsh-sealed-skills/test/license-client.test.ts`

**Interfaces:**
- Consumes: `ENDPOINTS`、`MAX_CLOCK_SKEW_SECONDS`、`RENEW_THRESHOLD_SECONDS`、`deviceProofKey`、`deviceProofMessage`、`deviceProofMac`、`licenseStatus`、`parseErrorEnvelope`、`verifyLicense`、`signLicense`（测试用）、`LicenseError`、`LicensePayload`、`PackRef`（Task 1）；`Keystore`、`x25519PrivateFromRaw`、`x25519PublicFromRaw`（M1）。
- Produces:
  - `type LicenseDenialCode = 'NO_LICENSE' | 'LICENSE_REVOKED' | 'LICENSE_EXPIRED' | 'CLOCK_UNTRUSTED' | 'SERVER_REJECTED' | 'SERVER_UNAVAILABLE' | 'BAD_SERVER_LICENSE'`
  - `class LicenseDenied extends Error { readonly code: LicenseDenialCode }`
  - `interface Entitlement { state: 'active' | 'grace'; license: string; payload: LicensePayload; source: 'cache' | 'network' }`
  - `interface LicenseClientOptions { serverUrl; serverProofPubB64; keystore; homeDir; trustedLicenseKeys; fetchFn?; now?; retry? }`
  - `class LicenseClient`：`constructor(opts)`、`ensureLicense(pack: PackRef): Promise<Entitlement>`、`activate(pack, purchaseToken)`、`activateTrial(pack)`、`renew(pack, licenseText)`、`importLicense(license, pack?)`
  - 磁盘布局：`$SEALED_HOME/licenses/<lid>.license.json`、`$SEALED_HOME/clock.json`（`{ v: 1, lastSeenMs }`）。

- [ ] **Step 1: 写失败测试**

`packages/dsh-sealed-skills/test/license-client.test.ts`：

```ts
import { createPublicKey, generateKeyPairSync, type KeyObject } from 'node:crypto'
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { b64u, rawPrivateBytes, rawPublicBytes, signLicense, type LicensePayload } from '@sealed/license-format'
import { LicenseClient, type LicenseClientOptions } from '../src/index.js'

const T0_SECONDS = 1_700_000_000
const T0_MS = T0_SECONDS * 1000
const PACK = { id: 'com.example.p', version: '1.0.0' }
type Queued = { status: number; body: unknown } | 'throw'

function createFixture() {
  const dir = mkdtempSync(join(tmpdir(), 'sealed-home-'))
  const signingKey = generateKeyPairSync('ed25519')
  const device = generateKeyPairSync('x25519')
  const privRaw = rawPrivateBytes(device.privateKey)
  const devicePub = rawPublicBytes(device.publicKey).toString('base64url')
  const responses: Queued[] = []
  const calls: Queued[] = []
  let nowMs = T0_MS
  const fetchFn = (async () => {
    const next = responses[calls.length] ?? 'throw'
    calls.push(next)
    if (next === 'throw') throw new Error('network down')
    return new Response(JSON.stringify(next.body), { status: next.status, headers: { 'content-type': 'application/json' } })
  }) as unknown as typeof fetch
  const keystore = {
    async loadDevicePrivateKey() { return Buffer.from(privRaw) },
    async loadDevicePublicKey() { return rawPublicBytes(device.publicKey) },
    async createDeviceKey() {},
    async deleteDeviceKey() {},
  }
  const opts: LicenseClientOptions = {
    serverUrl: 'http://127.0.0.1:1',
    serverProofPubB64: b64u(rawPublicBytes(generateKeyPairSync('x25519').publicKey)),
    keystore, homeDir: dir, trustedLicenseKeys: [createPublicKey(signingKey.publicKey) as KeyObject],
    fetchFn, now: () => nowMs, retry: { attempts: 2, baseMs: 1, maxMs: 2 },
  }
  const license = (over: Partial<{ lid: string; iat: number; expOffset: number; pack: LicensePayload['pack']; dev: string }> = {}) =>
    signLicense({
      v: 1, lid: over.lid ?? 'lic_1', sub: 'cust', pack: over.pack ?? { ...PACK, author_pub: 'A'.repeat(43) },
      dev: over.dev ?? devicePub, iat: over.iat ?? T0_SECONDS, exp: (over.iat ?? T0_SECONDS) + (over.expOffset ?? 604800),
      grace_until: (over.iat ?? T0_SECONDS) + (over.expOffset ?? 604800) + 259200,
      caps: ['full'], groups: ['pro'], keys: [], seats: { plan: 'pro', limit: 1 },
    }, signingKey.privateKey)
  return {
    dir, calls, license, devicePub,
    client: new LicenseClient(opts),
    setNow: (ms: number) => { nowMs = ms },
    respond: (...next: Queued[]) => { responses.splice(0, responses.length, ...next); calls.length = 0 },
    writeCached: (text: string, lid = 'lic_1') => writeFileSync(join(dir, 'licenses', lid + '.license.json'), text),
    cachedPath: (lid = 'lic_1') => join(dir, 'licenses', lid + '.license.json'),
  }
}

describe('LicenseClient', () => {
  it('returns a cached active license without touching the network', async () => {
    const f = createFixture()
    f.writeCached(f.license())
    const ent = await f.client.ensureLicense(PACK)
    expect(ent.state).toBe('active')
    expect(ent.source).toBe('cache')
    expect(f.calls.length).toBe(0)
  })

  it('stays usable in grace offline and never mutates state on a network failure', async () => {
    const f = createFixture()
    f.respond('throw')
    const text = f.license({ iat: T0_SECONDS - 604800 - 60, expOffset: 0 })
    f.writeCached(text)
    const ent = await f.client.ensureLicense(PACK)
    expect(ent.state).toBe('grace')
    expect(ent.source).toBe('cache')
    expect(readFileSync(f.cachedPath(), 'utf8')).toBe(text)
    expect(existsSync(join(f.dir, 'clock.json'))).toBe(false)
  })

  it('renews an expired license online and writes the new license', async () => {
    const f = createFixture()
    const fresh = f.license({ lid: 'lic_old', iat: T0_SECONDS, expOffset: 604800 })
    f.respond({ status: 200, body: { license: fresh } })
    f.writeCached(f.license({ lid: 'lic_old', iat: T0_SECONDS - 604800 - 259200 - 10, expOffset: 0 }), 'lic_old')
    const ent = await f.client.ensureLicense(PACK)
    expect(ent.state).toBe('active')
    expect(ent.source).toBe('network')
    expect(readFileSync(f.cachedPath('lic_old'), 'utf8')).toBe(fresh)
  })

  it('removes the cached license and denies when the server reports REVOKED', async () => {
    const f = createFixture()
    f.respond({ status: 403, body: { error: { code: 'REVOKED', message: 'revoked' } } })
    f.writeCached(f.license({ iat: T0_SECONDS - 604800 - 259200 - 10, expOffset: 0 }))
    await expect(f.client.ensureLicense(PACK)).rejects.toMatchObject({ code: 'LICENSE_REVOKED' })
    expect(existsSync(f.cachedPath())).toBe(false)
  })

  it('denies with CLOCK_UNTRUSTED when the clock rolled back and the server is unreachable', async () => {
    const f = createFixture()
    f.respond('throw')
    f.writeCached(f.license())
    f.setNow(T0_MS - 3_600_000)
    await expect(f.client.ensureLicense(PACK)).rejects.toMatchObject({ code: 'CLOCK_UNTRUSTED' })
  })

  it('retries a 5xx and succeeds on the next attempt', async () => {
    const f = createFixture()
    const fresh = f.license({ lid: 'lic_old', iat: T0_SECONDS })
    f.respond({ status: 500, body: {} }, { status: 200, body: { license: fresh } })
    f.writeCached(f.license({ lid: 'lic_old', iat: T0_SECONDS - 604800 - 259200 - 10, expOffset: 0 }), 'lic_old')
    const ent = await f.client.ensureLicense(PACK)
    expect(ent.source).toBe('network')
    expect(f.calls.length).toBe(2)
  })

  it('rejects a license for another pack without writing it', async () => {
    const f = createFixture()
    const other = f.license({ lid: 'lic_other', pack: { id: 'com.other', version: '1.0.0', author_pub: 'A'.repeat(43) } })
    f.respond({ status: 200, body: { license: other } })
    f.writeCached(f.license({ iat: T0_SECONDS - 604800 - 259200 - 10, expOffset: 0 }))
    await expect(f.client.ensureLicense(PACK)).rejects.toMatchObject({ code: 'BAD_SERVER_LICENSE' })
    expect(existsSync(f.cachedPath('lic_other'))).toBe(false)
  })

  it('maps a SEAT_LIMIT rejection on activate to SERVER_REJECTED without writing a license', async () => {
    const f = createFixture()
    f.respond({ status: 409, body: { error: { code: 'SEAT_LIMIT', message: 'no seats' } } })
    await expect(f.client.activate(PACK, 'purchase-token')).rejects.toMatchObject({ code: 'SERVER_REJECTED' })
    expect(f.calls.length).toBe(1)
  })
})
```

以上 8 个用例只使用**假**的 `fetch`；真实密钥接线与端到端回路由 Task 9 覆盖。

- [ ] **Step 2: 运行测试确认失败**

Run: `corepack pnpm -C packages/dsh-sealed-skills test`
Expected: FAIL —— `../src/index.js` 未导出 `LicenseClient` / `LicenseDenied`。

- [ ] **Step 3: 实现**

`packages/dsh-sealed-skills/src/license-client.ts`：

```ts
import { chmodSync, mkdirSync, readdirSync, readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs'
import { diffieHellman, randomBytes, type KeyObject } from 'node:crypto'
import { join } from 'node:path'
import {
  ENDPOINTS, LicenseError, MAX_CLOCK_SKEW_SECONDS, RENEW_THRESHOLD_SECONDS,
  deviceProofKey, deviceProofMac, deviceProofMessage, isRawX25519Pub, licenseStatus,
  parseErrorEnvelope, unb64u, verifyLicense,
  type LicensePayload, type PackRef,
} from '@sealed/license-format'
import { x25519PrivateFromRaw, x25519PublicFromRaw, type Keystore } from './keystore.js'

export type LicenseDenialCode =
  | 'NO_LICENSE' | 'LICENSE_REVOKED' | 'LICENSE_EXPIRED' | 'CLOCK_UNTRUSTED'
  | 'SERVER_REJECTED' | 'SERVER_UNAVAILABLE' | 'BAD_SERVER_LICENSE'

export class LicenseDenied extends Error {
  constructor(readonly code: LicenseDenialCode, message: string) {
    super(message)
    this.name = 'LicenseDenied'
  }
}

export interface Entitlement {
  state: 'active' | 'grace'
  license: string
  payload: LicensePayload
  source: 'cache' | 'network'
}

export interface LicenseClientOptions {
  // 两者都可选：纯离线（只读缓存 / 导入离线 license）时无需配置；在线方法在调用时才校验。
  serverUrl?: string
  serverProofPubB64?: string
  keystore: Keystore
  homeDir: string
  trustedLicenseKeys: KeyObject[]
  fetchFn?: typeof fetch
  now?: () => number
  retry?: { attempts: number; baseMs: number; maxMs: number }
}

interface ClockState { v: 1; lastSeenMs: number }
type Envelope = { status: number; body: Record<string, unknown> }

export class LicenseClient {
  private readonly fetchFn: typeof fetch
  private readonly retry: { attempts: number; baseMs: number; maxMs: number }
  private readonly licensesDir: string
  private readonly clockPath: string
  private devicePub?: string

  constructor(private readonly opts: LicenseClientOptions) {
    this.fetchFn = opts.fetchFn ?? globalThis.fetch
    this.retry = opts.retry ?? { attempts: 3, baseMs: 200, maxMs: 2000 }
    this.licensesDir = join(opts.homeDir, 'licenses')
    this.clockPath = join(opts.homeDir, 'clock.json')
    mkdirSync(this.licensesDir, { recursive: true })
  }

  async ensureLicense(pack: PackRef): Promise<Entitlement> {
    await this.devicePublicB64()
    const cached = this.readCached(pack)
    const rolledBack = this.clockRolledBack()
    if (cached && !rolledBack) {
      const status = licenseStatus(cached.payload, this.nowMs())
      const secondsLeft = cached.payload.exp - Math.floor(this.nowMs() / 1000)
      if (status === 'active' && secondsLeft > RENEW_THRESHOLD_SECONDS) {
        return this.accept(cached.payload.pack, cached.license, 'cache')
      }
    }
    if (cached) {
      let renewError: unknown
      try {
        return await this.renew(pack, cached.license)
      } catch (error) {
        renewError = error
      }
      if (renewError instanceof LicenseDenied && renewError.code === 'SERVER_UNAVAILABLE') {
        if (rolledBack) throw new LicenseDenied('CLOCK_UNTRUSTED', 'the local clock moved backwards and the license server is unreachable')
        const status = licenseStatus(cached.payload, this.nowMs())
        if (status !== 'expired') return { state: status, license: cached.license, payload: cached.payload, source: 'cache' }
      }
      throw renewError
    }
    throw new LicenseDenied('NO_LICENSE', 'no license is available for this pack')
  }

  async activate(pack: PackRef, purchaseToken: string): Promise<Entitlement> {
    await this.devicePublicB64()
    const response = await this.post(ENDPOINTS.activate, { device_pub: this.devicePub, purchase_token: purchaseToken, pack })
    if (response.status !== 200) throw this.rejected(response)
    return this.accept(pack, String(response.body.license), 'network')
  }

  async activateTrial(pack: PackRef): Promise<Entitlement> {
    await this.devicePublicB64()
    const response = await this.post(ENDPOINTS.trial, { device_pub: this.devicePub, pack })
    if (response.status !== 200) throw this.rejected(response)
    return this.accept(pack, String(response.body.license), 'network')
  }

  async renew(pack: PackRef, licenseText: string): Promise<Entitlement> {
    await this.devicePublicB64()
    const payload = this.parseTrusted(licenseText)
    for (let attempt = 0; attempt < 2; attempt++) {
      const proof = await this.proofFor(payload.lid)
      const response = await this.post(ENDPOINTS.renew, {
        license_id: payload.lid, device_pub: this.devicePub, nonce: proof.nonce, ts: proof.ts, mac: proof.mac,
      })
      if (response.status === 200) return this.accept(pack, String(response.body.license), 'network')
      const parsed = parseErrorEnvelope(response.body)
      if (parsed?.code === 'REPLAY') continue
      if (parsed?.code === 'REVOKED') {
        rmSync(join(this.licensesDir, payload.lid + '.license.json'), { force: true })
        throw new LicenseDenied('LICENSE_REVOKED', parsed.message)
      }
      throw this.rejected(response)
    }
    throw new LicenseDenied('SERVER_REJECTED', 'the license server kept rejecting the renewal nonce')
  }

  /** 导入离线预置的 license（校验签名与设备绑定后落盘）。 */
  async importLicense(license: string, pack?: PackRef): Promise<Entitlement> {
    await this.devicePublicB64()
    const payload = this.parseTrusted(license)
    if (pack && (payload.pack.id !== pack.id || payload.pack.version !== pack.version)) {
      throw new LicenseDenied('BAD_SERVER_LICENSE', 'license is for a different pack')
    }
    return this.accept(payload.pack, license, 'cache')
  }

  private parseTrusted(license: string): LicensePayload {
    try {
      return verifyLicense(license, this.opts.trustedLicenseKeys)
    } catch (error) {
      throw new LicenseDenied('BAD_SERVER_LICENSE', error instanceof LicenseError ? error.message : 'license is not trusted')
    }
  }

  private accept(pack: PackRef, license: string, source: 'cache' | 'network'): Entitlement {
    const payload = this.parseTrusted(license)
    if (payload.pack.id !== pack.id || payload.pack.version !== pack.version) {
      throw new LicenseDenied('BAD_SERVER_LICENSE', 'license is for a different pack')
    }
    if (payload.dev !== this.devicePub) throw new LicenseDenied('BAD_SERVER_LICENSE', 'license is bound to a different device')
    this.writeFile(join(this.licensesDir, payload.lid + '.license.json'), license)
    this.advanceClock(payload.iat * 1000)
    const status = licenseStatus(payload, this.nowMs())
    return { state: status === 'grace' ? 'grace' : 'active', license, payload, source }
  }

  private readCached(pack: PackRef): { license: string; payload: LicensePayload } | undefined {
    let names: string[]
    try {
      names = readdirSync(this.licensesDir)
    } catch {
      return undefined
    }
    for (const name of names) {
      if (!name.endsWith('.license.json')) continue
      const text = readFileSync(join(this.licensesDir, name), 'utf8')
      let payload: LicensePayload
      try {
        payload = verifyLicense(text, this.opts.trustedLicenseKeys)
      } catch {
        continue
      }
      if (payload.pack.id === pack.id && payload.pack.version === pack.version) return { license: text, payload }
    }
    return undefined
  }

  private async devicePublicB64(): Promise<string> {
    if (!this.devicePub) {
      const pub = await this.opts.keystore.loadDevicePublicKey()
      if (!pub) throw new LicenseDenied('NO_LICENSE', 'no device key is available')
      this.devicePub = pub.toString('base64url')
    }
    return this.devicePub
  }

  private async proofFor(licenseId: string): Promise<{ nonce: string; ts: number; mac: string }> {
    const nonce = randomBytes(16).toString('base64url')
    const ts = Math.floor(this.nowMs() / 1000)
    const proofPub = this.opts.serverProofPubB64
    if (!proofPub || !isRawX25519Pub(proofPub)) throw new LicenseDenied('SERVER_UNAVAILABLE', 'no license server proof key is configured')
    const peer = unb64u(proofPub)
    let shared: Buffer
    if (this.opts.keystore.ecdh) {
      shared = await this.opts.keystore.ecdh(peer)
    } else {
      const raw = await this.opts.keystore.loadDevicePrivateKey()
      if (!raw) throw new LicenseDenied('NO_LICENSE', 'no device key is available')
      try {
        shared = diffieHellman({ privateKey: x25519PrivateFromRaw(raw), publicKey: x25519PublicFromRaw(peer) })
      } finally {
        raw.fill(0)
      }
    }
    return { nonce, ts, mac: deviceProofMac(deviceProofKey(shared, licenseId), deviceProofMessage(licenseId, nonce, ts)) }
  }

  private async post(path: string, body: unknown): Promise<Envelope> {
    if (!this.opts.serverUrl) throw new LicenseDenied('SERVER_UNAVAILABLE', 'no license server URL is configured')
    const url = this.opts.serverUrl.replace(/\/+$/, '') + path
    let lastError: unknown
    for (let attempt = 0; attempt < this.retry.attempts; attempt++) {
      try {
        const res = await this.fetchFn(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) })
        if (res.status >= 500) {
          lastError = new Error('license server responded ' + res.status)
          await this.backoff(attempt)
          continue
        }
        const parsed: unknown = await res.json().catch(() => ({}))
        return { status: res.status, body: (parsed ?? {}) as Record<string, unknown> }
      } catch (error) {
        lastError = error
        await this.backoff(attempt)
      }
    }
    throw new LicenseDenied('SERVER_UNAVAILABLE', 'license server is unreachable: ' + (lastError instanceof Error ? lastError.message : String(lastError)))
  }

  private async backoff(attempt: number): Promise<void> {
    const capped = Math.min(this.retry.maxMs, this.retry.baseMs * 2 ** attempt)
    await new Promise((resolve) => setTimeout(resolve, capped * (0.5 + Math.random() * 0.5)))
  }

  private rejected(response: Envelope): LicenseDenied {
    const parsed = parseErrorEnvelope(response.body)
    if (parsed?.code === 'REVOKED') return new LicenseDenied('LICENSE_REVOKED', parsed.message)
    return new LicenseDenied('SERVER_REJECTED', 'license server rejected the request (' + response.status + ')')
  }

  private nowMs(): number {
    return this.opts.now ? this.opts.now() : Date.now()
  }

  private readClock(): ClockState {
    try {
      const parsed = JSON.parse(readFileSync(this.clockPath, 'utf8')) as Partial<ClockState>
      if (parsed && parsed.v === 1 && typeof parsed.lastSeenMs === 'number') return { v: 1, lastSeenMs: parsed.lastSeenMs }
    } catch {
      // 缺少或损坏的时钟文件视为“没有观测锚点”。
    }
    return { v: 1, lastSeenMs: 0 }
  }

  private clockRolledBack(): boolean {
    return this.nowMs() + MAX_CLOCK_SKEW_SECONDS * 1000 < this.readClock().lastSeenMs
  }

  private advanceClock(ms: number): void {
    if (ms <= this.readClock().lastSeenMs) return
    this.writeFile(this.clockPath, JSON.stringify({ v: 1, lastSeenMs: ms }))
  }

  private writeFile(path: string, text: string): void {
    const tmp = path + '.tmp'
    writeFileSync(tmp, text, { encoding: 'utf8', mode: 0o600 })
    try { chmodSync(tmp, 0o600) } catch { /* Windows 依赖用户目录 ACL */ }
    renameSync(tmp, path)
  }
}
```

`packages/dsh-sealed-skills/src/index.ts` 追加：

```ts
export * from './license-client.js'
```

- [ ] **Step 4: 运行测试确认通过**

Run: `corepack pnpm -C packages/dsh-sealed-skills test`
Expected: PASS（M1 的 40 + 新增 8 = 48）。

- [ ] **Step 5: 提交**

```bash
git add packages/dsh-sealed-skills
git commit -m "feat(dsh-sealed-skills): add online license client with grace and clock-rollback handling"
```
---

### Task 8: 接入插件与 `author_pub` 绑定（移除 M1 占位符）

**Files:**
- Modify: `packages/dsh-sealed-skills/src/core.ts`（构造函数去掉 `authorPublicKeyB64`，改从 license 取作者键）
- Modify: `packages/dsh-sealed-skills/src/plugin.ts`（`LicenseClient` 接线；mount 支持 licensePath / purchaseToken / trial）
- Modify: `packages/dsh-sealed-skills/test/core.test.ts`（移除全部 `authorPublicKeyB64`，新增 1 个 PACK_SIGNATURE 用例）
- Modify: `packages/dsh-sealed-skills/test/plugin.test.ts`（移除 mount 上的 `authorPublicKeyB64`）
- Modify: `packages/seal-cli/src/trial.ts`（`author_pub` 改为真实作者公钥）
- Modify: `packages/seal-cli/src/cli.ts`（`seal trial` usage 文案改为“作者本地试用，签发键即作者键”）
- Modify: `scripts/m1-smoke.mjs`（去掉 `authorPublicKeyB64`）
- Modify: `docs/sealed-skills/notes/trial-license-author-pub-placeholder.md`（标记被 M2 取代）
- Test: `packages/dsh-sealed-skills/test/core.test.ts`、`packages/dsh-sealed-skills/test/plugin.test.ts`

**Interfaces:**
- Consumes: `SealedCore`（M1）、`LicenseClient`/`LicenseDenied`/`Entitlement`（Task 7）、`readContainer`（`@sealed/pack-format`）。
- Produces:
  - `SealedCore` 新签名：`new SealedCore({ pack, license, trustedLicenseKeys, keystore, now? })`；`get licensePayload(): LicensePayload`
  - `SealedPackMount = { packPath; licensePath?; purchaseToken?; trial? }`（删除 `authorPublicKeyB64`）
  - `SealedSkillsConfig` 增加 `serverUrl?` / `serverProofPubB64?`
  - `apply()`：每个 mount 懒加载 `SealedCore`；缺 license 时按 `purchaseToken` → `trial` 顺序在线激活，全部失败则该 mount 静默跳过（fail-closed）。

- [ ] **Step 1: 改测试（失败）**

`packages/dsh-sealed-skills/test/core.test.ts`：
1. 全文删除 `authorPublicKeyB64: ed25519RawX(...),`（共 16 处），构造参数只留 `pack`/`license`/`trustedLicenseKeys`/`keystore`。
2. 追加新用例：

```ts
it("verifies the manifest with the author_pub carried by the license, rejecting a mismatch", async () => {
  const ks = await newKeystore()
  const otherAuthor = generateKeyPairSync('ed25519')
  const license = licenseFor(await ks.loadDevicePublicKey()!, ['meta', 'skill:translate:body'], {
    pack: { id: packId, version, author_pub: ed25519RawX(otherAuthor.publicKey) },
  })
  expect(() => new SealedCore({ pack, license, trustedLicenseKeys: [author.publicKey], keystore: ks }))
    .toThrowError(expect.objectContaining({ code: 'PACK_SIGNATURE' }))
})
```

`packages/dsh-sealed-skills/test/plugin.test.ts`：把两处 `{ packPath, licensePath, authorPublicKeyB64: 'x' }` 改为 `{ packPath, licensePath }`，并给这些 mount 的 config 提供该文件内容所需的 `trustedLicenseKeysB64`（现有用例只验证“坏 mount 被跳过”，保留原有断言不变即可）。

- [ ] **Step 2: 运行测试确认失败**

Run: `corepack pnpm -C packages/dsh-sealed-skills test`
Expected: FAIL —— `SealedCore` 仍要求 `authorPublicKeyB64`，新用例的 `PACK_SIGNATURE` 尚未触发。

- [ ] **Step 3: 实现**

`packages/dsh-sealed-skills/src/core.ts` 构造函数替换为：

```ts
constructor(private readonly opts: {
  pack: Buffer
  license: string
  trustedLicenseKeys: KeyObject[]
  keystore: Keystore
  now?: () => number
}) {
  this.parsed = readContainer(opts.pack)
  this.payload = verifyLicense(opts.license, opts.trustedLicenseKeys)
  if (this.payload.pack.id !== this.parsed.manifest.pack_id || this.payload.pack.version !== this.parsed.manifest.version) {
    throw new SealedError('LICENSE_INVALID', 'license is for a different pack or version')
  }
  // Review Focus 6：作者公钥只能来自已签名的 license，绝不接受调用方传入。
  let authorKey: KeyObject
  try {
    authorKey = createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: this.payload.pack.author_pub }, format: 'jwk' })
  } catch {
    throw new SealedError('PACK_SIGNATURE', 'license carries an unusable author public key')
  }
  if (!verifyManifestSignature(this.parsed.manifestBytes, this.parsed.signature, authorKey)) {
    throw new SealedError('PACK_SIGNATURE', 'pack manifest signature does not match the author key in the license')
  }
}
```

并在类中追加：

```ts
/** 已校验的 license 载荷（只读），供上层判定授权状态。 */
get licensePayload(): LicensePayload { return this.payload }
```

`packages/dsh-sealed-skills/src/plugin.ts` 整体替换为：

```ts
import { readFileSync } from 'node:fs'
import { createPublicKey } from 'node:crypto'
import { join } from 'node:path'
import { readContainer } from '@sealed/pack-format'
import { SealedCore } from './core.js'
import { FileKeystore } from './keystore.js'
import { LicenseClient, LicenseDenied, type Entitlement } from './license-client.js'
import { createDshSkillProvider, type DshSkillProvider, type DshSkillProviderControl } from './provider.js'

/** One installed pack. Provide `licensePath` for an offline license, or `purchaseToken`/`trial` for online activation. */
export interface SealedPackMount {
  readonly packPath: string
  readonly licensePath?: string
  readonly purchaseToken?: string
  readonly trial?: boolean
}

export interface SealedSkillsConfig {
  readonly mounts?: SealedPackMount[]
  readonly trustedLicenseKeysB64?: string[]
  readonly serverUrl?: string
  readonly serverProofPubB64?: string
  readonly keystoreDir?: string
  readonly rank?: number
}

export interface SkillsContext {
  readonly skills: {
    registerProvider(create: (control: DshSkillProviderControl) => DshSkillProvider): () => void
  }
}

export const name = 'sealed-skills'
export const inject = ['skills']

export function apply(ctx: SkillsContext, config: SealedSkillsConfig = {}): () => void {
  const mounts = config.mounts ?? []
  const homeDir = config.keystoreDir ?? process.env.SEALED_HOME ?? join(process.cwd(), '.sealed-home')
  const keystore = new FileKeystore({ dir: homeDir })
  const trustedLicenseKeys = (config.trustedLicenseKeysB64 ?? []).map((key) =>
    createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: key }, format: 'jwk' }))
  const client = new LicenseClient({
    serverUrl: config.serverUrl ?? process.env.SEALED_SERVER_URL,
    serverProofPubB64: config.serverProofPubB64 ?? process.env.SEALED_SERVER_PROOF_PUB,
    keystore, homeDir, trustedLicenseKeys,
  })

  const cores = new Map<string, Promise<SealedCore>>()
  const coreFor = (mount: SealedPackMount): Promise<SealedCore> => {
    let pending = cores.get(mount.packPath)
    if (!pending) {
      pending = buildCore(mount).catch((error: unknown) => { cores.delete(mount.packPath); throw error })
      cores.set(mount.packPath, pending)
    }
    return pending
  }

  async function buildCore(mount: SealedPackMount): Promise<SealedCore> {
    const pack = readFileSync(mount.packPath)
    const manifest = readContainer(pack).manifest
    const packRef = { id: manifest.pack_id, version: manifest.version }
    let entitlement: Entitlement
    if (mount.licensePath) {
      entitlement = await client.importLicense(readFileSync(mount.licensePath, 'utf8'), packRef)
    } else {
      try {
        entitlement = await client.ensureLicense(packRef)
      } catch (error) {
        if (!(error instanceof LicenseDenied) || error.code !== 'NO_LICENSE') throw error
        if (mount.purchaseToken) entitlement = await client.activate(packRef, mount.purchaseToken)
        else if (mount.trial) entitlement = await client.activateTrial(packRef)
        else throw error
      }
    }
    return new SealedCore({ pack, license: entitlement.license, trustedLicenseKeys, keystore })
  }

  const aggregate = {
    async list() {
      const summaries = []
      for (const mount of mounts) {
        try {
          summaries.push(...await (await coreFor(mount)).list())
        } catch {
          // fail closed per mount
        }
      }
      return summaries
    },
    async readSkill(skillName: string) {
      for (const mount of mounts) {
        try {
          const core = await coreFor(mount)
          if (!(await core.list()).some((skill) => skill.name === skillName)) continue
          return await core.readSkill(skillName)
        } catch {
          continue
        }
      }
      throw new Error('no such sealed skill')
    },
  }

  return ctx.skills.registerProvider((control) =>
    createDshSkillProvider(aggregate, { rank: config.rank, signal: control.signal }))
}

export const plugin = { name, inject, apply }
export default plugin
```

`packages/seal-cli/src/trial.ts`：把 `author_pub` 改为真实作者公钥——

```ts
import { createPublicKey, randomBytes, type KeyObject } from 'node:crypto'
// …
const authorPub = rawPublicBytes(createPublicKey(opts.signingKey)).toString('base64url')
// …
pack: { id: opts.manifest.pack_id, version: opts.manifest.version, author_pub: authorPub },
```

`packages/seal-cli/src/cli.ts`：`USAGE` 中 `seal trial` 一行改为
`'  seal trial <pack> --master <x.master.json> --device-pub <b64url> --days <n> --key <author.key.json> [-o <out.license>]   # local trial; the author key is the license signer',`

`scripts/m1-smoke.mjs`：删除 `authorPublicKeyB64: author.publicKey.export({ format: 'jwk' }).x,` 一行（作者键现在由 license 携带）。

- [ ] **Step 4: 更新文档**

`docs/sealed-skills/notes/trial-license-author-pub-placeholder.md` 顶部追加：

```md
> **SUPERSEDED (M2):** The placeholder no longer exists. Both the license server and the
> local `seal trial` path now put the real author Ed25519 public key in `pack.author_pub`,
> and `SealedCore` verifies the manifest with that key. This note is kept only for history.
```

- [ ] **Step 5: 运行测试与冒烟确认通过**

Run: `corepack pnpm -r build; corepack pnpm -C packages/dsh-sealed-skills test; corepack pnpm -C packages/seal-cli test; node scripts/m1-smoke.mjs`
Expected: 全绿；`m1-smoke.mjs` 打印 `disk-leak-check: clean`。

- [ ] **Step 6: 提交**

```bash
git add packages/dsh-sealed-skills packages/seal-cli scripts docs
git commit -m "feat: bind manifest verification to the license author_pub and wire the license client"
```
---

### Task 9: 端到端集成、冒烟脚本、退出标准与开发者文档

**Files:**
- Modify: `packages/dsh-sealed-skills/package.json`（devDependency 增加 `@sealed/license-server`）
- Create: `packages/dsh-sealed-skills/test/e2e-licensing.test.ts`
- Create: `scripts/m2-smoke.mjs`
- Create: `docs/sealed-skills/spec/protocol.md`
- Create: `docs/sealed-skills/guide/publish-and-license.md`
- Create: `docs/sealed-skills/guide/for-skill-developers.md`
- Modify: `docs/sealed-skills/README.md`、`docs/sealed-skills/guide/author-quickstart.md`
- Modify: `package.json`（根：`"smoke:m2": "node scripts/m2-smoke.mjs"`）

**Interfaces:**
- Consumes: 全部前序任务的产物（server 的 `createApp`/`openStore`/`loadServerKeys`/`serverLicensePublicB64`/`putPurchase`，client 的 `LicenseClient`、`SealedCore`、`FileKeystore`）。
- Produces: 一条真实 HTTP 回路的集成测试 + 可人工运行的冒烟脚本 + 面向开发者的协议与接入文档。

- [ ] **Step 1: 写端到端失败测试**

`packages/dsh-sealed-skills/test/e2e-licensing.test.ts`：

```ts
import { createPublicKey, generateKeyPairSync, randomBytes } from 'node:crypto'
import { mkdtempSync } from 'node:fs'
import type { AddressInfo } from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'
import { deriveEntryKey, encodeManifest, entryAad, sealEntry, signManifest, writeContainer, type PackEntryMeta, type PackManifest } from '@sealed/pack-format'
import { b64u, rawPrivateBytes, signLicense, wrapEntryKey, type LicensePayload } from '@sealed/license-format'
import { createApp, loadServerKeys, openStore, serverLicensePublicB64, type Store } from '@sealed/license-server'
import { SealedCore } from '../src/core.js'
import { LicenseClient } from '../src/license-client.js'
import { FileKeystore } from '../src/keystore.js'

const packId = 'com.example.translate'
const version = '1.0.0'
const ADMIN = 'admin-token'
const master = randomBytes(32)
const author = generateKeyPairSync('ed25519')
const authorPub = (author.publicKey.export({ format: 'jwk' }) as { x: string }).x

function buildPack(): Buffer {
  const entries: { id: string; type: PackEntryMeta['type']; body: string }[] = [
    { id: 'meta', type: 'meta', body: JSON.stringify({ skills: [{ name: 'translate', description: '翻译', invocation: { modelInvocable: true, userInvocable: true }, entries: ['skill:translate:body'] }], resources: {} }) },
    { id: 'skill:translate:body', type: 'text', body: '把用户输入翻译成英文。\n' },
  ]
  const manifest: PackManifest = { pack_id: packId, version, label: '翻译', entry_count: entries.length, entries: [] }
  const chunks = entries.map((entry) => {
    const key = deriveEntryKey(master, packId, version, entry.id)
    const sealed = sealEntry(key, entryAad(packId, version, entry.id), Buffer.from(entry.body, 'utf8'))
    manifest.entries.push({ id: entry.id, type: entry.type, size: sealed.ct.length, trial: entry.id !== 'skill:translate:body' })
    return { id: entry.id, nonce: sealed.nonce, ct: sealed.ct }
  })
  return writeContainer({ manifest, chunks, signature: signManifest(encodeManifest(manifest), author.privateKey) })
}

let current: { close: () => void } | undefined
afterEach(() => { current?.close(); current = undefined })

async function startServer() {
  const proofKey = generateKeyPairSync('x25519')
  const keys = loadServerKeys({
    SEALED_SERVER_LICENSE_KEY: (generateKeyPairSync('ed25519').privateKey.export({ format: 'jwk' }) as { d: string }).d,
    SEALED_SERVER_PROOF_KEY: rawPrivateBytes(proofKey.privateKey).toString('base64url'),
    SEALED_SERVER_MASTER_KEY: b64u(Buffer.alloc(32, 4)),
  } as NodeJS.ProcessEnv)
  const store = openStore(':memory:')
  const server = createApp({ store, keys, adminToken: ADMIN })
  server.listen(0)
  current = server
  await new Promise<void>((resolve) => server.once('listening', () => resolve()))
  const url = 'http://127.0.0.1:' + (server.address() as AddressInfo).port
  return { url, store, keys, licensePublic: serverLicensePublicB64(keys) }
}

async function newClient(url: string, serverProofPubB64: string, licensePubB64: string, homeDir: string) {
  const keystore = new FileKeystore({ dir: homeDir })
  await keystore.createDeviceKey()
  return new LicenseClient({
    serverUrl: url, serverProofPubB64, keystore, homeDir,
    trustedLicenseKeys: [createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: licensePubB64 }, format: 'jwk' })],
    retry: { attempts: 2, baseMs: 1, maxMs: 2 },
  })
}

const packRef = { id: packId, version }

describe('M2 licensing end to end', () => {
  it('publishes, activates, decrypts, renews and then fails to renew after a revoke', async () => {
    const { url, store, keys, licensePublic } = await startServer()
    const pack = buildPack()
    const published = await fetch(url + '/v1/admin/packs', {
      method: 'POST', headers: { 'content-type': 'application/json', authorization: 'Bearer ' + ADMIN },
      body: JSON.stringify({
        pack: packRef, author_pub: authorPub, label: '翻译', master_b64: master.toString('base64url'),
        trial_entries: ['meta'], entries: [{ id: 'meta', type: 'meta', size: 1 }, { id: 'skill:translate:body', type: 'text', size: 1 }],
      }),
    })
    expect(published.status).toBe(200)
    store.putPurchase({ token: 'purchase-1', sub: 'cust', packId, version, plan: 'pro', seats: 1 })

    const home = mkdtempSync(join(tmpdir(), 'sealed-home-'))
    const client = await newClient(url, keys.proofPublicB64, licensePublic, home)
    const entitlement = await client.activate(packRef, 'purchase-1')
    expect(entitlement.state).toBe('active')

    const keystore = new FileKeystore({ dir: home })
    const core = new SealedCore({
      pack, license: entitlement.license, keystore,
      trustedLicenseKeys: [createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: licensePublic }, format: 'jwk' })],
    })
    expect((await core.list()).map((s) => s.name)).toEqual(['translate'])
    expect((await core.readSkill('translate')).content).toBe('把用户输入翻译成英文。\n')

    const renewed = await client.renew(packRef, entitlement.license)
    expect(renewed.source).toBe('network')

    const revoked = await fetch(url + '/v1/revoke', {
      method: 'POST', headers: { 'content-type': 'application/json', authorization: 'Bearer ' + ADMIN },
      body: JSON.stringify({ license_id: entitlement.payload.lid }),
    })
    expect((await revoked.json()).revoked).toBe(1)
    await expect(client.renew(packRef, renewed.license)).rejects.toMatchObject({ code: 'LICENSE_REVOKED' })
  })

  it('grants a server trial only the trial entries and refuses the rest', async () => {
    const { url, store, keys, licensePublic } = await startServer()
    const pack = buildPack()
    await fetch(url + '/v1/admin/packs', {
      method: 'POST', headers: { 'content-type': 'application/json', authorization: 'Bearer ' + ADMIN },
      body: JSON.stringify({ pack: packRef, author_pub: authorPub, label: '翻译', master_b64: master.toString('base64url'), trial_entries: ['meta'], entries: [{ id: 'meta', type: 'meta', size: 1 }, { id: 'skill:translate:body', type: 'text', size: 1 }] }),
    })
    const home = mkdtempSync(join(tmpdir(), 'sealed-home-'))
    const client = await newClient(url, keys.proofPublicB64, licensePublic, home)
    const trial = await client.activateTrial(packRef)
    expect(trial.payload.caps).toEqual(['trial'])
    const core = new SealedCore({
      pack, license: trial.license, keystore: new FileKeystore({ dir: home }),
      trustedLicenseKeys: [createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: licensePublic }, format: 'jwk' })],
    })
    await expect(core.readSkill('translate')).rejects.toMatchObject({ code: 'NOT_GRANTED' })
    expect(store.getTrial(await (new FileKeystore({ dir: home })).loadDevicePublicKey().then((b) => b!.toString('base64url')), packId, version)).toBeDefined()
  })
})
```

- [ ] **Step 2: 运行测试确认失败**

Run: `corepack pnpm -C packages/dsh-sealed-skills test`
Expected: FAIL —— 未声明 `@sealed/license-server` devDependency，导入失败。

- [ ] **Step 3: 接线并跑通**

`packages/dsh-sealed-skills/package.json` 的 `devDependencies` 增加 `"@sealed/license-server": "workspace:*"`，然后 `corepack pnpm install`，并 `corepack pnpm -r build` 让 `@sealed/license-server/dist` 就位（集成测试按 workspace 包的 `main` 解析）。

Run: `corepack pnpm -C packages/dsh-sealed-skills test`
Expected: PASS（dsh-sealed-skills 50 = 48 + 2 集成）。

- [ ] **Step 4: 写冒烟脚本**

`scripts/m2-smoke.mjs`（`node scripts/m2-smoke.mjs`）：复用 `scripts/m1-smoke.mjs` 的 `demo/translate` 与泄漏检查，但走真实授权服务器——进程内 `createApp`（`127.0.0.1:0`），`/v1/admin/packs` 发布 pack，`store.putPurchase` 造一张票，`LicenseClient.activate` 激活，`SealedCore` 读出正文，`/v1/revoke` 吊销后再续期应失败。脚本最后打印：
```
m2-smoke: publish → activate → decrypt → renew → revoke → renew-denied OK
m2-smoke: trial grants only trial entries OK
disk-leak-check: clean (no plaintext body in .sealed-home/ artifacts)
```
并在根 `package.json` 增加 `"smoke:m2": "node scripts/m2-smoke.mjs"`。

- [ ] **Step 5: 写文档**

`docs/sealed-skills/spec/protocol.md`（协议参考，必须包含）：
- 版本与常量表：`PROTOCOL_VERSION=1`、`LICENSE_TTL_SECONDS=604800`、`LICENSE_GRACE_SECONDS=259200`、`RENEW_THRESHOLD_SECONDS=172800`、`MAX_CLOCK_SKEW_SECONDS=300`、`NONCE_TTL_SECONDS=600`、`MAX_BODY_BYTES=1048576`。
- 端点表（方法、路径、鉴权、请求体、成功响应、错误码）：
  - `GET /v1/health` → `{ ok: true, version }`（无鉴权）
  - `POST /v1/trial` → `{ license }`；错误 `PACK_NOT_FOUND`(404)、`TRIAL_ALREADY_USED`(409)
  - `POST /v1/activate` → `{ license }`；错误 `BAD_PURCHASE_TOKEN`(401)、`PACK_NOT_FOUND`(404)、`SEAT_LIMIT`(409)
  - `POST /v1/renew` → `{ license }`；错误 `UNKNOWN_LICENSE`(404)、`REVOKED`(403)、`BAD_DEVICE_PROOF`(401)、`BAD_REQUEST`(400，时间戳超窗)、`REPLAY`(409)
  - `POST /v1/revoke`（`Authorization: Bearer <admin token>`）→ `{ revoked }`；错误 `UNAUTHORIZED`(401)、`UNKNOWN_LICENSE`(404)
  - `POST /v1/admin/packs`（Bearer）→ `{ pack, entries }`；错误 `UNAUTHORIZED`(401)、`BAD_REQUEST`(400)
  - 统一错误信封 `{ error: { code, message } }`；错误码全集见 Task 1 的 `ProtocolErrorCode`。
- 设备证明算法（逐字照抄 Global Constraints 里的 DH-MAC 公式与 `deviceProofMessage` 的拼接顺序），并给出客户端伪代码。
- 请求示例与响应示例（各端点一条 JSON）。
- 版本协商与兼容策略：未知字段容忍、`v` 不匹配的处理（服务端拒绝新 major，客户端拒绝未知 major）。

`docs/sealed-skills/guide/publish-and-license.md`（作者接入指南）：
- 服务端部署：环境变量 `SEALED_SERVER_LICENSE_KEY`/`SEALED_SERVER_PROOF_KEY`/`SEALED_SERVER_MASTER_KEY`（各为 base64url 32 字节）、`SEALED_SERVER_ADMIN_TOKEN`、`SEALED_SERVER_PORT`、`SEALED_SERVER_DB`；`node packages/license-server/dist/bin.js`。
- 作者流程：`seal keygen` → `seal pack`（产出 `.sealedpack` 与 `.master.json`）→ `POST /v1/admin/packs` 登记（只上传 master，不上传明文）→ 在自己的计费系统里为买家签发 `purchase_token` → 交付 `.sealedpack` + `purchase_token`。
- 用户流程：配置 `serverUrl` + `serverProofPubB64` + 受信任的 license 签名公钥 → 首次使用 `purchaseToken` 在线激活 → 之后离线宽限。
- 续期/吊销/席位：TTL 7 天、宽限 3 天、`renew` 在 `exp` 前 2 天起触发；吊销在 TTL 内生效（客户端下次续期失败）；席位随吊销释放。
- 安全清单：密钥只放服务端；`master.json` 不入包、不进 git；管理接口只在私网暴露；审计表保留。

`docs/sealed-skills/guide/for-skill-developers.md`（生态邀请，面向新作者）：
- 这个生态解决什么：源码不出包、按设备授权、可试用、可续费/吊销。
- 五分钟上手：从 `author-quickstart` 到 `publish-and-license` 的最短路径，含可复制的命令块。
- 商业模式示例：订阅（续期）、席位（团队）、试用（`trial_entries`）。
- 参与方式：运行时适配器接口（M1 的 `SealedCore`/`SkillProvider`）、密钥库后端（Plan 2B）、协议扩展（`protocol.ts` 单一真源）。
- 明确边界与残余风险（威胁模型 B）：有能力的用户仍可从内存中取回明文；不要把它当作 DRM。

`docs/sealed-skills/README.md`：新增“M2：授权闭环”一节（三个部件、如何本地起服务、`smoke:m2` 命令），并把仓库布局更新为 5 个 M1 包 + `license-server`。
`docs/sealed-skills/guide/author-quickstart.md`：在“打包”之后追加“登记到授权服务器并签发 purchase token”的步骤，链接到新文档。

- [ ] **Step 6: 全量验证**

Run: `corepack pnpm -r build; corepack pnpm -r test; node scripts/m2-smoke.mjs`
Expected: 全绿；`m2-smoke` 三段输出均 OK。

- [ ] **Step 7: 提交**

```bash
git add -A
git commit -m "test(m2): end-to-end licensing tests, smoke script and developer documentation"
```

---

## M2 Exit Criteria（合并前必须全部成立）

- [ ] `corepack pnpm -r build` 与 `corepack pnpm -r test` 全绿；M1 的 126 个测试无一回归。
- [ ] `node scripts/m1-smoke.mjs` 与 `node scripts/m2-smoke.mjs` 均通过，且都打印 `disk-leak-check: clean`。
- [ ] 授权闭环可复现：发布 → 激活 → 解密读取 → 续期 → 吊销 → 续期被拒。
- [ ] 试用只解锁 `trial_entries`：非试用条目返回 `NOT_GRANTED`，同一设备二次试用返回 `TRIAL_ALREADY_USED`。
- [ ] 断网时宽限期内的已授权 skill 仍可用；断网不会写入任何新 license 或推进时钟锚点。
- [ ] 重放 nonce、`|now - ts| > 300`、时钟回拨均被拒。
- [ ] 席位并发激活不超卖；吊销后席位被释放。
- [ ] 服务端对畸形/超长/未授权请求只返回结构化 4xx/429，日志与响应不含技能内容或密钥字节。
- [ ] license 的 `pack.author_pub` 与包 manifest 的签名键不一致时构造 `SealedCore` 抛 `PACK_SIGNATURE`。
- [ ] 文档齐全：`docs/sealed-skills/spec/protocol.md`、`guide/publish-and-license.md`、`guide/for-skill-developers.md`。

## 后续（Plan 2B，另行成文）

OS 密钥库后端（Windows DPAPI / macOS Keychain / Linux libsecret）、缺省 fail-closed 与 `--allow-file-keystore` 显式退路、按平台 CI。Plan 2B 复用本计划的 `Keystore` 接口与 `LicenseClient`，不改协议。

## Self-Review

**1. Spec coverage**

| Spec 章节 | 落点 |
| --- | --- |
| §6.3 客户端 bundle | Task 7（license-client）、Task 8（plugin 接线）、Plan 2B（OS keystore） |
| §6.4 服务端 | Task 2（存储）、Task 3（密钥/签发）、Task 4/5/6（端点） |
| §7.2 激活 | Task 1（`ActivateRequest`）、Task 4（`handleActivate`）、Task 7（`activate`）、Task 9（e2e） |
| §7.4 续期 | Task 1（`RenewRequest`/设备证明）、Task 5（`handleRenew`）、Task 7（`renew`）、Task 9（e2e） |
| §7.5 吊销 | Task 5（`handleRevoke`）、Task 7（`REVOKED` → 删缓存）、Task 9（e2e） |
| §7.6 试用 | Task 4（`handleTrial`）、Task 7（`activateTrial`）、Task 9（e2e） |
| §8 错误处理与降级 | Review Focus 1；Task 7（`ensureLicense` 宽限 + 不改状态）、Task 6（结构化 4xx/429） |
| §9 技术选型 | Global Constraints（Node 内置 crypto、`node:http`、`node:sqlite`、无第三方运行时依赖） |
| §5.2 license 令牌 | 沿用 M1 格式；`pack.author_pub` 真实化见 Task 8 |

**2. Placeholder scan**

无 “TBD/TODO/待定/fill in” 之类占位；文档任务给出必须包含的章节与关键事实表。Task 3 的 `SEALED_SERVER_LICENSE_KEY_PEM` 退路已在正文说明为“仅当某 Node 版本不接受 JWK `d` 时启用”。

**3. Type consistency**

- `ServerError`(code)/`HttpError`(status, code) 在 Task 2/3 定义，Task 5/6 一致使用 `expect.objectContaining({ status, code })`。
- `Store.getLicensesForDevice` 在 Task 5 才新增，Task 5 的 `handleRevoke` 与其一致。
- `LicenseClientOptions.serverUrl` / `serverProofPubB64` 为可选（Task 7 已按此写，plugin 在离线 mount 下也无需配置它们）。
- `Entitlement.source` 取值 `'cache' | 'network'`，Task 7/9 断言一致；`SealedCore` 去掉了 `authorPublicKeyB64`，Task 8 同步更新测试与冒烟脚本。
- `createRateLimiter` 返回 `{ check(key): boolean }`，Task 6 的 app 使用一致。

**4. Review Focus 覆盖**

1. 宽限期可用性 → Task 7「stays usable in grace offline and never mutates state」+ Task 9 e2e。
2. 重放/时间回拨 → Task 5「rejects a replayed nonce and an out-of-window timestamp」+ Task 7「CLOCK_UNTRUSTED」。
3. 席位/吊销竞态 → Task 5「revokes by license id, releases the seat」+ Task 9 e2e 吊销后续期失败。
4. 密钥库不可用/损坏 → M1 的 core.test「corrupt device keystore」「foreign device key」；Plan 2B 补 OS 后端。
5. 服务端输入对抗 → Task 6「answers malformed JSON, oversized bodies and bad input with 4xx, never 500」+ 限流用例。
6. `author_pub` 绑定 → Task 8 新增 `PACK_SIGNATURE` 用例。

*修订记录：初稿由 Task 1–4 起；本轮补全 Task 5–9、退出标准与自检。*