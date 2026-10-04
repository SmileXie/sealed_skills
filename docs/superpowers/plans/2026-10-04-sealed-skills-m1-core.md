# Sealed Skills M1（加密核心与虚拟技能加载）Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 打通「作者打包 → 本地签发试用 license → 插件在内存中解密、以无路径虚拟技能提供」的最小可用闭环。

**Architecture:** pnpm monorepo，五个包：`canonical-json`（JCS 子集）、`pack-format`（容器 / 密钥派生 / AEAD）、`license-format`（令牌 / X25519 编解码 / CK 封装）、`seal-cli`（作者工具）、`dsh-sealed-skills`（运行时：keystore + core + registry + provider）。M1 不含授权服务器（试用 license 用本地 dev 密钥签发）、不含日志掩码与脚本执行（M3）。

**Tech Stack:** TypeScript（ESM / NodeNext）、Node ≥ 20 内置 `crypto`（X25519 / HKDF-SHA256 / AES-256-GCM / Ed25519）、vitest、pnpm（corepack）。

**Spec:** `docs/superpowers/specs/2026-10-04-sealed-skills-design.md`

## Global Constraints

- Node ≥ 20（本机 24.x）；包管理器 pnpm，命令统一写 `corepack pnpm <cmd>`；TS ESM，`moduleResolution: NodeNext`，`strict: true`。
- 密码学只用 Node 内置 `crypto`；M1 不引入任何第三方加密库。
- pack 容器 `format_version = 1`；license `v = 1`；字节布局见 spec §5.1 / §5.2。
- `CK_i = HKDF-SHA256(master, salt = utf8(pack_id)||0x00||utf8(version), info = utf8("entry:")||utf8(entry_id), 32)`。
- `entry AAD = utf8(pack_id)||0x00||utf8(version)||0x00||utf8(entry_id)`。
- `KEK = HKDF-SHA256(ECDH(eph_priv, dev_pub), salt = utf8(lid), info = utf8("wrap:")||utf8(eid), 32)`；`wrap AAD = utf8(lid)||0x00||utf8(eid)`。
- 条目 id 约定：`meta` / `skill:<name>:body` / `skill:<name>:res:<path>` / `script:<name>:<path>` / `data:<name>`。
- 不变量：磁盘上不得出现明文技能正文 / 脚本；错误消息、日志、异常对象不得包含明文内容。
- 所有二进制字段用 base64url 无填充编码。
- 单条目密文上限 32 MiB（`33554432` 字节），超限报错。

## Review Focus

1. 二进制资源（png / 字体 / zip）条目必须字节级往返一致，不能被当作 UTF-8 破坏。
2. 单条目接近 32 MiB 上限时不 OOM、不静默截断；超限给明确错误。
3. 截断 / 损坏 / 篡改的 pack 文件必须报明确错误，绝不返回部分明文或让宿主崩溃。
4. 空目录或缺少 frontmatter 的 SKILL.md 必须给可执行错误，绝不产出空包。
5. 含 `:`、空格、unicode 的条目 id 与资源相对路径必须派生确定，且映射资源路径时不得路径穿越（`..`）。

---

### Task 1: Monorepo 骨架 + `@sealed/canonical-json`

**Files:**
- Create: `package.json`、`pnpm-workspace.yaml`、`tsconfig.base.json`、`.gitignore`
- Create: `packages/canonical-json/{package.json,tsconfig.json,vitest.config.ts,src/index.ts}`
- Test: `packages/canonical-json/test/canonical-json.test.ts`

**Interfaces:**
- Produces: `canonicalJson(value: unknown): string`、`class CanonicalJsonError extends Error`

- [ ] **Step 1: 建骨架文件**

`.gitignore`：
```
node_modules/
dist/
.dsh-checkout/
.sealed-home/
*.sealedpack
*.master.json
*.license
```

`pnpm-workspace.yaml`：
```yaml
packages:
  - packages/*
```

根 `package.json`：
```json
{
  "name": "sealed-skills",
  "private": true,
  "type": "module",
  "scripts": {
    "test": "corepack pnpm -r test",
    "build": "corepack pnpm -r build"
  },
  "devDependencies": {
    "typescript": "^5.6.0",
    "vitest": "^2.1.0",
    "@types/node": "^22.0.0"
  }
}
```

`tsconfig.base.json`：
```json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "NodeNext",
    "moduleResolution": "NodeNext",
    "strict": true,
    "declaration": true,
    "skipLibCheck": true,
    "types": ["node"]
  }
}
```

每个包用同一套 `tsconfig.json` 与 `vitest.config.ts`：

`packages/canonical-json/tsconfig.json`：
```json
{ "extends": "../../tsconfig.base.json", "compilerOptions": { "outDir": "dist", "rootDir": "src" }, "include": ["src"] }
```

`packages/canonical-json/vitest.config.ts`：
```ts
import { defineConfig } from 'vitest/config'
export default defineConfig({ test: { include: ['test/**/*.test.ts'] } })
```

`packages/canonical-json/package.json`：
```json
{
  "name": "@sealed/canonical-json",
  "version": "0.1.0",
  "type": "module",
  "main": "dist/index.js",
  "types": "dist/index.d.ts",
  "scripts": { "build": "tsc -p tsconfig.json", "test": "vitest run" }
}
```

- [ ] **Step 2: 写失败测试**

`packages/canonical-json/test/canonical-json.test.ts`：
```ts
import { describe, expect, it } from 'vitest'
import { canonicalJson, CanonicalJsonError } from '../src/index.js'

describe('canonicalJson', () => {
  it('sorts object keys by UTF-16 code units', () => {
    expect(canonicalJson({ b: 1, a: 2, A: 3 })).toBe('{"A":3,"a":2,"b":1}')
  })

  it('serializes nested structures without whitespace', () => {
    expect(canonicalJson({ z: [1, true, null], a: { y: 'x' } })).toBe('{"a":{"y":"x"},"z":[1,true,null]}')
  })

  it('drops undefined properties but rejects undefined inside arrays', () => {
    expect(canonicalJson({ a: undefined, b: 1 })).toBe('{"b":1}')
    expect(() => canonicalJson([undefined])).toThrow(CanonicalJsonError)
  })

  it('rejects non-integer numbers', () => {
    expect(() => canonicalJson(1.5)).toThrow(CanonicalJsonError)
    expect(() => canonicalJson(2 ** 53)).toThrow(CanonicalJsonError)
  })

  it('keeps unicode literal and escapes control characters', () => {
    expect(canonicalJson({ s: '译\n' })).toBe('{"s":"译\\n"}')
  })
})
```

- [ ] **Step 3: 运行测试确认失败**

Run: `corepack pnpm -C packages/canonical-json test`
Expected: FAIL —— 无法解析 `../src/index.js`（文件不存在）。

- [ ] **Step 4: 实现**

`packages/canonical-json/src/index.ts`：
```ts
export class CanonicalJsonError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'CanonicalJsonError'
  }
}

/**
 * RFC 8785 的子集：对象键按 UTF-16 code unit 升序，无空白，
 * 仅支持 string / boolean / null / 安全整数 / 数组 / 普通对象。
 */
export function canonicalJson(value: unknown): string {
  if (value === null) return 'null'
  switch (typeof value) {
    case 'boolean':
      return value ? 'true' : 'false'
    case 'number':
      if (!Number.isSafeInteger(value)) throw new CanonicalJsonError('only safe integers are supported')
      return Object.is(value, -0) ? '0' : String(value)
    case 'string':
      return JSON.stringify(value)
    case 'object': {
      if (Array.isArray(value)) {
        return '[' + value.map((item) => {
          if (item === undefined) throw new CanonicalJsonError('undefined is not allowed in arrays')
          return canonicalJson(item)
        }).join(',') + ']'
      }
      const obj = value as Record<string, unknown>
      const keys = Object.keys(obj).filter((k) => obj[k] !== undefined).sort()
      return '{' + keys.map((k) => JSON.stringify(k) + ':' + canonicalJson(obj[k])).join(',') + '}'
    }
    default:
      throw new CanonicalJsonError('unsupported type: ' + typeof value)
  }
}
```

- [ ] **Step 5: 运行测试确认通过**

Run: `corepack pnpm -C packages/canonical-json test`
Expected: PASS（5 passed）。

- [ ] **Step 6: 提交**

```bash
git add package.json pnpm-workspace.yaml tsconfig.base.json .gitignore packages/canonical-json
git commit -m "feat(canonical-json): add JCS subset serializer with monorepo scaffold"
```
---

### Task 2: `@sealed/pack-format` 密钥派生与条目 AEAD

**Files:**
- Create: `packages/pack-format/{package.json,tsconfig.json,vitest.config.ts}`
- Create: `packages/pack-format/src/{aad.ts,keys.ts,aead.ts,index.ts}`
- Test: `packages/pack-format/test/{keys.test.ts,aead.test.ts}`

**Interfaces:**
- Produces:
  - `entryAad(packId: string, version: string, entryId: string): Buffer`
  - `deriveEntryKey(master: Buffer, packId: string, version: string, entryId: string): Buffer`
  - `sealEntry(key: Buffer, aad: Buffer, plaintext: Buffer): { nonce: Buffer; ct: Buffer }`
  - `openEntry(key: Buffer, aad: Buffer, nonce: Buffer, ct: Buffer): Buffer`

- [ ] **Step 1: 包配置**

`packages/pack-format/package.json`（`tsconfig.json`、`vitest.config.ts` 与 Task 1 完全相同）：
```json
{
  "name": "@sealed/pack-format",
  "version": "0.1.0",
  "type": "module",
  "main": "dist/index.js",
  "types": "dist/index.d.ts",
  "scripts": { "build": "tsc -p tsconfig.json", "test": "vitest run" }
}
```

- [ ] **Step 2: 写失败测试**

`packages/pack-format/test/keys.test.ts`：
```ts
import { describe, expect, it } from 'vitest'
import { deriveEntryKey, entryAad } from '../src/index.js'

const master = Buffer.alloc(32, 7)

describe('deriveEntryKey', () => {
  it('is deterministic and 32 bytes', () => {
    const a = deriveEntryKey(master, 'com.x.p', '1.0.0', 'meta')
    expect(a.length).toBe(32)
    expect(a.equals(deriveEntryKey(master, 'com.x.p', '1.0.0', 'meta'))).toBe(true)
  })

  it('separates entries, versions and packs', () => {
    const base = deriveEntryKey(master, 'com.x.p', '1.0.0', 'a')
    expect(base.equals(deriveEntryKey(master, 'com.x.p', '1.0.0', 'b'))).toBe(false)
    expect(base.equals(deriveEntryKey(master, 'com.x.p', '1.0.1', 'a'))).toBe(false)
    expect(base.equals(deriveEntryKey(master, 'com.x.q', '1.0.0', 'a'))).toBe(false)
  })
})

describe('entryAad', () => {
  it('is unambiguous across the separator', () => {
    expect(entryAad('p', '1', 'a:b').equals(entryAad('p:1', '', 'a:b'))).toBe(false)
  })
})
```

`packages/pack-format/test/aead.test.ts`：
```ts
import { describe, expect, it } from 'vitest'
import { deriveEntryKey, entryAad, openEntry, sealEntry } from '../src/index.js'

const key = deriveEntryKey(Buffer.alloc(32, 1), 'com.x.p', '1.0.0', 'data:blob')
const aad = entryAad('com.x.p', '1.0.0', 'data:blob')

describe('entry AEAD', () => {
  it('round-trips utf8 text', () => {
    const { nonce, ct } = sealEntry(key, aad, Buffer.from('译\n文', 'utf8'))
    expect(ct.length).toBe(Buffer.byteLength('译\n文') + 16)
    expect(openEntry(key, aad, nonce, ct).toString('utf8')).toBe('译\n文')
  })

  it('round-trips binary bytes exactly', () => {
    const blob = Buffer.from(Array.from({ length: 4096 }, (_, i) => (i * 37) % 256))
    const { nonce, ct } = sealEntry(key, aad, blob)
    expect(openEntry(key, aad, nonce, ct).equals(blob)).toBe(true)
  })

  it('rejects a flipped ciphertext byte', () => {
    const { nonce, ct } = sealEntry(key, aad, Buffer.from('hello'))
    ct[0] = ct[0] ^ 0xff
    expect(() => openEntry(key, aad, nonce, ct)).toThrow()
  })

  it('rejects a mismatched AAD', () => {
    const { nonce, ct } = sealEntry(key, aad, Buffer.from('hello'))
    expect(() => openEntry(key, entryAad('com.x.p', '1.0.0', 'data:other'), nonce, ct)).toThrow()
  })

  it('rejects ciphertext shorter than the auth tag', () => {
    expect(() => openEntry(key, aad, Buffer.alloc(12), Buffer.alloc(8))).toThrow('ciphertext too short')
  })
})
```

- [ ] **Step 3: 运行测试确认失败**

Run: `corepack pnpm -C packages/pack-format test`
Expected: FAIL —— `../src/index.js` 不存在。

- [ ] **Step 4: 实现**

`packages/pack-format/src/aad.ts`：
```ts
const SEP = Buffer.from([0x00])

/** 用 0x00 分隔拼接，避免 id/version/pack 拼接歧义。 */
export function entryAad(packId: string, version: string, entryId: string): Buffer {
  return Buffer.concat([
    Buffer.from(packId, 'utf8'),
    SEP,
    Buffer.from(version, 'utf8'),
    SEP,
    Buffer.from(entryId, 'utf8'),
  ])
}
```

`packages/pack-format/src/keys.ts`：
```ts
import { hkdfSync } from 'node:crypto'

export const KEY_BYTES = 32

export function deriveEntryKey(master: Buffer, packId: string, version: string, entryId: string): Buffer {
  const salt = Buffer.concat([Buffer.from(packId, 'utf8'), Buffer.from([0x00]), Buffer.from(version, 'utf8')])
  const info = Buffer.concat([Buffer.from('entry:', 'utf8'), Buffer.from(entryId, 'utf8')])
  return Buffer.from(hkdfSync('sha256', master, salt, info, KEY_BYTES))
}
```

`packages/pack-format/src/aead.ts`：
```ts
import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto'

export const NONCE_BYTES = 12
export const TAG_BYTES = 16

export function sealEntry(key: Buffer, aad: Buffer, plaintext: Buffer): { nonce: Buffer; ct: Buffer } {
  const nonce = randomBytes(NONCE_BYTES)
  const cipher = createCipheriv('aes-256-gcm', key, nonce)
  cipher.setAAD(aad)
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()])
  return { nonce, ct }
}

export function openEntry(key: Buffer, aad: Buffer, nonce: Buffer, ct: Buffer): Buffer {
  if (ct.length < TAG_BYTES) throw new Error('ciphertext too short')
  const tag = ct.subarray(ct.length - TAG_BYTES)
  const body = ct.subarray(0, ct.length - TAG_BYTES)
  const decipher = createDecipheriv('aes-256-gcm', key, nonce)
  decipher.setAAD(aad)
  decipher.setAuthTag(tag)
  return Buffer.concat([decipher.update(body), decipher.final()])
}
```

`packages/pack-format/src/index.ts`：
```ts
export * from './aad.js'
export * from './keys.js'
export * from './aead.js'
export * from './container.js'
```
（Task 3 才会创建 `container.ts`；本步骤先只写前三行，Task 3 再加第四行。）

- [ ] **Step 5: 运行测试确认通过**

Run: `corepack pnpm -C packages/pack-format test`
Expected: PASS（7 passed）。

- [ ] **Step 6: 提交**

```bash
git add packages/pack-format
git commit -m "feat(pack-format): add entry key derivation and AEAD"
```
---

### Task 3: `@sealed/pack-format` 容器读写与签名

**Files:**
- Create: `packages/pack-format/src/container.ts`
- Modify: `packages/pack-format/src/index.ts`（追加一行导出）
- Test: `packages/pack-format/test/container.test.ts`

**Interfaces:**
- Consumes: `NONCE_BYTES`（Task 2）。
- Produces:
  - `type PackEntryType = 'meta' | 'text' | 'script' | 'data'`
  - `interface PackEntryMeta { id: string; type: PackEntryType; size: number; trial: boolean }`
  - `interface PackManifest { pack_id: string; version: string; label: string; entry_count: number; entries: PackEntryMeta[] }`
  - `const PACK_MAGIC = 'SLDSK1'`、`const PACK_FORMAT_VERSION = 1`、`const MAX_ENTRY_BYTES = 33554432`
  - `class PackFormatError extends Error { code: 'BAD_MAGIC'|'BAD_VERSION'|'TRUNCATED'|'BAD_MANIFEST'|'TOO_LARGE'|'TABLE_MISMATCH' }`
  - `writeContainer(input: { manifest: PackManifest; chunks: { id: string; nonce: Buffer; ct: Buffer }[]; signature: Buffer }): Buffer`
  - `readContainer(buf: Buffer): { manifest: PackManifest; manifestBytes: Buffer; signature: Buffer; chunks: { id: string; offset: number; nonce: Buffer; ct: Buffer }[] }`
  - `signManifest(manifestBytes: Buffer, privateKey: KeyObject): Buffer`
  - `verifyManifestSignature(manifestBytes: Buffer, signature: Buffer, publicKey: KeyObject): boolean`

- [ ] **Step 1: 写失败测试**

`packages/pack-format/test/container.test.ts`：
```ts
import { generateKeyPairSync } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import {
  MAX_ENTRY_BYTES, readContainer, signManifest, verifyManifestSignature, writeContainer,
} from '../src/index.js'
import type { PackManifest } from '../src/index.js'

const { privateKey, publicKey } = generateKeyPairSync('ed25519')

function buildFixture() {
  const manifest: PackManifest = {
    pack_id: 'com.example.translate', version: '1.0.0', label: '翻译助手', entry_count: 1,
    entries: [{ id: 'meta', type: 'meta', size: 21, trial: true }],
  }
  const signature = signManifest(Buffer.from(JSON.stringify(manifest)), privateKey)
  const file = writeContainer({ manifest, chunks: [{ id: 'meta', nonce: Buffer.alloc(12, 3), ct: Buffer.alloc(21, 9) }], signature })
  return { manifest, file, signature }
}

describe('container', () => {
  it('round-trips manifest, signature and chunk offsets', () => {
    const { manifest, file, signature } = buildFixture()
    const parsed = readContainer(file)
    expect(parsed.manifest).toEqual(manifest)
    expect(parsed.signature.equals(signature)).toBe(true)
    expect(parsed.chunks[0].ct.length).toBe(21)
    expect(file.subarray(parsed.chunks[0].offset, parsed.chunks[0].offset + 12).equals(Buffer.alloc(12, 3))).toBe(true)
  })

  it('verifies a good signature and rejects a tampered manifest', () => {
    const { manifest, signature } = buildFixture()
    const bytes = Buffer.from(JSON.stringify(manifest))
    expect(verifyManifestSignature(bytes, signature, publicKey)).toBe(true)
    expect(verifyManifestSignature(Buffer.from(JSON.stringify({ ...manifest, label: 'x' })), signature, publicKey)).toBe(false)
  })

  it('rejects a bad magic', () => {
    const { file } = buildFixture()
    file[0] = 0x58
    expect(() => readContainer(file)).toThrowError(expect.objectContaining({ code: 'BAD_MAGIC' }))
  })

  it('rejects a truncated file', () => {
    const { file } = buildFixture()
    expect(() => readContainer(file.subarray(0, file.length - 4))).toThrowError(expect.objectContaining({ code: 'TRUNCATED' }))
  })

  it('rejects an entry larger than the 32 MiB cap', () => {
    const manifest: PackManifest = {
      pack_id: 'com.example.p', version: '1.0.0', label: 'p', entry_count: 1,
      entries: [{ id: 'data:big', type: 'data', size: MAX_ENTRY_BYTES + 1, trial: false }],
    }
    expect(() => writeContainer({ manifest, chunks: [{ id: 'data:big', nonce: Buffer.alloc(12), ct: Buffer.alloc(MAX_ENTRY_BYTES + 1) }], signature: Buffer.alloc(64) }))
      .toThrowError(expect.objectContaining({ code: 'TOO_LARGE' }))
  })

  it('rejects a chunk table that disagrees with the manifest', () => {
    const { manifest, signature } = buildFixture()
    expect(() => writeContainer({ manifest, chunks: [], signature }))
      .toThrowError(expect.objectContaining({ code: 'TABLE_MISMATCH' }))
  })

  it('rejects a chunk whose ciphertext length disagrees with the manifest size', () => {
    const { manifest, signature } = buildFixture()
    expect(() => writeContainer({ manifest, chunks: [{ id: 'meta', nonce: Buffer.alloc(12), ct: Buffer.alloc(20) }], signature }))
      .toThrowError(expect.objectContaining({ code: 'TABLE_MISMATCH' }))
  })
})
```

- [ ] **Step 2: 运行测试确认失败**

Run: `corepack pnpm -C packages/pack-format test`
Expected: FAIL —— 无法从 `../src/index.js` 导入 `writeContainer`。

- [ ] **Step 3: 实现**

`packages/pack-format/src/container.ts`：
```ts
import { sign as edSign, verify as edVerify, type KeyObject } from 'node:crypto'
import { NONCE_BYTES } from './aead.js'

export const PACK_MAGIC = 'SLDSK1'
export const PACK_FORMAT_VERSION = 1
export const MAX_ENTRY_BYTES = 33554432

export type PackEntryType = 'meta' | 'text' | 'script' | 'data'
export interface PackEntryMeta { id: string; type: PackEntryType; size: number; trial: boolean }
export interface PackManifest {
  pack_id: string
  version: string
  label: string
  entry_count: number
  entries: PackEntryMeta[]
}

export type PackErrorCode = 'BAD_MAGIC' | 'BAD_VERSION' | 'TRUNCATED' | 'BAD_MANIFEST' | 'TOO_LARGE' | 'TABLE_MISMATCH'
export class PackFormatError extends Error {
  constructor(readonly code: PackErrorCode, message: string) {
    super(message)
    this.name = 'PackFormatError'
  }
}

export function signManifest(manifestBytes: Buffer, privateKey: KeyObject): Buffer {
  return edSign(null, manifestBytes, privateKey)
}

export function verifyManifestSignature(manifestBytes: Buffer, signature: Buffer, publicKey: KeyObject): boolean {
  return edVerify(null, manifestBytes, publicKey, signature)
}

export function writeContainer(input: {
  manifest: PackManifest
  chunks: { id: string; nonce: Buffer; ct: Buffer }[]
  signature: Buffer
}): Buffer {
  const { manifest, chunks, signature } = input
  if (chunks.length !== manifest.entry_count || chunks.length !== manifest.entries.length) {
    throw new PackFormatError('TABLE_MISMATCH', 'chunk count does not match manifest')
  }
  for (const [i, chunk] of chunks.entries()) {
    const meta = manifest.entries[i]
    if (meta.id !== chunk.id) throw new PackFormatError('TABLE_MISMATCH', 'chunk id mismatch at index ' + i)
    if (meta.size !== chunk.ct.length) throw new PackFormatError('TABLE_MISMATCH', 'chunk size mismatch at index ' + i)
    if (meta.size > MAX_ENTRY_BYTES) throw new PackFormatError('TOO_LARGE', 'entry ' + meta.id + ' exceeds 32 MiB cap')
    if (chunk.nonce.length !== NONCE_BYTES) throw new PackFormatError('TABLE_MISMATCH', 'bad nonce length for ' + meta.id)
  }

  const manifestBytes = Buffer.from(JSON.stringify(manifest), 'utf8')
  const header = Buffer.concat([
    Buffer.from(PACK_MAGIC, 'ascii'),
    Buffer.from([PACK_FORMAT_VERSION, 0]),
    u32(manifestBytes.length),
  ])
  const sigBlock = Buffer.concat([u32(signature.length), signature])
  const tableSize = chunks.reduce((n, c) => n + 4 + Buffer.byteLength(c.id, 'utf8') + 8 + 4, 0)
  let cursor = header.length + manifestBytes.length + sigBlock.length + 4 + tableSize

  const tableParts: Buffer[] = [u32(chunks.length)]
  const chunkParts: Buffer[] = []
  for (const chunk of chunks) {
    const idBytes = Buffer.from(chunk.id, 'utf8')
    tableParts.push(u32(idBytes.length), idBytes, u64(cursor), u32(chunk.ct.length))
    chunkParts.push(chunk.nonce, chunk.ct)
    cursor += NONCE_BYTES + chunk.ct.length
  }
  return Buffer.concat([header, manifestBytes, sigBlock, ...tableParts, ...chunkParts])
}

export function readContainer(buf: Buffer): {
  manifest: PackManifest
  manifestBytes: Buffer
  signature: Buffer
  chunks: { id: string; offset: number; nonce: Buffer; ct: Buffer }[]
} {
  let p = 0
  const need = (n: number) => {
    if (p + n > buf.length) throw new PackFormatError('TRUNCATED', 'unexpected end of pack file')
  }
  need(6)
  if (buf.subarray(0, 6).toString('ascii') !== PACK_MAGIC) throw new PackFormatError('BAD_MAGIC', 'not a sealed pack')
  p = 6
  need(2)
  if (buf[p] !== PACK_FORMAT_VERSION) throw new PackFormatError('BAD_VERSION', 'unsupported pack format version ' + buf[p])
  p += 2
  need(4)
  const manifestLen = buf.readUInt32BE(p); p += 4
  need(manifestLen)
  const manifestBytes = buf.subarray(p, p + manifestLen); p += manifestLen
  need(4)
  const sigLen = buf.readUInt32BE(p); p += 4
  need(sigLen)
  const signature = buf.subarray(p, p + sigLen); p += sigLen
  need(4)
  const count = buf.readUInt32BE(p); p += 4

  let manifest: PackManifest
  try {
    manifest = JSON.parse(manifestBytes.toString('utf8')) as PackManifest
  } catch {
    throw new PackFormatError('BAD_MANIFEST', 'manifest is not valid JSON')
  }
  if (manifest.entry_count !== count || !Array.isArray(manifest.entries) || manifest.entries.length !== count) {
    throw new PackFormatError('TABLE_MISMATCH', 'manifest entry_count disagrees with the chunk table')
  }

  const chunks: { id: string; offset: number; nonce: Buffer; ct: Buffer }[] = []
  for (let i = 0; i < count; i++) {
    need(4)
    const idLen = buf.readUInt32BE(p); p += 4
    need(idLen)
    const id = buf.subarray(p, p + idLen).toString('utf8'); p += idLen
    need(12)
    const offset = Number(buf.readBigUInt64BE(p)); p += 8
    const ctLen = buf.readUInt32BE(p); p += 4
    if (ctLen > MAX_ENTRY_BYTES) throw new PackFormatError('TOO_LARGE', 'entry ' + id + ' exceeds 32 MiB cap')
    if (offset + NONCE_BYTES + ctLen > buf.length) throw new PackFormatError('TRUNCATED', 'chunk ' + id + ' runs past end of file')
    chunks.push({ id, offset, nonce: buf.subarray(offset, offset + NONCE_BYTES), ct: buf.subarray(offset + NONCE_BYTES, offset + NONCE_BYTES + ctLen) })
  }
  return { manifest, manifestBytes, signature, chunks }
}

function u32(n: number): Buffer {
  const b = Buffer.alloc(4)
  b.writeUInt32BE(n, 0)
  return b
}
function u64(n: number): Buffer {
  const b = Buffer.alloc(8)
  b.writeBigUInt64BE(BigInt(n), 0)
  return b
}
```

`packages/pack-format/src/index.ts` 追加：
```ts
export * from './container.js'
```

- [ ] **Step 4: 运行测试确认通过**

Run: `corepack pnpm -C packages/pack-format test`
Expected: PASS（14 passed）。

- [ ] **Step 5: 提交**

```bash
git add packages/pack-format
git commit -m "feat(pack-format): add container writer, reader and manifest signing"
```
---

### Task 4: `@sealed/license-format`

**Files:**
- Create: `packages/license-format/{package.json,tsconfig.json,vitest.config.ts}`
- Create: `packages/license-format/src/{types.ts,b64.ts,x25519.ts,token.ts,wrap.ts,index.ts}`
- Test: `packages/license-format/test/{token.test.ts,wrap.test.ts}`

**Interfaces:**
- Consumes: `canonicalJson`（Task 1）。
- Produces:
  - `interface LicenseGrant { eid: string; eph: string; n: string; c: string }`
  - `interface LicensePayload { v: 1; lid: string; sub: string; pack: { id: string; version: string; author_pub: string }; dev: string; iat: number; exp: number; grace_until: number; caps: ('trial'|'full')[]; groups: string[]; keys: LicenseGrant[]; seats: { plan: string; limit: number } }`
  - `b64u(buf: Buffer): string`、`unb64u(s: string): Buffer`
  - `x25519PublicFromRaw(raw: Buffer): KeyObject`、`x25519PrivateFromRaw(raw: Buffer): KeyObject`
  - `rawPublicBytes(key: KeyObject): Buffer`、`rawPrivateBytes(key: KeyObject): Buffer`
  - `signLicense(payload: LicensePayload, privateKey: KeyObject): string`
  - `parseLicense(text: string): { payload: LicensePayload; payloadB64: string; sig: string }`
  - `verifyLicense(text: string, publicKeys: KeyObject[]): LicensePayload`
  - `licenseStatus(payload: LicensePayload, nowMs: number): 'active'|'grace'|'expired'`
  - `wrapEntryKey(payload: Pick<LicensePayload,'lid'>, eid: string, contentKey: Buffer, devicePublicKey: KeyObject): LicenseGrant`
  - `unwrapEntryKey(payload: LicensePayload, eid: string, devicePrivateKey: KeyObject): Buffer`
  - `class LicenseError extends Error { code: string }`

- [ ] **Step 1: 包配置**

`packages/license-format/package.json`：
```json
{
  "name": "@sealed/license-format",
  "version": "0.1.0",
  "type": "module",
  "main": "dist/index.js",
  "types": "dist/index.d.ts",
  "scripts": { "build": "tsc -p tsconfig.json", "test": "vitest run" },
  "dependencies": { "@sealed/canonical-json": "workspace:*" }
}
```

- [ ] **Step 2: 写失败测试**

`packages/license-format/test/token.test.ts`：
```ts
import { generateKeyPairSync } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import { licenseStatus, parseLicense, signLicense, verifyLicense } from '../src/index.js'
import type { LicensePayload } from '../src/index.js'

const { privateKey, publicKey } = generateKeyPairSync('ed25519')
const { publicKey: otherPublic } = generateKeyPairSync('ed25519')

function sample(overrides: Partial<LicensePayload> = {}): LicensePayload {
  return {
    v: 1, lid: 'lic_1', sub: 'cust_1',
    pack: { id: 'com.example.p', version: '1.0.0', author_pub: 'AAAA' },
    dev: 'BBBB', iat: 1000, exp: 2000, grace_until: 3000,
    caps: ['trial'], groups: ['g1'],
    keys: [{ eid: 'meta', eph: 'CCCC', n: 'DDDD', c: 'EEEE' }],
    seats: { plan: 'pro', limit: 1 },
    ...overrides,
  }
}

describe('license token', () => {
  it('signs and verifies, preserving the payload', () => {
    expect(verifyLicense(signLicense(sample(), privateKey), [publicKey])).toEqual(sample())
  })

  it('rejects a token signed by another key', () => {
    expect(() => verifyLicense(signLicense(sample(), privateKey), [otherPublic])).toThrow('LICENSE_BAD_SIGNATURE')
  })

  it('rejects a tampered payload', () => {
    const token = JSON.parse(signLicense(sample(), privateKey)) as { payload: string; sig: string }
    const payload = JSON.parse(Buffer.from(token.payload, 'base64url').toString('utf8')) as LicensePayload
    payload.exp = 999999
    const forged = JSON.stringify({ payload: Buffer.from(JSON.stringify(payload)).toString('base64url'), sig: token.sig })
    expect(() => verifyLicense(forged, [publicKey])).toThrow('LICENSE_BAD_SIGNATURE')
  })

  it('reports active, grace and expired around the boundaries', () => {
    const p = sample()
    expect(licenseStatus(p, 1999_000)).toBe('active')
    expect(licenseStatus(p, 2000_000)).toBe('grace')
    expect(licenseStatus(p, 2999_000)).toBe('grace')
    expect(licenseStatus(p, 3000_000)).toBe('expired')
  })

  it('rejects structurally invalid payloads', () => {
    expect(() => parseLicense('{"payload":"e30","sig":"AA"}')).toThrow('LICENSE_MALFORMED')
  })
})
```

`packages/license-format/test/wrap.test.ts`：
```ts
import { generateKeyPairSync } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import { rawPublicBytes, unwrapEntryKey, wrapEntryKey } from '../src/index.js'
import type { LicensePayload } from '../src/index.js'

const device = generateKeyPairSync('x25519')
const foreign = generateKeyPairSync('x25519')

function payload(): LicensePayload {
  return {
    v: 1, lid: 'lic_9', sub: 'c', pack: { id: 'p', version: '1', author_pub: 'A' },
    dev: rawPublicBytes(device.publicKey).toString('base64url'),
    iat: 0, exp: 1, grace_until: 2, caps: ['full'], groups: [], keys: [], seats: { plan: 'pro', limit: 1 },
  }
}

describe('entry key wrapping', () => {
  it('round-trips a content key to the right device', () => {
    const p = payload()
    const ck = Buffer.alloc(32, 5)
    p.keys.push(wrapEntryKey(p, 'data:x', ck, device.publicKey))
    expect(unwrapEntryKey(p, 'data:x', device.privateKey).equals(ck)).toBe(true)
  })

  it('fails for a foreign device key', () => {
    const p = payload()
    p.keys.push(wrapEntryKey(p, 'data:x', Buffer.alloc(32, 5), device.publicKey))
    expect(() => unwrapEntryKey(p, 'data:x', foreign.privateKey)).toThrow('LICENSE_UNWRAP_FAILED')
  })

  it('reports a missing grant distinctly from a failed unwrap', () => {
    expect(() => unwrapEntryKey(payload(), 'data:y', device.privateKey)).toThrow('LICENSE_NO_GRANT')
  })

  it('rejects unwrapping an entry key with a mismatched payload lid', () => {
    const p = payload()
    p.keys.push(wrapEntryKey(p, 'data:x', Buffer.alloc(32, 5), device.publicKey))
    expect(() => unwrapEntryKey({ ...p, lid: 'lic_other' }, 'data:x', device.privateKey)).toThrow('LICENSE_UNWRAP_FAILED')
  })
})
```

- [ ] **Step 3: 运行测试确认失败**

Run: `corepack pnpm -C packages/license-format test`
Expected: FAIL —— `../src/index.js` 不存在。

- [ ] **Step 4: 实现**

`packages/license-format/src/types.ts`：
```ts
export interface LicenseGrant { eid: string; eph: string; n: string; c: string }
export interface LicensePayload {
  v: 1
  lid: string
  sub: string
  pack: { id: string; version: string; author_pub: string }
  dev: string
  iat: number
  exp: number
  grace_until: number
  caps: ('trial' | 'full')[]
  groups: string[]
  keys: LicenseGrant[]
  seats: { plan: string; limit: number }
}
```

`packages/license-format/src/b64.ts`：
```ts
export function b64u(buf: Buffer): string { return buf.toString('base64url') }
export function unb64u(s: string): Buffer { return Buffer.from(s, 'base64url') }
```

`packages/license-format/src/x25519.ts`：
```ts
import { createPrivateKey, createPublicKey, type KeyObject } from 'node:crypto'

export class LicenseError extends Error {
  constructor(readonly code: string, message: string) {
    super(message)
    this.name = 'LicenseError'
  }
}

// X25519 的 PKCS8 / SPKI DER 前缀后面就是 32 字节原始密钥，
// 用 DER 而不是 JWK，避免不同 Node 版本对 OKP JWK 私有键（缺少 x）的处理差异。
const PKCS8_PREFIX = Buffer.from('302e020100300506032b656e04220420', 'hex')
const SPKI_PREFIX = Buffer.from('302a300506032b656e032100', 'hex')

export function x25519PublicFromRaw(raw: Buffer): KeyObject {
  if (raw.length !== 32) throw new LicenseError('LICENSE_MALFORMED', 'X25519 public key must be 32 bytes')
  return createPublicKey({ key: Buffer.concat([SPKI_PREFIX, raw]), format: 'der', type: 'spki' })
}

export function x25519PrivateFromRaw(raw: Buffer): KeyObject {
  if (raw.length !== 32) throw new LicenseError('LICENSE_MALFORMED', 'X25519 private key must be 32 bytes')
  return createPrivateKey({ key: Buffer.concat([PKCS8_PREFIX, raw]), format: 'der', type: 'pkcs8' })
}

export function rawPublicBytes(key: KeyObject): Buffer {
  const der = key.export({ format: 'der', type: 'spki' }) as Buffer
  return der.subarray(der.length - 32)
}

export function rawPrivateBytes(key: KeyObject): Buffer {
  const der = key.export({ format: 'der', type: 'pkcs8' }) as Buffer
  return der.subarray(der.length - 32)
}
```

`packages/license-format/src/token.ts`：
```ts
import { sign as edSign, verify as edVerify, type KeyObject } from 'node:crypto'
import { canonicalJson } from '@sealed/canonical-json'
import { b64u, unb64u } from './b64.js'
import { LicenseError } from './x25519.js'
import type { LicensePayload } from './types.js'

function payloadBytes(payload: LicensePayload): Buffer {
  return Buffer.from(canonicalJson(payload as unknown as Record<string, unknown>), 'utf8')
}

export function signLicense(payload: LicensePayload, privateKey: KeyObject): string {
  const bytes = payloadBytes(payload)
  return JSON.stringify({ payload: b64u(bytes), sig: b64u(edSign(null, bytes, privateKey)) })
}

export function parseLicense(text: string): { payload: LicensePayload; payloadB64: string; sig: string } {
  let raw: { payload?: unknown; sig?: unknown }
  try {
    raw = JSON.parse(text) as { payload?: unknown; sig?: unknown }
  } catch {
    throw new LicenseError('LICENSE_MALFORMED', 'license is not JSON')
  }
  if (typeof raw.payload !== 'string' || typeof raw.sig !== 'string') {
    throw new LicenseError('LICENSE_MALFORMED', 'license is missing payload or sig')
  }
  let parsed: unknown
  try {
    parsed = JSON.parse(unb64u(raw.payload).toString('utf8'))
  } catch {
    throw new LicenseError('LICENSE_MALFORMED', 'license payload is not JSON')
  }
  const p = parsed as LicensePayload
  const ok = p !== null && typeof p === 'object' && p.v === 1 &&
    typeof p.lid === 'string' && typeof p.sub === 'string' && typeof p.dev === 'string' &&
    typeof p.iat === 'number' && typeof p.exp === 'number' && typeof p.grace_until === 'number' &&
    Array.isArray(p.keys) && Array.isArray(p.caps) && Array.isArray(p.groups) &&
    p.pack !== undefined && typeof p.pack.id === 'string' && typeof p.pack.version === 'string' && typeof p.pack.author_pub === 'string'
  if (!ok) throw new LicenseError('LICENSE_MALFORMED', 'license payload has the wrong shape')
  return { payload: p, payloadB64: raw.payload, sig: raw.sig }
}

export function verifyLicense(text: string, publicKeys: KeyObject[]): LicensePayload {
  const { payload, payloadB64, sig } = parseLicense(text)
  const bytes = unb64u(payloadB64)
  if (!bytes.equals(payloadBytes(payload))) {
    throw new LicenseError('LICENSE_NOT_CANONICAL', 'license payload is not canonically encoded')
  }
  const signature = unb64u(sig)
  if (!publicKeys.some((key) => edVerify(null, bytes, key, signature))) {
    throw new LicenseError('LICENSE_BAD_SIGNATURE', 'license signature is not trusted')
  }
  return payload
}

export function licenseStatus(payload: LicensePayload, nowMs: number): 'active' | 'grace' | 'expired' {
  const now = Math.floor(nowMs / 1000)
  if (now < payload.exp) return 'active'
  if (now < payload.grace_until) return 'grace'
  return 'expired'
}
```

注意：Task 4 的测试里 `parseLicense(...)` 直接用 `toThrow('LICENSE_MALFORMED')`，因此测试断言与 `verifyLicense` 的错误码字符串必须一致。

`packages/license-format/src/wrap.ts`：
```ts
import { createCipheriv, createDecipheriv, diffieHellman, generateKeyPairSync, hkdfSync, randomBytes, type KeyObject } from 'node:crypto'
import { b64u, unb64u } from './b64.js'
import { LicenseError, rawPublicBytes, x25519PublicFromRaw } from './x25519.js'
import type { LicenseGrant, LicensePayload } from './types.js'

const SEP = Buffer.from([0x00])

export function wrapAad(lid: string, eid: string): Buffer {
  return Buffer.concat([Buffer.from(lid, 'utf8'), SEP, Buffer.from(eid, 'utf8')])
}

function kek(shared: Buffer, lid: string, eid: string): Buffer {
  const info = Buffer.concat([Buffer.from('wrap:', 'utf8'), Buffer.from(eid, 'utf8')])
  return Buffer.from(hkdfSync('sha256', shared, Buffer.from(lid, 'utf8'), info, 32))
}

export function wrapEntryKey(
  payload: Pick<LicensePayload, 'lid'>,
  eid: string,
  contentKey: Buffer,
  devicePublicKey: KeyObject,
): LicenseGrant {
  const ephemeral = generateKeyPairSync('x25519')
  const shared = diffieHellman({ privateKey: ephemeral.privateKey, publicKey: devicePublicKey })
  const key = kek(shared, payload.lid, eid)
  const nonce = randomBytes(12)
  const cipher = createCipheriv('aes-256-gcm', key, nonce)
  cipher.setAAD(wrapAad(payload.lid, eid))
  const ct = Buffer.concat([cipher.update(contentKey), cipher.final(), cipher.getAuthTag()])
  return { eid, eph: b64u(rawPublicBytes(ephemeral.publicKey)), n: b64u(nonce), c: b64u(ct) }
}

export function unwrapEntryKey(payload: LicensePayload, eid: string, devicePrivateKey: KeyObject): Buffer {
  const grant = payload.keys.find((k) => k.eid === eid)
  if (!grant) throw new LicenseError('LICENSE_NO_GRANT', 'license grants no key for ' + eid)
  const shared = diffieHellman({ privateKey: devicePrivateKey, publicKey: x25519PublicFromRaw(unb64u(grant.eph)) })
  const key = kek(shared, payload.lid, eid)
  const ct = unb64u(grant.c)
  if (ct.length < 16) throw new LicenseError('LICENSE_UNWRAP_FAILED', 'wrapped key is too short')
  const tag = ct.subarray(ct.length - 16)
  const body = ct.subarray(0, ct.length - 16)
  const decipher = createDecipheriv('aes-256-gcm', key, unb64u(grant.n))
  decipher.setAAD(wrapAad(payload.lid, eid))
  decipher.setAuthTag(tag)
  try {
    return Buffer.concat([decipher.update(body), decipher.final()])
  } catch {
    throw new LicenseError('LICENSE_UNWRAP_FAILED', 'could not unwrap the entry key with this device key')
  }
}
```

`packages/license-format/src/index.ts`：
```ts
export * from './types.js'
export * from './b64.js'
export * from './x25519.js'
export * from './token.js'
export * from './wrap.js'
```

- [ ] **Step 5: 运行测试确认通过**

Run: `corepack pnpm -C packages/license-format test`
Expected: PASS（9 passed）。

- [ ] **Step 6: 提交**

```bash
git add packages/license-format
git commit -m "feat(license-format): add signed license tokens and device-bound key wrapping"
```
---

### Task 5: `@sealed/dsh-sealed-skills` 的 Keystore 与设备密钥

**Files:**
- Create: `packages/dsh-sealed-skills/{package.json,tsconfig.json,vitest.config.ts}`
- Create: `packages/dsh-sealed-skills/src/keystore.ts`
- Test: `packages/dsh-sealed-skills/test/keystore.test.ts`

**Interfaces:**
- Consumes: `x25519PublicFromRaw` / `x25519PrivateFromRaw` / `rawPublicBytes` / `rawPrivateBytes`（Task 4，全部转出供本包复用）。
- Produces:
  - `interface Keystore { loadDevicePrivateKey(): Promise<Buffer|undefined>; loadDevicePublicKey(): Promise<Buffer|undefined>; createDeviceKey(): Promise<void>; deleteDeviceKey(): Promise<void>; ecdh(peerPublic: Buffer): Promise<Buffer> }`
  - `class FileKeystore implements Keystore`，构造函数 `{ dir: string }`，公开只读字段 `dir`
  - `class KeystoreError extends Error`

- [ ] **Step 1: 包配置**

`packages/dsh-sealed-skills/package.json`：
```json
{
  "name": "@sealed/dsh-sealed-skills",
  "version": "0.1.0",
  "type": "module",
  "main": "dist/index.js",
  "types": "dist/index.d.ts",
  "scripts": { "build": "tsc -p tsconfig.json", "test": "vitest run" },
  "dependencies": {
    "@sealed/canonical-json": "workspace:*",
    "@sealed/pack-format": "workspace:*",
    "@sealed/license-format": "workspace:*"
  }
}
```

- [ ] **Step 2: 写失败测试**

`packages/dsh-sealed-skills/test/keystore.test.ts`：
```ts
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { FileKeystore, KeystoreError, x25519PrivateFromRaw } from '../src/keystore.js'

function fresh(): FileKeystore {
  return new FileKeystore({ dir: mkdtempSync(join(tmpdir(), 'sealed-')) })
}

describe('FileKeystore', () => {
  it('creates a 32-byte device key pair on demand', async () => {
    const ks = fresh()
    expect(await ks.loadDevicePublicKey()).toBeUndefined()
    await ks.createDeviceKey()
    const priv = await ks.loadDevicePrivateKey()
    const pub = await ks.loadDevicePublicKey()
    expect(priv?.length).toBe(32)
    expect(pub?.length).toBe(32)
    expect(x25519PrivateFromRaw(priv!).export({ format: 'jwk' })).toMatchObject({ crv: 'X25519' })
  })

  it('is idempotent for createDeviceKey', async () => {
    const ks = fresh()
    await ks.createDeviceKey()
    const first = await ks.loadDevicePublicKey()
    await ks.createDeviceKey()
    expect((await ks.loadDevicePublicKey())!.equals(first!)).toBe(true)
  })

  it('stores base64url on disk and never a PEM', async () => {
    const ks = fresh()
    await ks.createDeviceKey()
    const text = readFileSync(join(ks.dir, 'device.json'), 'utf8')
    expect(text).not.toContain('PRIVATE KEY')
    expect(JSON.parse(text)).toMatchObject({ v: 1, alg: 'x25519' })
  })

  it('deletes the key material', async () => {
    const ks = fresh()
    await ks.createDeviceKey()
    await ks.deleteDeviceKey()
    expect(existsSync(join(ks.dir, 'device.json'))).toBe(false)
    expect(await ks.loadDevicePrivateKey()).toBeUndefined()
  })

  it('throws a typed error on a corrupted file', async () => {
    const ks = fresh()
    await ks.createDeviceKey()
    const file = join(ks.dir, 'device.json')
    const parsed = JSON.parse(readFileSync(file, 'utf8')) as { priv: string }
    parsed.priv = 'not-base64!!'
    writeFileSync(file, JSON.stringify(parsed))
    await expect(ks.loadDevicePrivateKey()).rejects.toThrow(KeystoreError)
  })

  it('derives the same shared secret from both sides via ecdh', async () => {
    const a = fresh(); const b = fresh()
    await a.createDeviceKey(); await b.createDeviceKey()
    const sharedA = await a.ecdh((await b.loadDevicePublicKey())!)
    const sharedB = await b.ecdh((await a.loadDevicePublicKey())!)
    expect(sharedA.equals(sharedB)).toBe(true)
  })
})
```

- [ ] **Step 3: 运行测试确认失败**

Run: `corepack pnpm -C packages/dsh-sealed-skills test`
Expected: FAIL —— `../src/keystore.js` 不存在。

- [ ] **Step 4: 实现**

`packages/dsh-sealed-skills/src/keystore.ts`：
```ts
import { chmodSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { createPublicKey, diffieHellman, generateKeyPairSync } from 'node:crypto'
import { join } from 'node:path'
import {
  rawPrivateBytes, rawPublicBytes, x25519PrivateFromRaw, x25519PublicFromRaw,
} from '@sealed/license-format'

export { rawPrivateBytes, rawPublicBytes, x25519PrivateFromRaw, x25519PublicFromRaw }

export class KeystoreError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'KeystoreError'
  }
}

export interface Keystore {
  loadDevicePrivateKey(): Promise<Buffer | undefined>
  loadDevicePublicKey(): Promise<Buffer | undefined>
  createDeviceKey(): Promise<void>
  deleteDeviceKey(): Promise<void>
  ecdh(peerPublic: Buffer): Promise<Buffer>
}

const KEY_FILE = 'device.json'

/**
 * M1/M2 的明文密钥库后端：私钥以 base64url 存于 $SEALED_HOME/device.json，POSIX 下 chmod 0600。
 * M2 会加入 DPAPI / Keychain / libsecret 后端，本后端仅作为显式退路保留。
 */
export class FileKeystore implements Keystore {
  readonly dir: string
  private readonly file: string

  constructor(opts: { dir: string }) {
    this.dir = opts.dir
    this.file = join(opts.dir, KEY_FILE)
    mkdirSync(this.dir, { recursive: true })
  }

  async createDeviceKey(): Promise<void> {
    if (existsSync(this.file)) return
    const { privateKey } = generateKeyPairSync('x25519')
    const body = JSON.stringify({ v: 1, alg: 'x25519', priv: rawPrivateBytes(privateKey).toString('base64url') })
    writeFileSync(this.file, body, { encoding: 'utf8', mode: 0o600 })
    try { chmodSync(this.file, 0o600) } catch { /* Windows 依赖用户目录 ACL */ }
  }

  async loadDevicePrivateKey(): Promise<Buffer | undefined> {
    if (!existsSync(this.file)) return undefined
    let parsed: { priv?: unknown }
    try {
      parsed = JSON.parse(readFileSync(this.file, 'utf8')) as { priv?: unknown }
    } catch {
      throw new KeystoreError('device key file is not valid JSON')
    }
    if (typeof parsed.priv !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(parsed.priv)) {
      throw new KeystoreError('device key file has an invalid private key')
    }
    return Buffer.from(parsed.priv, 'base64url')
  }

  async loadDevicePublicKey(): Promise<Buffer | undefined> {
    const priv = await this.loadDevicePrivateKey()
    if (!priv) return undefined
    try {
      return rawPublicBytes(createPublicKey(x25519PrivateFromRaw(priv)))
    } finally {
      priv.fill(0)
    }
  }

  async deleteDeviceKey(): Promise<void> {
    rmSync(this.file, { force: true })
  }

  async ecdh(peerPublic: Buffer): Promise<Buffer> {
    const priv = await this.loadDevicePrivateKey()
    if (!priv) throw new KeystoreError('no device key')
    try {
      return diffieHellman({ privateKey: x25519PrivateFromRaw(priv), publicKey: x25519PublicFromRaw(peerPublic) })
    } finally {
      priv.fill(0)
    }
  }
}

- [ ] **Step 5: 运行测试确认通过**

Run: `corepack pnpm -C packages/dsh-sealed-skills test`
Expected: PASS（6 passed）。

- [ ] **Step 6: 提交**

```bash
git add packages/dsh-sealed-skills
git commit -m "feat(dsh-sealed-skills): add keystore interface and file-backed device keys"
```
---

### Task 6: `@sealed/seal-cli`（keygen / pack / inspect / trial）

**Files:**
- Create: `packages/seal-cli/{package.json,tsconfig.json,vitest.config.ts}`
- Create: `packages/seal-cli/src/{frontmatter.ts,paths.ts,pack.ts,trial.ts,index.ts}`
- Test: `packages/seal-cli/test/{pack.test.ts,trial.test.ts}`

**Interfaces:**
- Consumes: `sealEntry` / `deriveEntryKey` / `entryAad` / `writeContainer` / `signManifest` / `readContainer` / `verifyManifestSignature`（Task 2、3），`signLicense` / `wrapEntryKey` / `rawPublicBytes` / `x25519PublicFromRaw`（Task 4）。
- Produces:
  - `parseSkillMarkdown(text: string): { frontmatter: Record<string, string|boolean>; body: string }`
  - `assertSafeRelPath(rel: string): string`（不安全时抛 `ENTRY_PATH_INVALID`）
  - `packSkillDir(dir: string, opts: { packId: string; version: string; label: string; master: Buffer; trialEntryIds: string[]; authorPrivateKey: KeyObject }): { file: Buffer; manifest: PackManifest; master: Buffer }`
  - `inspectPack(file: Buffer, authorPublicKey?: KeyObject): { manifest: PackManifest; signatureValid: boolean | undefined; chunks: number }`
  - `makeTrialLicense(opts: { manifest: PackManifest; master: Buffer; devicePublicKey: KeyObject; trialEntryIds: string[]; days: number; signingKey: KeyObject; now?: number; lid?: string }): string`

条目 `type` 只表达角色，不表达编码；二进制资源同样按字节加密、解密。

- [ ] **Step 1: 包配置**

`packages/seal-cli/package.json`：
```json
{
  "name": "@sealed/seal-cli",
  "version": "0.1.0",
  "type": "module",
  "main": "dist/index.js",
  "types": "dist/index.d.ts",
  "scripts": { "build": "tsc -p tsconfig.json", "test": "vitest run" },
  "dependencies": {
    "@sealed/pack-format": "workspace:*",
    "@sealed/license-format": "workspace:*"
  }
}
```

- [ ] **Step 2: 写失败测试**

`packages/seal-cli/test/pack.test.ts`：
```ts
import { generateKeyPairSync } from 'node:crypto'
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { deriveEntryKey, entryAad, openEntry, readContainer, verifyManifestSignature } from '@sealed/pack-format'
import { assertSafeRelPath, inspectPack, packSkillDir, parseSkillMarkdown } from '../src/index.js'

function skillDir(files: Record<string, Buffer | string>): string {
  const dir = mkdtempSync(join(tmpdir(), 'skill-'))
  for (const [rel, content] of Object.entries(files)) {
    const full = join(dir, rel)
    mkdirSync(join(full, '..'), { recursive: true })
    writeFileSync(full, content)
  }
  return dir
}

const author = generateKeyPairSync('ed25519')
const master = Buffer.alloc(32, 5)
const base = { packId: 'com.example.translate', version: '1.0.0', label: '翻译', master, authorPrivateKey: author.privateKey, trialEntryIds: [] as string[] }

const goodDir = () => skillDir({
  'SKILL.md': '---\nname: translate\ndescription: 翻译文本\nwhenToUse: 需要翻译时\n---\n\n把用户输入翻译成英文。\n',
  'scripts/run.py': 'print("hi")\n',
  'resources/logo.png': Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x00, 0xff, 0xfe]),
  'data/glossary.json': JSON.stringify({ a: '甲' }),
})

describe('parseSkillMarkdown', () => {
  it('splits frontmatter from the body', () => {
    const parsed = parseSkillMarkdown('---\nname: x\ndescription: y\n---\nbody text\n')
    expect(parsed.frontmatter).toEqual({ name: 'x', description: 'y' })
    expect(parsed.body).toBe('body text\n')
  })

  it('rejects a file without frontmatter', () => {
    expect(() => parseSkillMarkdown('no frontmatter')).toThrow('SKILL_MD_NO_FRONTMATTER')
  })
})

describe('assertSafeRelPath', () => {
  it('accepts ordinary relative paths including unicode and colons', () => {
    expect(assertSafeRelPath('图 片:v1.png')).toBe('图 片:v1.png')
  })

  it('rejects traversal and absolute-ish segments', () => {
    expect(() => assertSafeRelPath('a/../b')).toThrow('ENTRY_PATH_INVALID')
    expect(() => assertSafeRelPath('/etc/passwd')).toThrow('ENTRY_PATH_INVALID')
    expect(() => assertSafeRelPath('a//b')).toThrow('ENTRY_PATH_INVALID')
    expect(() => assertSafeRelPath('a/./b')).toThrow('ENTRY_PATH_INVALID')
  })
})

describe('packSkillDir', () => {
  it('produces a verifiable pack whose body entry decrypts with the derived key', () => {
    const { file, manifest } = packSkillDir(goodDir(), base)
    const parsed = readContainer(file)
    expect(parsed.manifest.pack_id).toBe(base.packId)
    expect(parsed.manifest.entries.map((e) => e.id).sort()).toEqual([
      'data:glossary.json', 'meta', 'script:translate:scripts/run.py',
      'skill:translate:body', 'skill:translate:res:logo.png',
    ])
    expect(verifyManifestSignature(parsed.manifestBytes, parsed.signature, author.publicKey)).toBe(true)
    expect(manifest.entry_count).toBe(parsed.chunks.length)

    const id = 'skill:translate:body'
    const chunk = parsed.chunks.find((c) => c.id === id)!
    const key = deriveEntryKey(master, base.packId, base.version, id)
    expect(openEntry(key, entryAad(base.packId, base.version, id), chunk.nonce, chunk.ct).toString('utf8'))
      .toBe('把用户输入翻译成英文。\n')
  })

  it('keeps binary resources byte-exact and records type as a role, not an encoding', () => {
    const parsed = readContainer(packSkillDir(goodDir(), base).file)
    const id = 'skill:translate:res:logo.png'
    const chunk = parsed.chunks.find((c) => c.id === id)!
    const plain = openEntry(deriveEntryKey(master, base.packId, base.version, id), entryAad(base.packId, base.version, id), chunk.nonce, chunk.ct)
    expect(plain.equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x00, 0xff, 0xfe]))).toBe(true)
  })

  it('rejects a directory without SKILL.md', () => {
    expect(() => packSkillDir(skillDir({ 'scripts/a.py': 'x' }), base)).toThrow('NO_SKILL_MD')
  })

  it('is deterministic apart from nonces', () => {
    const first = readContainer(packSkillDir(goodDir(), base).file).manifest
    const second = readContainer(packSkillDir(goodDir(), base).file).manifest
    expect(second).toEqual(first)
  })

  it('accepts unicode and colon-bearing file names deterministically', () => {
    const dir = skillDir({ 'SKILL.md': '---\nname: t\ndescription: d\n---\nb\n', 'resources/图 片:v1.png': Buffer.from([1, 2, 3]) })
    const ids = readContainer(packSkillDir(dir, { ...base, packId: 'com.example.u' }).file).manifest.entries.map((e) => e.id)
    expect(ids).toContain('skill:t:res:图 片:v1.png')
  })

  it('refuses an entry above the 32 MiB cap', () => {
    const dir = skillDir({ 'SKILL.md': '---\nname: big\ndescription: d\n---\nb\n', 'data/huge.bin': Buffer.alloc(33 * 1024 * 1024, 1) })
    expect(() => packSkillDir(dir, { ...base, packId: 'com.example.big' })).toThrow('TOO_LARGE')
  })

  it('inspects without any key able to decrypt', () => {
    const info = inspectPack(packSkillDir(goodDir(), base).file, author.publicKey)
    expect(info.signatureValid).toBe(true)
    expect(info.chunks).toBe(5)
  })
})
```

`packages/seal-cli/test/trial.test.ts`：
```ts
import { generateKeyPairSync } from 'node:crypto'
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { deriveEntryKey, readContainer } from '@sealed/pack-format'
import { unwrapEntryKey, verifyLicense } from '@sealed/license-format'
import { makeTrialLicense, packSkillDir } from '../src/index.js'

const author = generateKeyPairSync('ed25519')
const device = generateKeyPairSync('x25519')
const master = Buffer.alloc(32, 9)

const dir = mkdtempSync(join(tmpdir(), 'skill-'))
mkdirSync(join(dir, 'scripts'), { recursive: true })
writeFileSync(join(dir, 'SKILL.md'), '---\nname: translate\ndescription: 翻译\n---\n正文\n')
writeFileSync(join(dir, 'scripts/run.py'), 'print(1)\n')

describe('makeTrialLicense', () => {
  it('grants only the trial entries and nothing else', () => {
    const { file, manifest } = packSkillDir(dir, {
      packId: 'com.example.t', version: '1.0.0', label: 't', master, authorPrivateKey: author.privateKey,
      trialEntryIds: ['meta', 'skill:translate:body'],
    })
    const license = makeTrialLicense({ manifest, master, devicePublicKey: device.publicKey, trialEntryIds: ['meta', 'skill:translate:body'], days: 7, signingKey: author.privateKey })
    const payload = verifyLicense(license, [author.publicKey])
    expect(payload.caps).toEqual(['trial'])
    expect(payload.keys.map((k) => k.eid).sort()).toEqual(['meta', 'skill:translate:body'])

    const ck = deriveEntryKey(master, 'com.example.t', '1.0.0', 'meta')
    expect(unwrapEntryKey(payload, 'meta', device.privateKey).equals(ck)).toBe(true)
    expect(() => unwrapEntryKey(payload, 'script:translate:scripts/run.py', device.privateKey)).toThrow('LICENSE_NO_GRANT')
    expect(readContainer(file).manifest.entries.length).toBe(3)
  })

  it('sets exp to days and grace to three more days', () => {
    const { manifest } = packSkillDir(dir, { packId: 'com.example.t2', version: '1.0.0', label: 't', master, authorPrivateKey: author.privateKey, trialEntryIds: ['meta'] })
    const payload = verifyLicense(makeTrialLicense({ manifest, master, devicePublicKey: device.publicKey, trialEntryIds: ['meta'], days: 7, signingKey: author.privateKey, now: 1_000_000 }), [author.publicKey])
    expect(payload.exp - payload.iat).toBe(7 * 86400)
    expect(payload.grace_until - payload.exp).toBe(3 * 86400)
  })
})
```

- [ ] **Step 3: 运行测试确认失败**

Run: `corepack pnpm -C packages/seal-cli test`
Expected: FAIL —— `../src/index.js` 不存在。

- [ ] **Step 4: 实现**

`packages/seal-cli/src/frontmatter.ts`：
```ts
export function parseSkillMarkdown(text: string): { frontmatter: Record<string, string | boolean>; body: string } {
  if (!text.startsWith('---\n')) throw new Error('SKILL_MD_NO_FRONTMATTER')
  const end = text.indexOf('\n---', 3)
  if (end < 0) throw new Error('SKILL_MD_NO_FRONTMATTER')
  const block = text.slice(4, end)
  const body = text.slice(end + 4).replace(/^\r?\n/, '')
  const frontmatter: Record<string, string | boolean> = {}
  for (const line of block.split('\n')) {
    const trimmed = line.trim()
    if (trimmed === '' || trimmed.startsWith('#')) continue
    const at = trimmed.indexOf(':')
    if (at <= 0) throw new Error('SKILL_MD_BAD_FRONTMATTER')
    const key = trimmed.slice(0, at).trim()
    const raw = trimmed.slice(at + 1).trim()
    frontmatter[key] = raw === 'true' ? true : raw === 'false' ? false : raw
  }
  if (typeof frontmatter.name !== 'string') throw new Error('SKILL_MD_BAD_FRONTMATTER')
  if (typeof frontmatter.description !== 'string') throw new Error('SKILL_MD_BAD_FRONTMATTER')
  return { frontmatter, body }
}
```

`packages/seal-cli/src/paths.ts`：
```ts
export function assertSafeRelPath(rel: string): string {
  const parts = rel.split('/')
  if (rel.startsWith('/') || rel.includes('\\')) throw new Error('ENTRY_PATH_INVALID: ' + rel)
  if (parts.some((part) => part === '' || part === '.' || part === '..')) throw new Error('ENTRY_PATH_INVALID: ' + rel)
  return rel
}
```

`packages/seal-cli/src/pack.ts`：
```ts
import type { KeyObject } from 'node:crypto'
import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join, relative, sep } from 'node:path'
import {
  MAX_ENTRY_BYTES, deriveEntryKey, entryAad, readContainer, sealEntry, signManifest, verifyManifestSignature, writeContainer,
  type PackEntryMeta, type PackManifest,
} from '@sealed/pack-format'
import { parseSkillMarkdown } from './frontmatter.js'
import { assertSafeRelPath } from './paths.js'

export function packSkillDir(dir: string, opts: {
  packId: string
  version: string
  label: string
  master: Buffer
  trialEntryIds: string[]
  authorPrivateKey: KeyObject
}): { file: Buffer; manifest: PackManifest; master: Buffer } {
  let skillText: string
  try {
    skillText = readFileSync(join(dir, 'SKILL.md'), 'utf8')
  } catch {
    throw new Error('NO_SKILL_MD')
  }
  const { frontmatter, body } = parseSkillMarkdown(skillText)
  const name = frontmatter.name as string

  const entries: { id: string; type: PackEntryMeta['type']; bytes: Buffer }[] = [
    { id: 'meta', type: 'meta', bytes: Buffer.alloc(0) },
    { id: 'skill:' + name + ':body', type: 'text', bytes: Buffer.from(body, 'utf8') },
  ]
  const resources: Record<string, string> = {}
  const roots: [string, string, PackEntryMeta['type']][] = [
    ['resources', 'skill:' + name + ':res:', 'text'],
    ['scripts', 'script:' + name + ':', 'script'],
    ['data', 'data:', 'data'],
  ]
  for (const [subdir, prefix, type] of roots) {
    const root = join(dir, subdir)
    let files: string[] = []
    try { if (statSync(root).isDirectory()) files = walk(root) } catch { continue }
    for (const abs of files) {
      const rel = assertSafeRelPath(relative(root, abs).split(sep).join('/'))
      const id = prefix + rel
      entries.push({ id, type, bytes: readFileSync(abs) })
      if (subdir === 'resources') resources[id] = rel
    }
  }

  const meta = {
    skills: [{
      name,
      description: frontmatter.description as string,
      ...(typeof frontmatter.whenToUse === 'string' ? { whenToUse: frontmatter.whenToUse } : {}),
      invocation: {
        modelInvocable: frontmatter['disable-model-invocation'] !== true,
        userInvocable: frontmatter['user-invocable'] !== false,
      },
      entries: entries
        .filter((e) => e.id.startsWith('skill:' + name + ':') || e.id.startsWith('script:' + name + ':'))
        .map((e) => e.id),
    }],
    resources,
  }
  entries[0] = { id: 'meta', type: 'meta', bytes: Buffer.from(JSON.stringify(meta), 'utf8') }
  entries.sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0))

  const manifest: PackManifest = { pack_id: opts.packId, version: opts.version, label: opts.label, entry_count: entries.length, entries: [] }
  const chunks: { id: string; nonce: Buffer; ct: Buffer }[] = []
  for (const entry of entries) {
    if (entry.bytes.length > MAX_ENTRY_BYTES) throw new Error('TOO_LARGE: ' + entry.id)
    const sealed = sealEntry(deriveEntryKey(opts.master, opts.packId, opts.version, entry.id), entryAad(opts.packId, opts.version, entry.id), entry.bytes)
    manifest.entries.push({ id: entry.id, type: entry.type, size: sealed.ct.length, trial: opts.trialEntryIds.includes(entry.id) })
    chunks.push({ id: entry.id, nonce: sealed.nonce, ct: sealed.ct })
  }
  const signature = signManifest(Buffer.from(JSON.stringify(manifest), 'utf8'), opts.authorPrivateKey)
  return { file: writeContainer({ manifest, chunks, signature }), manifest, master: opts.master }
}

export function inspectPack(file: Buffer, authorPublicKey?: KeyObject): { manifest: PackManifest; signatureValid: boolean | undefined; chunks: number } {
  const parsed = readContainer(file)
  return {
    manifest: parsed.manifest,
    signatureValid: authorPublicKey ? verifyManifestSignature(parsed.manifestBytes, parsed.signature, authorPublicKey) : undefined,
    chunks: parsed.chunks.length,
  }
}

function walk(root: string): string[] {
  const out: string[] = []
  for (const name of readdirSync(root)) {
    const abs = join(root, name)
    if (statSync(abs).isDirectory()) out.push(...walk(abs))
    else out.push(abs)
  }
  return out
}
```

`packages/seal-cli/src/trial.ts`：
```ts
import { randomBytes, type KeyObject } from 'node:crypto'
import { deriveEntryKey, type PackManifest } from '@sealed/pack-format'
import { rawPublicBytes, signLicense, wrapEntryKey, type LicensePayload } from '@sealed/license-format'

export function makeTrialLicense(opts: {
  manifest: PackManifest
  master: Buffer
  devicePublicKey: KeyObject
  trialEntryIds: string[]
  days: number
  signingKey: KeyObject
  now?: number
  lid?: string
}): string {
  const now = Math.floor((opts.now ?? Date.now()) / 1000)
  const devicePub = rawPublicBytes(opts.devicePublicKey).toString('base64url')
  const payload: LicensePayload = {
    v: 1,
    lid: opts.lid ?? 'lic_trial_' + now + '_' + randomBytes(4).toString('hex'),
    sub: 'trial',
    pack: { id: opts.manifest.pack_id, version: opts.manifest.version, author_pub: devicePub },
    dev: devicePub,
    iat: now,
    exp: now + opts.days * 86400,
    grace_until: now + (opts.days + 3) * 86400,
    caps: ['trial'],
    groups: ['trial'],
    keys: [],
    seats: { plan: 'trial', limit: 1 },
  }
  const wanted = new Set(opts.trialEntryIds)
  for (const entry of opts.manifest.entries) {
    if (!wanted.has(entry.id)) continue
    const ck = deriveEntryKey(opts.master, opts.manifest.pack_id, opts.manifest.version, entry.id)
    try {
      payload.keys.push(wrapEntryKey(payload, entry.id, ck, opts.devicePublicKey))
    } finally {
      ck.fill(0)
    }
  }
  return signLicense(payload, opts.signingKey)
}
```

`packages/seal-cli/src/index.ts`：
```ts
export * from './frontmatter.js'
export * from './paths.js'
export * from './pack.js'
export * from './trial.js'
```

M1 的本地试用把 `pack.author_pub` 临时填成设备公钥占位；M2 由服务端填入真正的作者签名公钥，实现时在 `docs/sealed-skills/notes/` 记录该临时约定。

- [ ] **Step 5: 运行测试确认通过**

Run: `corepack pnpm -C packages/seal-cli test`
Expected: PASS（11 passed）。

- [ ] **Step 6: 提交**

```bash
git add packages/seal-cli
git commit -m "feat(seal-cli): add pack, inspect and trial license issuance"
```
---

### Task 7: `@sealed/dsh-sealed-skills` 的 core、registry 与 skill provider

**Files:**
- Create: `packages/dsh-sealed-skills/src/{core.ts,provider.ts,registry.ts,index.ts}`
- Test: `packages/dsh-sealed-skills/test/{core.test.ts,provider.test.ts}`

**Interfaces:**
- Consumes: `readContainer` / `openEntry` / `deriveEntryKey` / `entryAad` / `verifyManifestSignature`（Task 2、3），`verifyLicense` / `licenseStatus` / `unwrapEntryKey` / `x25519PrivateFromRaw`（Task 4），`Keystore` / `x25519PublicFromRaw`（Task 5）。
- Produces:
  - `interface SkillSummary { name: string; description: string; whenToUse?: string; invocation: { modelInvocable: boolean; userInvocable: boolean } }`
  - `interface SkillDefinition extends SkillSummary { content: string }`
  - `class SealedError extends Error { code: 'PACK_SIGNATURE'|'LICENSE_INVALID'|'LICENSE_EXPIRED'|'NOT_GRANTED'|'DECRYPT_FAILED'|'META_INVALID' }`
  - `class SealedCore { constructor(opts: { pack: Buffer; authorPublicKeyB64: string; license: string; trustedLicenseKeys: KeyObject[]; keystore: Keystore; now?: () => number }); list(): Promise<SkillSummary[]>; readSkill(name: string): Promise<SkillDefinition>; readEntry(id: string): Promise<Buffer> }`
  - `interface SkillProviderLike { readonly name: string; list(): Promise<SkillSummary[]>; get(name: string): Promise<SkillDefinition | undefined> }`
  - `createSkillProvider(core: Pick<SealedCore, 'list'|'readSkill'>): SkillProviderLike`
  - `class PackRegistry { constructor(opts: { dir: string }); scan(): string[] }`

- [ ] **Step 1: 写失败测试**

`packages/dsh-sealed-skills/test/core.test.ts`：
```ts
import { generateKeyPairSync, randomBytes, type KeyObject } from 'node:crypto'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { deriveEntryKey, entryAad, sealEntry, signManifest, writeContainer, type PackEntryMeta, type PackManifest } from '@sealed/pack-format'
import { signLicense, wrapEntryKey, type LicensePayload } from '@sealed/license-format'
import { SealedCore } from '../src/core.js'
import { FileKeystore, x25519PublicFromRaw } from '../src/keystore.js'

const author = generateKeyPairSync('ed25519')
const master = randomBytes(32)
const packId = 'com.example.translate'
const version = '1.0.0'

function ed25519RawX(key: KeyObject): string {
  return (key.export({ format: 'jwk' }) as { x: string }).x
}

function buildPack(entries: { id: string; type: PackEntryMeta['type']; body: string }[]): Buffer {
  const manifest: PackManifest = { pack_id: packId, version, label: '翻译', entry_count: entries.length, entries: [] }
  const chunks: { id: string; nonce: Buffer; ct: Buffer }[] = []
  for (const entry of entries) {
    const key = deriveEntryKey(master, packId, version, entry.id)
    const sealed = sealEntry(key, entryAad(packId, version, entry.id), Buffer.from(entry.body, 'utf8'))
    manifest.entries.push({ id: entry.id, type: entry.type, size: sealed.ct.length, trial: true })
    chunks.push({ id: entry.id, nonce: sealed.nonce, ct: sealed.ct })
  }
  const signature = signManifest(Buffer.from(JSON.stringify(manifest)), author.privateKey)
  return writeContainer({ manifest, chunks, signature })
}

const meta = JSON.stringify({
  skills: [{ name: 'translate', description: '翻译文本', whenToUse: '需要翻译时', invocation: { modelInvocable: true, userInvocable: true }, entries: ['skill:translate:body'] }],
  resources: {},
})
const pack = buildPack([
  { id: 'meta', type: 'meta', body: meta },
  { id: 'skill:translate:body', type: 'text', body: '把用户输入翻译成英文。\n' },
])

async function newKeystore(): Promise<FileKeystore> {
  const ks = new FileKeystore({ dir: mkdtempSync(join(tmpdir(), 'ks-')) })
  await ks.createDeviceKey()
  return ks
}

function licenseFor(devicePub: Buffer, entryIds: string[], overrides: Partial<LicensePayload> = {}): string {
  const payload: LicensePayload = {
    v: 1, lid: 'lic_t', sub: 'trial',
    pack: { id: packId, version, author_pub: ed25519RawX(author.publicKey) },
    dev: devicePub.toString('base64url'),
    iat: 0, exp: 4_000_000_000, grace_until: 4_000_000_000 + 3 * 86400,
    caps: ['trial'], groups: [], keys: [], seats: { plan: 'trial', limit: 1 },
    ...overrides,
  }
  for (const id of entryIds) {
    payload.keys.push(wrapEntryKey(payload, id, deriveEntryKey(master, packId, version, id), x25519PublicFromRaw(devicePub)))
  }
  return signLicense(payload, author.privateKey)
}

describe('SealedCore', () => {
  it('lists and reads a granted skill without exposing any file path', async () => {
    const ks = await newKeystore()
    const core = new SealedCore({
      pack, authorPublicKeyB64: ed25519RawX(author.publicKey),
      license: licenseFor(await ks.loadDevicePublicKey()!, ['meta', 'skill:translate:body']),
      trustedLicenseKeys: [author.publicKey], keystore: ks,
    })
    expect(await core.list()).toEqual([{ name: 'translate', description: '翻译文本', whenToUse: '需要翻译时', invocation: { modelInvocable: true, userInvocable: true } }])
    const skill = await core.readSkill('translate')
    expect(skill.content).toBe('把用户输入翻译成英文。\n')
    expect(skill).not.toHaveProperty('path')
    expect(await core.readEntry('skill:translate:body')).toBeInstanceOf(Buffer)
  })

  it('refuses an entry the license does not grant', async () => {
    const ks = await newKeystore()
    const core = new SealedCore({
      pack, authorPublicKeyB64: ed25519RawX(author.publicKey),
      license: licenseFor(await ks.loadDevicePublicKey()!, ['meta']),
      trustedLicenseKeys: [author.publicKey], keystore: ks,
    })
    await expect(core.readSkill('translate')).rejects.toMatchObject({ code: 'NOT_GRANTED' })
  })

  it('refuses an expired license before touching the pack', async () => {
    const ks = await newKeystore()
    const core = new SealedCore({
      pack, authorPublicKeyB64: ed25519RawX(author.publicKey),
      license: licenseFor(await ks.loadDevicePublicKey()!, ['meta', 'skill:translate:body'], { exp: 100, grace_until: 200 }),
      trustedLicenseKeys: [author.publicKey], keystore: ks,
    })
    await expect(core.list()).rejects.toMatchObject({ code: 'LICENSE_EXPIRED' })
  })

  it('stays usable inside the grace window', async () => {
    const ks = await newKeystore()
    const now = 150_000
    const core = new SealedCore({
      pack, authorPublicKeyB64: ed25519RawX(author.publicKey),
      license: licenseFor(await ks.loadDevicePublicKey()!, ['meta', 'skill:translate:body'], { exp: 100, grace_until: 200 }),
      trustedLicenseKeys: [author.publicKey], keystore: ks, now: () => now,
    })
    expect((await core.readSkill('translate')).content).toContain('翻译')
  })

  it('rejects a pack signed by a different author key', async () => {
    const ks = await newKeystore()
    const other = generateKeyPairSync('ed25519')
    expect(() => new SealedCore({
      pack, authorPublicKeyB64: ed25519RawX(other.publicKey),
      license: licenseFor(Buffer.alloc(32, 1), ['meta']),
      trustedLicenseKeys: [author.publicKey], keystore: ks,
    })).toThrowError(expect.objectContaining({ code: 'PACK_SIGNATURE' }))
  })

  it('rejects a tampered chunk as a typed decrypt failure', async () => {
    const ks = await newKeystore()
    const tampered = Buffer.from(pack)
    const idx = tampered.length - 5
    tampered[idx] = tampered[idx] ^ 0xff
    const core = new SealedCore({
      pack: tampered, authorPublicKeyB64: ed25519RawX(author.publicKey),
      license: licenseFor(await ks.loadDevicePublicKey()!, ['meta', 'skill:translate:body']),
      trustedLicenseKeys: [author.publicKey], keystore: ks,
    })
    await expect(core.readSkill('translate')).rejects.toMatchObject({ code: 'DECRYPT_FAILED' })
  })
})
```

`packages/dsh-sealed-skills/test/provider.test.ts`：
```ts
import { describe, expect, it } from 'vitest'
import { PackRegistry } from '../src/registry.js'
import { createSkillProvider } from '../src/provider.js'
import type { SkillDefinition, SkillSummary } from '../src/core.js'

const summary: SkillSummary = { name: 'a', description: 'd', invocation: { modelInvocable: true, userInvocable: true } }
const definition: SkillDefinition = { ...summary, content: 'body' }

const core = {
  list: async () => [summary],
  readSkill: async (name: string) => {
    if (name !== 'a') throw new Error('no such skill')
    return definition
  },
}

describe('createSkillProvider', () => {
  it('reports its provider name', () => {
    expect(createSkillProvider(core).name).toBe('sealed')
  })

  it('lists summaries and loads bodies on demand', async () => {
    const provider = createSkillProvider(core)
    expect(await provider.list()).toEqual([summary])
    expect((await provider.get('a'))?.content).toBe('body')
  })

  it('returns undefined instead of throwing for an unknown skill', async () => {
    expect(await createSkillProvider(core).get('missing')).toBeUndefined()
  })

  it('returns undefined instead of leaking an error when the pack cannot be read', async () => {
    const broken = createSkillProvider({ list: async () => [], readSkill: async () => { throw new Error('LICENSE_EXPIRED') } })
    expect(await broken.get('a')).toBeUndefined()
  })
})

describe('PackRegistry', () => {
  it('returns an empty list for a missing directory', () => {
    expect(new PackRegistry({ dir: 'definitely-not-here' }).scan()).toEqual([])
  })
})
```

- [ ] **Step 2: 运行测试确认失败**

Run: `corepack pnpm -C packages/dsh-sealed-skills test`
Expected: FAIL —— `src/core.js` 不存在。

- [ ] **Step 3: 实现**

`packages/dsh-sealed-skills/src/core.ts`：
```ts
import { createPublicKey, type KeyObject } from 'node:crypto'
import { entryAad, openEntry, readContainer, verifyManifestSignature } from '@sealed/pack-format'
import { licenseStatus, unwrapEntryKey, verifyLicense, type LicensePayload } from '@sealed/license-format'
import { x25519PrivateFromRaw, type Keystore } from './keystore.js'

export interface SkillSummary {
  name: string
  description: string
  whenToUse?: string
  invocation: { modelInvocable: boolean; userInvocable: boolean }
}
export interface SkillDefinition extends SkillSummary { content: string }

export type SealedErrorCode = 'PACK_SIGNATURE' | 'LICENSE_INVALID' | 'LICENSE_EXPIRED' | 'NOT_GRANTED' | 'DECRYPT_FAILED' | 'META_INVALID'
export class SealedError extends Error {
  constructor(readonly code: SealedErrorCode, message: string) {
    super(message)
    this.name = 'SealedError'
  }
}

interface MetaShape {
  skills: (SkillSummary & { entries: string[] })[]
  resources: Record<string, string>
}

export class SealedCore {
  private readonly parsed: ReturnType<typeof readContainer>
  private readonly payload: LicensePayload
  private meta?: MetaShape

  constructor(private readonly opts: {
    pack: Buffer
    authorPublicKeyB64: string
    license: string
    trustedLicenseKeys: KeyObject[]
    keystore: Keystore
    now?: () => number
  }) {
    this.parsed = readContainer(opts.pack)
    const authorKey = createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: opts.authorPublicKeyB64 }, format: 'jwk' })
    if (!verifyManifestSignature(this.parsed.manifestBytes, this.parsed.signature, authorKey)) {
      throw new SealedError('PACK_SIGNATURE', 'pack manifest signature does not match the trusted author key')
    }
    this.payload = verifyLicense(opts.license, opts.trustedLicenseKeys)
    if (this.payload.pack.id !== this.parsed.manifest.pack_id || this.payload.pack.version !== this.parsed.manifest.version) {
      throw new SealedError('LICENSE_INVALID', 'license is for a different pack or version')
    }
  }

  async list(): Promise<SkillSummary[]> {
    const meta = await this.loadMeta()
    return meta.skills.map((skill) => {
      const summary: SkillSummary = { name: skill.name, description: skill.description, invocation: skill.invocation }
      if (skill.whenToUse) summary.whenToUse = skill.whenToUse
      return summary
    })
  }

  async readSkill(name: string): Promise<SkillDefinition> {
    const meta = await this.loadMeta()
    const skill = meta.skills.find((s) => s.name === name)
    if (!skill) throw new SealedError('META_INVALID', 'no such skill: ' + name)
    const bodyId = 'skill:' + name + ':body'
    if (!skill.entries.includes(bodyId)) throw new SealedError('META_INVALID', 'skill has no body entry')
    const content = (await this.readEntry(bodyId)).toString('utf8')
    const definition: SkillDefinition = { name: skill.name, description: skill.description, invocation: skill.invocation, content }
    if (skill.whenToUse) definition.whenToUse = skill.whenToUse
    return definition
  }

  async readEntry(id: string): Promise<Buffer> {
    this.assertUsable()
    const chunk = this.parsed.chunks.find((c) => c.id === id)
    if (!chunk) throw new SealedError('NOT_GRANTED', 'no such entry or not granted: ' + id)
    const raw = await this.opts.keystore.loadDevicePrivateKey()
    if (!raw) throw new SealedError('LICENSE_INVALID', 'no device key is available')
    let deviceKey: KeyObject
    try {
      deviceKey = x25519PrivateFromRaw(raw)
    } finally {
      raw.fill(0)
    }
    const ck = unwrapEntryKey(this.payload, id, deviceKey)
    try {
      return openEntry(ck, entryAad(this.parsed.manifest.pack_id, this.parsed.manifest.version, id), chunk.nonce, chunk.ct)
    } catch {
      throw new SealedError('DECRYPT_FAILED', 'entry failed authentication: ' + id)
    } finally {
      ck.fill(0)
    }
  }

  private async loadMeta(): Promise<MetaShape> {
    if (!this.meta) {
      const raw = (await this.readEntry('meta')).toString('utf8')
      let parsed: MetaShape
      try {
        parsed = JSON.parse(raw) as MetaShape
      } catch {
        throw new SealedError('META_INVALID', 'meta entry is not valid JSON')
      }
      if (!Array.isArray(parsed.skills)) throw new SealedError('META_INVALID', 'meta entry has no skills array')
      this.meta = parsed
    }
    return this.meta
  }

  private assertUsable(): void {
    const nowMs = this.opts.now ? this.opts.now() : Date.now()
    if (licenseStatus(this.payload, nowMs) === 'expired') {
      throw new SealedError('LICENSE_EXPIRED', 'license expired past its grace period')
    }
  }
}
```

`packages/dsh-sealed-skills/src/provider.ts`：
```ts
import type { SealedCore, SkillDefinition, SkillSummary } from './core.js'

export interface SkillProviderLike {
  readonly name: string
  list(): Promise<SkillSummary[]>
  get(name: string): Promise<SkillDefinition | undefined>
}

/**
 * dsh `SkillProvider` 的适配层。M1 只暴露 `list()` / `get()`：
 * `get()` 把「未授权 / 已过期 / 解密失败」统一折叠为 undefined，避免把包内信息或错误细节泄露给调用方。
 */
export function createSkillProvider(core: Pick<SealedCore, 'list' | 'readSkill'>): SkillProviderLike {
  return {
    name: 'sealed',
    list: () => core.list(),
    async get(name: string) {
      try {
        return await core.readSkill(name)
      } catch {
        return undefined
      }
    },
  }
}
```

`packages/dsh-sealed-skills/src/registry.ts`：
```ts
import { readdirSync } from 'node:fs'
import { join } from 'node:path'

export class PackRegistry {
  constructor(private readonly opts: { dir: string }) {}

  scan(): string[] {
    try {
      return readdirSync(this.opts.dir)
        .filter((file) => file.endsWith('.sealedpack'))
        .map((file) => join(this.opts.dir, file))
        .sort()
    } catch {
      return []
    }
  }
}
```

`packages/dsh-sealed-skills/src/index.ts`：
```ts
export * from './keystore.js'
export * from './core.js'
export * from './provider.js'
export * from './registry.js'
```

- [ ] **Step 4: 运行测试确认通过**

Run: `corepack pnpm -C packages/dsh-sealed-skills test`
Expected: PASS（16 passed）。

- [ ] **Step 5: 提交**

```bash
git add packages/dsh-sealed-skills
git commit -m "feat(dsh-sealed-skills): add sealed core, pack registry and virtual skill provider"
```
---

### Task 8: 真实 dsh 集成冒烟 + 文档骨架

**Files:**
- Create: `demo/translate/SKILL.md`、`demo/cordis.yml`、`packages/dsh-sealed-skills/src/plugin.ts`（Step 4 依据真实 dsh API 落地）
- Create: `scripts/m1-smoke.mjs`
- Create: `docs/sealed-skills/README.md`、`docs/sealed-skills/guide/author-quickstart.md`、`docs/sealed-skills/notes/dsh-skill-provider.md`
- Modify: `.gitignore`（已含 `.dsh-checkout/`、`.sealed-home/`）

**Interfaces:**
- Consumes: Task 1–7 的全部产物。
- Produces: 可复现的端到端冒烟脚本；`docs/sealed-skills/notes/dsh-skill-provider.md` 记录真实 `SkillProvider` 签名与我们的适配差异。

- [ ] **Step 1: 建 demo 技能**

`demo/translate/SKILL.md`：
```markdown
---
name: translate
description: 把用户输入翻译成英文
whenToUse: 当用户要求翻译文本时
---

把用户输入翻译成自然、地道的英文，保留原有语气与格式。
```

`demo/cordis.yml`（真实 dsh 冒烟用；`/abs/path` 由脚本或手工替换为仓库绝对路径）：
```yaml
- insert:
    - id: sealed
      name: '/abs/path/to/sealed_skills/packages/dsh-sealed-skills/src/plugin.ts'
```

- [ ] **Step 2: 写冒烟脚本**

`scripts/m1-smoke.mjs`：
```js
import { generateKeyPairSync, randomBytes } from 'node:crypto'
import { mkdirSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { packSkillDir } from '../packages/seal-cli/dist/pack.js'
import { makeTrialLicense } from '../packages/seal-cli/dist/trial.js'
import { FileKeystore, x25519PublicFromRaw } from '../packages/dsh-sealed-skills/dist/keystore.js'
import { SealedCore } from '../packages/dsh-sealed-skills/dist/core.js'

const root = new URL('../', import.meta.url)
const home = fileURLToPath(new URL('.sealed-home/', root))
mkdirSync(home, { recursive: true })

const author = generateKeyPairSync('ed25519')
const master = randomBytes(32)
const trialEntryIds = ['meta', 'skill:translate:body']

const { file, manifest } = packSkillDir(fileURLToPath(new URL('demo/translate', root)), {
  packId: 'com.example.translate', version: '1.0.0', label: '翻译', master, trialEntryIds,
  authorPrivateKey: author.privateKey,
})

const keystore = new FileKeystore({ dir: home })
await keystore.createDeviceKey()
const devicePublicKey = x25519PublicFromRaw(await keystore.loadDevicePublicKey())
const license = makeTrialLicense({
  manifest, master, devicePublicKey, trialEntryIds, days: 7, signingKey: author.privateKey,
})

const core = new SealedCore({
  pack: file,
  authorPublicKeyB64: author.publicKey.export({ format: 'jwk' }).x,
  license,
  trustedLicenseKeys: [author.publicKey],
  keystore,
})

console.log('skills:', await core.list())
console.log('content:', (await core.readSkill('translate')).content)
```

- [ ] **Step 3: 运行冒烟**

Run: `corepack pnpm -r build; node scripts/m1-smoke.mjs`
Expected: 打印 `skills: [ { name: 'translate', ... } ]` 与 `content: 把用户输入翻译成自然、地道的英文，保留原有语气与格式。`
随后人工确认：`.sealed-home/` 与仓库根目录下不存在该正文的明文（`demo/` 源目录本身除外）。

- [ ] **Step 4: 真实 dsh 集成（环境相关；做不了必须写明未验证）**

```bash
git clone --depth 1 https://github.com/deepseek-ai/deepseek-harness .dsh-checkout
cd .dsh-checkout
corepack pnpm install
```

打开 `packages/skill/skill/src/index.ts`，确认 `SkillProvider` 的真实签名（`list(options)` / `get(locator, options)` / `SkillProviderControl` / `SkillCandidate.locator` 的类型），把实测结果写进 `docs/sealed-skills/notes/dsh-skill-provider.md`，并据此调整 `packages/dsh-sealed-skills/src/provider.ts` 的适配层（`SkillProviderLike` → dsh `SkillProvider`），同时新建 `packages/dsh-sealed-skills/src/plugin.ts`：导出 `apply(ctx)`，在 `ctx.skills.registerProvider()`（或 `ctx.skills.register()`）上注册 sealed provider，供 `demo/cordis.yml` 挂载。若本机无法完成 clone/install，笔记中必须写「未验证」并列出待确认项。

- [ ] **Step 5: 文档骨架**

`docs/sealed-skills/README.md`：生态总览（M1 范围、五个包各自的职责、`scripts/m1-smoke.mjs` 的运行方法、M2 起将接入授权服务器与日志掩码）。

`docs/sealed-skills/guide/author-quickstart.md`：以 `demo/translate` 为例，给出可复制命令与预期输出：
```bash
corepack pnpm -r build
node -e "import('./packages/seal-cli/dist/pack.js').then(async (m) => { const a = (await import('node:crypto')).generateKeyPairSync('ed25519'); const r = m.packSkillDir('./demo/translate', { packId: 'com.example.translate', version: '1.0.0', label: '翻译', master: Buffer.alloc(32, 1), trialEntryIds: ['meta','skill:translate:body'], authorPrivateKey: a.privateKey }); console.log(r.manifest.entries.map((e) => e.id)) })"
```

- [ ] **Step 6: 提交**

```bash
git add demo scripts docs/sealed-skills .gitignore
git commit -m "feat(demo): add M1 smoke path and ecosystem docs skeleton"
```

---

## 后续计划（不在本文件范围，各自独立成文）

- **M2 授权闭环**：`license-server`（activate / renew / trial / revoke）+ DPAPI / Keychain / libsecret 密钥库后端 + 宽限期与时钟回拨检测 + 席位与吊销。
- **M3 防泄漏**：`log-mask`（消息投影掩码，退路为自定义 SessionPersistence provider）+ 金丝雀泄漏扫描 CI gate + `ctx.invariants` 插件 + `tool-runtime` 脚本执行（JS/TS 经 `ctx.ptcRuntime`，Python 经 stdin 管道）。
- **M4 生态与交付**：完整 `docs/sealed-skills/` 七篇 + golden vectors + 发布流程与 CI。
- **M5 加固**：原生 / WASM `DecryptBackend`，让设备私钥与内容密钥不进入 JS 堆。

## 出口标准（M1 完成定义）

1. `corepack pnpm -r test` 全绿；五个包各有独立测试。
2. `node scripts/m1-smoke.mjs` 端到端跑通：磁盘上只有密文包与 license，没有明文技能正文。
3. 授权负路径可复现：未授权条目、过期 license、篡改密文、篡改 manifest 各自抛出对应的 `SealedError`。
4. `docs/sealed-skills/notes/dsh-skill-provider.md` 存在，且明确标注真实 dsh 签名「已验证」或「未验证 + 待确认项」。