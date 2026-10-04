// leak-gate: the M3 release-blocking canary leak acceptance gate (spec §10.3, plan §3.4 / Task 8).
//
// WHAT IT PROVES (spec S1: 磁盘上不出现技能正文/脚本源码明文):
//   1. A unique canary is embedded in the protected plaintext (skill body + script source +
//      resource entry), then the full chain runs: pack -> signed license -> real SealedCore
//      decryption -> placeholder provider -> log-mask marker/projection -> durable session log ->
//      sealed script execution -> the spec §8 error table. Afterwards EVERY on-disk surface this
//      process can reach is scanned BYTE-WISE (Buffer.includes) for the canary and for the body
//      derived from the author source directory: `.sealed-home` artifacts, the session log (both
//      the raw bytes and the zstd-decompressed payload of `session.jsonl.zstd`), spill, temp,
//      logs and telemetry. Zero hits is the pass condition.
//   2. Every §8 row is exercised and each produced error/telemetry message is collected; any
//      message carrying the canary or the body fails the gate.
//   3. A child process is SIGKILLed mid-decrypt; the disk is rescanned (crash residue).
//   4. A sealed script that echoes its own source on stderr must be refused (`output-redacted`).
//   5. With `SEALED_DSH_LAB=1` and an installed lab, a REAL `@deepseek-ai/dsh-session` session is
//      driven: its durable log must stay placeholder-only while `deriveMessages()` reveals the
//      canary. Without the lab this sub-check is a LOUD skip (UNVERIFIED, never a pass).
//
// STANDALONE: no `@deepseek-ai/*` import and no `.dsh-lab/` dependency on the default path — the
// module is imported dynamically and only behind the opt-in env gate. Node built-ins only.
// ZERO PLAINTEXT: the canary/body never reach argv, a log line, or an exit message; the whole
// scratch tree lives under `os.tmpdir()` and is removed before the process exits.
//
// Acceptance: prints exactly `leak-gate: clean` (exit 0), or `leak-gate: FAILED ...` (exit != 0).
// Progress/diagnostics go to stderr so stdout stays machine-checkable.
import { spawn } from 'node:child_process'
import { createPublicKey, generateKeyPairSync, randomBytes } from 'node:crypto'
import {
  existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve, sep } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { zstdCompressSync, zstdDecompressSync } from 'node:zlib'

import { packSkillDir } from '../packages/seal-cli/dist/pack.js'
import { parseSkillMarkdown } from '../packages/seal-cli/dist/frontmatter.js'
import { makeTrialLicense } from '../packages/seal-cli/dist/trial.js'
import { b64u, licenseStatus, rawPrivateBytes, rawPublicBytes, verifyLicense } from '../packages/license-format/dist/index.js'
import { MAX_ENTRY_BYTES, PACK_FORMAT_VERSION, readContainer, writeContainer } from '../packages/pack-format/dist/index.js'
import { createApp, loadServerKeys, openStore, serverLicensePublicB64 } from '../packages/license-server/dist/index.js'
import {
  apply,
  createCachingContentFor,
  createDshSkillProvider,
  createLogMaskProjection,
  createPlaceholderRegistry,
  createPlaintextReveal,
  executeSealedScript,
  FileKeystore,
  findSealedPlaintext,
  KeystoreError,
  LicenseClient,
  LicenseDenied,
  parsePlaceholder,
  placeholderFor,
  renderPlaceholder,
  SealedCore,
  sealedRedactedData,
  SEALED_REDACTED,
  SEALED_REDACTED_ALG,
  skillBodyEntryId,
  x25519PublicFromRaw,
} from '../packages/dsh-sealed-skills/dist/index.js'

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const PACK_ID = 'com.sealed.leakgate'
const VERSION = '1.0.0'
const SKILL = 'leakgate'
const ENTRY_BODY = 'skill:' + SKILL + ':body'
const LAB_SESSION = join(ROOT, '.dsh-lab', 'node_modules', '@deepseek-ai', 'dsh-session', 'lib', 'index.js')
const GATE_PREFIX = 'leak-gate'

// --- Byte-wise scanner (pure; exported so the vitest can prove it is non-vacuous) --------------

/** Every needle occurring in `buffer`, byte-wise. `label` names the protected plaintext source. */
export function scanBufferForNeedles(buffer, needles) {
  const hits = []
  for (const { label, needle } of needles) {
    if (needle.length > 0 && buffer.includes(needle)) hits.push({ label, how: 'raw' })
  }
  return hits
}

/** Recursively list regular files under `root` (missing/unreadable entries are skipped). */
export function listFiles(root) {
  const out = []
  const walk = (dir) => {
    let names
    try {
      names = readdirSync(dir)
    } catch {
      return
    }
    for (const name of names) {
      const abs = join(dir, name)
      let stat
      try {
        stat = statSync(abs)
      } catch {
        continue
      }
      if (stat.isDirectory()) walk(abs)
      else if (stat.isFile()) out.push(abs)
    }
  }
  walk(root)
  return out
}

/**
 * Byte-scan every file. A `.zstd` artifact is scanned twice: its raw bytes (a compressed frame can
 * still carry a literal) and its decompressed payload (the real `session.jsonl` content).
 */
export function scanFilesForNeedles(files, needles) {
  const hits = []
  for (const file of files) {
    let raw
    try {
      raw = readFileSync(file)
    } catch {
      continue
    }
    for (const hit of scanBufferForNeedles(raw, needles)) hits.push({ file, ...hit })
    if (file.endsWith('.zstd')) {
      let decompressed
      try {
        decompressed = zstdDecompressSync(raw)
      } catch {
        // A `.zstd` we cannot decompress is still scanned raw, but never silently: warn so a
        // truncated/partially-flushed artifact is not mistaken for a clean payload scan. This is a
        // warning, never a failure — a bad frame is not by itself evidence of a leak.
        note('WARNING: could not decompress ' + file + '; only its raw bytes were scanned')
        continue
      }
      for (const hit of scanBufferForNeedles(decompressed, needles)) hits.push({ file, ...hit, how: 'zstd' })
    }
  }
  return hits
}

function note(message) {
  process.stderr.write('[' + GATE_PREFIX + '] ' + message + '\n')
}

// --- Entry point --------------------------------------------------------------------------------

async function main() {
  const scratch = mkdtempSync(join(tmpdir(), 'sealed-' + GATE_PREFIX + '-'))
  let result
  try {
    result = await runGate(scratch)
  } catch (error) {
    const detail = error instanceof Error ? error.name + ': ' + error.message : String(error)
    if (process.env.LEAK_GATE_DEBUG && error instanceof Error) note(String(error.stack))
    note('internal error: ' + detail)
    result = { failures: ['internal error (' + (error instanceof Error ? error.name : 'unknown') + ')'] }
  } finally {
    cleanupScratch(scratch)
  }
  const failures = result.failures ?? []
  if (failures.length === 0) {
    process.stdout.write(GATE_PREFIX + ': clean\n')
    return
  }
  for (const failure of failures) note('FAILURE: ' + failure)
  process.stdout.write(GATE_PREFIX + ': FAILED ' + failures.join(' | ') + '\n')
  process.exitCode = 1
}

function cleanupScratch(scratch) {
  const base = resolve(tmpdir())
  const target = resolve(scratch)
  if (!target.startsWith(base + sep) || !target.includes('sealed-' + GATE_PREFIX + '-')) return
  try {
    rmSync(target, { recursive: true, force: true, maxRetries: 3 })
  } catch {
    // Best-effort; a leftover tmp dir under the OS temp root is not a repo artifact.
  }
}

const invokedDirectly = (() => {
  try {
    return process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href
  } catch {
    return false
  }
})()

// --- The gate -----------------------------------------------------------------------------------

async function runGate(scratch) {
  const failures = []
  const rows = []
  const errorTexts = []
  const canary = 'CANARY-' + randomBytes(16).toString('hex')
  const author = join(scratch, 'author')

  const bodyLine = canary + ' \u2014\u2014 leak-gate skill body (this line carries the unique canary).'
  const scriptSource = [
    '// sealed demo script for the leak gate',
    'const MARKER = ' + JSON.stringify(canary),
    "process.stdout.write('sealed-script:' + (process.argv[2] ?? '') + '\\n')",
    '',
  ].join('\n')
  const resourceText = canary + ' resource payload\n'
  writeAuthorTree(author, bodyLine, scriptSource, resourceText)
  const body = parseSkillMarkdown(readFileSync(join(author, 'SKILL.md'), 'utf8')).body
  const scriptEntryId = 'script:' + SKILL + ':run.mjs'
  const resourceEntryId = 'skill:' + SKILL + ':res:blob.txt'

  // Needles: the generated canary plus the protected plaintext DERIVED from the author source dir,
  // so no second literal copy of the body lives in this script.
  const needles = [
    { label: 'canary', needle: Buffer.from(canary, 'utf8') },
    { label: 'skill-body', needle: Buffer.from(body.trim(), 'utf8') },
    { label: 'script-source', needle: Buffer.from(scriptSource.trim(), 'utf8') },
    { label: 'resource', needle: Buffer.from(resourceText.trim(), 'utf8') },
  ]

  const authorKey = generateKeyPairSync('ed25519')
  const authorPub = authorKey.publicKey.export({ format: 'jwk' }).x
  const master = randomBytes(32)
  const trialEntryIds = ['meta', ENTRY_BODY, scriptEntryId, resourceEntryId]
  const { file: pack, manifest } = packSkillDir(author, {
    packId: PACK_ID, version: VERSION, label: 'leak-gate', master, trialEntryIds,
    authorPrivateKey: authorKey.privateKey,
  })

  // ---- on-disk "install" artifacts: pack + device key + signed license + clock + license cache
  const home = join(scratch, 'home')
  mkdirSync(home, { recursive: true })
  const packPath = join(home, SKILL + '.sealedpack')
  writeFileSync(packPath, pack)
  const keystore = new FileKeystore({ dir: home })
  await keystore.createDeviceKey()
  const license = makeTrialLicense({
    manifest, master, devicePublicKey: x25519PublicFromRaw(await keystore.loadDevicePublicKey()),
    trialEntryIds, days: 7, signingKey: authorKey.privateKey,
  })
  const licensePath = join(home, SKILL + '.license')
  writeFileSync(licensePath, license, 'utf8')
  const payload = verifyLicense(license, [authorKey.publicKey])
  const licensesDir = join(home, 'licenses')
  mkdirSync(licensesDir, { recursive: true })
  writeFileSync(join(licensesDir, payload.lid + '.license.json'), license, 'utf8')
  writeFileSync(join(home, 'clock.json'), JSON.stringify({ v: 1, lastSeenMs: Date.now() }))

  // ---- full chain: decrypt -> placeholder provider -> log-mask marker/projection -> durable log
  const core = new SealedCore({ pack, license, trustedLicenseKeys: [authorKey.publicKey], keystore })
  const registry = createPlaceholderRegistry()
  const plaintext = createPlaintextReveal()
  const provider = createDshSkillProvider(core, { contentFor: createCachingContentFor(registry, plaintext) })
  const summaries = await provider.list({})
  if (summaries.length !== 1 || summaries[0].name !== SKILL) failures.push('provider.list did not expose the licensed skill')
  const definition = summaries.length === 1 ? await provider.get(summaries[0], {}) : undefined
  const placeholder = definition?.content ?? ''
  const tokens = parsePlaceholder(placeholder)
  const token = tokens[0]
  if (!placeholder || placeholder.includes(canary)) failures.push('the provider did not return an unguessable placeholder')
  if (token === undefined) failures.push('the placeholder carried no registry token')

  const durableEvents = [{
    type: 'tool/result', seq: 0, time: 1700000000000,
    data: { turn: 0, step: 0, message: { id: 'lg-1', role: 'tool', content: [{ type: 'text', text: placeholder }] } },
  }]
  if (token !== undefined) {
    durableEvents.push({ type: SEALED_REDACTED, seq: 1, time: 1700000000001, data: sealedRedactedData(0, ENTRY_BODY, token) })
    const projection = createLogMaskProjection({ reveal: plaintext.reveal })
    const projected = projection.project(durableEvents[1], { nodes: [0], events: [durableEvents[0]], baseSeq: 0, messages: new Map() })
    const revealed = projected.get(0)?.content?.[0]?.text ?? ''
    if (!revealed.includes(canary)) failures.push('the log-mask projection did not reveal the canary (the gate would be vacuous)')
  }
  if (JSON.stringify(durableEvents).includes(canary)) failures.push('the durable session events carry plaintext')

  const sessionDir = join(scratch, 'session')
  mkdirSync(sessionDir, { recursive: true })
  const durableJsonl = Buffer.from(durableEvents.map((event) => JSON.stringify(event)).join('\n') + '\n', 'utf8')
  writeFileSync(join(sessionDir, 'session.jsonl'), durableJsonl)
  writeFileSync(join(sessionDir, 'session.jsonl.zstd'), zstdCompressSync(durableJsonl))

  // ---- other runtime surfaces the gate must sweep
  const spillDir = join(scratch, 'spill')
  mkdirSync(spillDir, { recursive: true })
  writeFileSync(join(spillDir, 'tool-output.txt'), 'sealed-script:ok\n')
  const logsDir = join(scratch, 'logs')
  mkdirSync(logsDir, { recursive: true })
  const telemetryDir = join(scratch, 'telemetry')
  mkdirSync(telemetryDir, { recursive: true })
  const tmpDir = join(scratch, 'tmp')
  mkdirSync(tmpDir, { recursive: true })
  writeFileSync(join(tmpDir, 'scratch.tmp'), 'ephemeral\n')

  // ---- run the sealed script for real (the child only ever sees the source on stdin)
  const scriptResult = await executeSealedScript(
    { readEntry: (id) => core.readEntry(id), confine: async (argv) => ({ argv: [...argv], enforcement: 'full' }) },
    { name: SKILL, entryId: scriptEntryId, runtime: 'node', policy: { mode: 'read-only', workspaceRoot: scratch } },
    ['hello'],
  )
  if (!scriptResult.ok || !scriptResult.stdout.includes('sealed-script:hello')) {
    failures.push('the sealed script did not run cleanly on the real node child')
  }
  errorTexts.push(JSON.stringify(scriptResult))

  // ---- spec §8: a child that echoes sealed source on stderr must be refused (Task 7 C1)
  const echoSource = Buffer.from('const = "' + canary + '"\n', 'utf8')
  const echoResult = await executeSealedScript(
    { readEntry: async () => Buffer.from(echoSource), confine: async (argv) => ({ argv: [...argv], enforcement: 'full' }) },
    { name: SKILL, entryId: scriptEntryId, runtime: 'node', policy: { mode: 'read-only', workspaceRoot: scratch } },
  )
  if (echoResult.ok || echoResult.reason !== 'output-redacted') {
    failures.push('a sealed script that echoed its own source on stderr was not refused')
  }
  errorTexts.push(JSON.stringify(echoResult))
  echoSource.fill(0)

  // ---- crash residue: SIGKILL a child that is decrypting the sealed body in memory
  await runCrashResidue({ scratch, packPath, licensePath, home, authorPubB64: authorPub }, failures)

  const record = (id, ok, detail) => {
    rows.push({ id, ok, detail: detail ?? '' })
    if (!ok) failures.push('§8 ' + id + ': ' + (detail ?? 'failed'))
  }
  const capture = async (promise) => {
    try {
      return { value: await promise }
    } catch (error) {
      return { error }
    }
  }
  const messageOf = (error) => (error instanceof Error ? error.message : String(error))
  // ---- spec §8 error table (automatable rows) --------------------------------------------------
  const proofKeys = generateKeyPairSync('x25519')
  const proofPubB64 = b64u(rawPublicBytes(proofKeys.publicKey))

  // 激活时断网 -> structured refusal (SERVER_UNAVAILABLE), redacted message.
  {
    const homeR1 = join(scratch, 'r1'); mkdirSync(homeR1, { recursive: true })
    const client = new LicenseClient({
      serverUrl: 'http://127.0.0.1:9', keystore: new FileKeystore({ dir: homeR1 }), homeDir: homeR1,
      trustedLicenseKeys: [authorKey.publicKey], retry: { attempts: 1, baseMs: 1, maxMs: 1 },
    })
    const r = await capture(client.activate({ id: PACK_ID, version: VERSION }, 'purchase-x'))
    const message = r.error ? messageOf(r.error) : ''
    errorTexts.push(message)
    record('activation-offline', r.error instanceof LicenseDenied && r.error.code === 'SERVER_UNAVAILABLE', message)
  }

  // 续期断网、未过期 -> silent cache fallback (fail-open within the window).
  {
    const homeR2 = join(scratch, 'r2'); mkdirSync(homeR2, { recursive: true })
    const ks2 = new FileKeystore({ dir: homeR2 }); await ks2.createDeviceKey()
    const lic2 = makeTrialLicense({
      manifest, master, devicePublicKey: x25519PublicFromRaw(await ks2.loadDevicePublicKey()),
      trialEntryIds, days: 7, signingKey: authorKey.privateKey,
    })
    const setup = new LicenseClient({ keystore: ks2, homeDir: homeR2, trustedLicenseKeys: [authorKey.publicKey] })
    await setup.importLicense(lic2)
    const nearExpiry = (verifyLicense(lic2, [authorKey.publicKey]).exp - 3600) * 1000
    const client = new LicenseClient({
      serverUrl: 'http://127.0.0.1:9', keystore: ks2, homeDir: homeR2,
      trustedLicenseKeys: [authorKey.publicKey], retry: { attempts: 1, baseMs: 1, maxMs: 1 }, now: () => nearExpiry,
    })
    const r = await capture(client.ensureLicense({ id: PACK_ID, version: VERSION }))
    if (r.error) errorTexts.push(messageOf(r.error))
    record('renew-offline-keeps-cache', r.value?.source === 'cache' && (r.value.state === 'active' || r.value.state === 'grace'), r.error ? messageOf(r.error) : 'source=' + r.value.source + ' state=' + r.value.state)
  }

  // 已过 exp 未续上 -> grace; grace 仍服务; grace 结束 -> 停用技能.
  {
    const graceNow = (payload.exp + 3600) * 1000
    const pastGrace = (payload.grace_until + 3600) * 1000
    const statusGrace = licenseStatus(payload, graceNow)
    const statusExpired = licenseStatus(payload, pastGrace)
    record('grace-window', statusGrace === 'grace' && statusExpired === 'expired', 'grace=' + statusGrace + ' expired=' + statusExpired)
    const graceCore = new SealedCore({ pack, license, trustedLicenseKeys: [authorKey.publicKey], keystore, now: () => graceNow })
    const graceRead = await capture(graceCore.readSkill(SKILL))
    if (graceRead.error) errorTexts.push(messageOf(graceRead.error))
    record('grace-still-serves', graceRead.value?.content?.includes(canary) === true, graceRead.error ? messageOf(graceRead.error) : 'read served')
    const expiredCore = new SealedCore({ pack, license, trustedLicenseKeys: [authorKey.publicKey], keystore, now: () => pastGrace })
    const expiredRead = await capture(expiredCore.readSkill(SKILL))
    if (expiredRead.error) errorTexts.push(messageOf(expiredRead.error))
    record('grace-end-refuses', expiredRead.error?.code === 'LICENSE_EXPIRED', expiredRead.error ? messageOf(expiredRead.error) : 'unexpectedly served')
  }

  // 系统时钟回拨 -> CLOCK_UNTRUSTED (cached license + unreachable server).
  {
    const homeR5 = join(scratch, 'r5'); mkdirSync(homeR5, { recursive: true })
    const ks5 = new FileKeystore({ dir: homeR5 }); await ks5.createDeviceKey()
    const lic5 = makeTrialLicense({
      manifest, master, devicePublicKey: x25519PublicFromRaw(await ks5.loadDevicePublicKey()),
      trialEntryIds, days: 7, signingKey: authorKey.privateKey,
    })
    const reader = new LicenseClient({ keystore: ks5, homeDir: homeR5, trustedLicenseKeys: [authorKey.publicKey] })
    await reader.importLicense(lic5)
    // The handshake anchor is AHEAD of the local clock (a rollback / a poisoned clock file).
    writeFileSync(join(homeR5, 'clock.json'), JSON.stringify({ v: 1, lastSeenMs: Date.now() + 10 * 86400000 }))
    const client = new LicenseClient({
      serverUrl: 'http://127.0.0.1:9', serverProofPubB64: proofPubB64, keystore: ks5, homeDir: homeR5,
      trustedLicenseKeys: [authorKey.publicKey], retry: { attempts: 1, baseMs: 1, maxMs: 1 },
    })
    const r = await capture(client.ensureLicense({ id: PACK_ID, version: VERSION }))
    const message = r.error ? messageOf(r.error) : ''
    errorTexts.push(message)
    record('clock-rollback', r.error instanceof LicenseDenied && r.error.code === 'CLOCK_UNTRUSTED', message || 'no rollback detected')
  }

  // license 验签失败 -> 拒绝（不缓存）.
  {
    const bad = await capture(Promise.resolve().then(() => verifyLicense('not-a-license', [authorKey.publicKey])))
    if (bad.error) errorTexts.push(messageOf(bad.error))
    record('license-bad-signature', bad.error !== undefined, bad.error ? messageOf(bad.error) : 'unexpectedly verified')
    const homeR6 = join(scratch, 'r6'); mkdirSync(homeR6, { recursive: true })
    const client = new LicenseClient({ keystore: new FileKeystore({ dir: homeR6 }), homeDir: homeR6, trustedLicenseKeys: [authorKey.publicKey] })
    const denied = await capture(client.importLicense('not-a-license'))
    if (denied.error) errorTexts.push(messageOf(denied.error))
    record('import-bad-license-refused', denied.error instanceof LicenseDenied && denied.error.code === 'BAD_SERVER_LICENSE', denied.error ? messageOf(denied.error) : 'unexpectedly imported')
  }

  // license 与设备不符 -> 拒绝.
  {
    const homeR7 = join(scratch, 'r7'); mkdirSync(homeR7, { recursive: true })
    const otherKeystore = new FileKeystore({ dir: homeR7 }); await otherKeystore.createDeviceKey()
    const otherCore = new SealedCore({ pack, license, trustedLicenseKeys: [authorKey.publicKey], keystore: otherKeystore })
    const r = await capture(otherCore.readSkill(SKILL))
    if (r.error) errorTexts.push(messageOf(r.error))
    record('license-device-mismatch', r.error?.code === 'LICENSE_INVALID', r.error ? messageOf(r.error) : 'unexpectedly served')
  }

  // 包被篡改: manifest 签名失败 + AEAD 标签失败.
  {
    const parsed = readContainer(pack)
    const tamperedSignature = Buffer.from(pack)
    const signatureOffset = 12 + parsed.manifestBytes.length + 4
    tamperedSignature[signatureOffset] = tamperedSignature[signatureOffset] ^ 0xff
    const rSig = await capture(Promise.resolve().then(() => new SealedCore({ pack: tamperedSignature, license, trustedLicenseKeys: [authorKey.publicKey], keystore })))
    if (rSig.error) errorTexts.push(messageOf(rSig.error))
    record('pack-tampered-signature', rSig.error?.code === 'PACK_SIGNATURE', rSig.error ? messageOf(rSig.error) : 'unexpectedly accepted')

    const bodyChunk = parsed.chunks.find((chunk) => chunk.id === ENTRY_BODY)
    const tamperedTag = Buffer.from(pack)
    tamperedTag[bodyChunk.offset + 12] = tamperedTag[bodyChunk.offset + 12] ^ 0xff
    const tamperedCore = new SealedCore({ pack: tamperedTag, license, trustedLicenseKeys: [authorKey.publicKey], keystore })
    const rTag = await capture(tamperedCore.readSkill(SKILL))
    if (rTag.error) errorTexts.push(messageOf(rTag.error))
    record('pack-tampered-aead', rTag.error?.code === 'DECRYPT_FAILED', rTag.error ? messageOf(rTag.error) : 'unexpectedly decrypted')
  }

  // 包版本过新 -> 拒绝并提示升级.
  {
    const newer = Buffer.from(pack)
    newer[6] = PACK_FORMAT_VERSION + 1
    const r = await capture(Promise.resolve().then(() => readContainer(newer)))
    if (r.error) errorTexts.push(messageOf(r.error))
    record('pack-version-too-new', r.error?.code === 'BAD_VERSION', r.error ? messageOf(r.error) : 'unexpectedly accepted')
  }

  // 设备私钥丢失 -> 触发重新激活 / 拒绝.
  {
    const homeR10 = join(scratch, 'r10'); mkdirSync(homeR10, { recursive: true })
    const emptyKeystore = new FileKeystore({ dir: homeR10 })
    const absent = await emptyKeystore.loadDevicePrivateKey()
    const coreNoKey = new SealedCore({ pack, license, trustedLicenseKeys: [authorKey.publicKey], keystore: emptyKeystore })
    const r = await capture(coreNoKey.readSkill(SKILL))
    if (r.error) errorTexts.push(messageOf(r.error))
    record('device-key-missing', absent === undefined && r.error?.code === 'LICENSE_INVALID', r.error ? messageOf(r.error) : 'unexpectedly served')
  }

  // 密钥库不可用/被锁 -> 降级只读发现（能列、不能解密；本实现的名字在加密 meta 中，故 list 也诚实降级为空）.
  {
    const brokenKeystore = {
      loadDevicePrivateKey: async () => { throw new KeystoreError('keystore is locked') },
      loadDevicePublicKey: async () => undefined,
      createDeviceKey: async () => {},
      deleteDeviceKey: async () => {},
    }
    const brokenCore = new SealedCore({ pack, license, trustedLicenseKeys: [authorKey.publicKey], keystore: brokenKeystore })
    const r = await capture(brokenCore.readSkill(SKILL))
    if (r.error) errorTexts.push(messageOf(r.error))
    record('keystore-unavailable-refuses-decrypt', r.error?.code === 'LICENSE_INVALID', r.error ? messageOf(r.error) : 'unexpectedly served')
    const brokenList = await createDshSkillProvider(brokenCore).list({})
    record('keystore-unavailable-list-degrades', Array.isArray(brokenList) && brokenList.length === 0, 'list length ' + brokenList.length)
  }
  // log-mask 注册失败 -> fail-closed: the provider refuses; the warning is redacted.
  {
    const warnings = []
    let captured = null
    const homeR15 = join(scratch, 'r15'); mkdirSync(homeR15, { recursive: true })
    const ctx = {
      skills: { registerProvider: (create) => { captured = create({ signal: new AbortController().signal, invalidate() {} }); return () => {} } },
      sessions: { registerMessageProjection() { throw new Error('the projection registry is unavailable') } },
      on() { return () => {} },
      logger: { warn: (message) => warnings.push(message) },
    }
    const dispose = apply(ctx, {
      mounts: [{ packPath, licensePath }], trustedLicenseKeysB64: [authorPub], keystoreDir: homeR15,
    })
    const list = await captured.list({})
    const get = await captured.get({ name: SKILL, locator: { sealedSkill: SKILL } }, {})
    record('logmask-not-ready-fail-closed', list.length === 0 && get === undefined, 'list=' + list.length + ' get=' + (get === undefined ? 'refused' : 'served'))
    errorTexts.push(...warnings.map(String))
    if (warnings.some((warning) => String(warning).includes(canary))) failures.push('§8 the log-mask readiness warning leaked plaintext')
    dispose()
  }

  // 沙箱不可用/审批被拒 -> 拒绝脚本类工具；纯提示词技能不受影响.
  {
    const unavailable = await executeSealedScript(
      {
        readEntry: (id) => core.readEntry(id),
        confine: async () => { const error = new Error('no sandbox'); error.code = 'SANDBOX_UNAVAILABLE'; throw error },
      },
      { name: SKILL, entryId: scriptEntryId, runtime: 'node', policy: { mode: 'read-only', workspaceRoot: scratch } },
    )
    errorTexts.push(JSON.stringify(unavailable))
    record('sandbox-unavailable', unavailable.ok === false && unavailable.reason === 'sandbox-unavailable', JSON.stringify(unavailable))
    const partial = await executeSealedScript(
      { readEntry: (id) => core.readEntry(id), confine: async (argv) => ({ argv: [...argv], enforcement: 'partial' }) },
      { name: SKILL, entryId: scriptEntryId, runtime: 'node', policy: { mode: 'read-only', workspaceRoot: scratch } },
    )
    errorTexts.push(JSON.stringify(partial))
    record('sandbox-not-enforcing', partial.ok === false && partial.reason === 'sandbox-not-enforcing', JSON.stringify(partial))
    const promptSkill = await provider.get({ name: SKILL, locator: { sealedSkill: SKILL } }, {})
    record('sandbox-refusal-keeps-prompt-skills', typeof promptSkill?.content === 'string' && promptSkill.content.length > 0, 'provider still serves prompt-only skills')
  }

  // 条目解密内存超限 -> 报错而非 OOM（打包器在写入前按 MAX_ENTRY_BYTES 拒绝）.
  {
    const oversized = {
      pack_id: PACK_ID, version: VERSION, label: 'oversized', entry_count: 1,
      entries: [{ id: ENTRY_BODY, type: 'text', size: MAX_ENTRY_BYTES + 1, trial: false }],
    }
    const r = await capture(Promise.resolve().then(() => writeContainer({
      manifest: oversized, chunks: [{ id: ENTRY_BODY, nonce: Buffer.alloc(12), ct: Buffer.alloc(1) }], signature: Buffer.alloc(64),
    })))
    if (r.error) errorTexts.push(messageOf(r.error))
    record('entry-too-large', r.error?.code === 'TOO_LARGE', r.error ? messageOf(r.error) : 'unexpectedly written')
  }

  // 服务端 5xx / 限流 -> 退避重试；不删除本地 license.
  {
    const homeR19 = join(scratch, 'r19'); mkdirSync(homeR19, { recursive: true })
    const ks19 = new FileKeystore({ dir: homeR19 }); await ks19.createDeviceKey()
    const lic19 = makeTrialLicense({
      manifest, master, devicePublicKey: x25519PublicFromRaw(await ks19.loadDevicePublicKey()),
      trialEntryIds, days: 7, signingKey: authorKey.privateKey,
    })
    const client500 = new LicenseClient({
      serverUrl: 'http://127.0.0.1:9', serverProofPubB64: proofPubB64, keystore: ks19, homeDir: homeR19, trustedLicenseKeys: [authorKey.publicKey],
      retry: { attempts: 1, baseMs: 1, maxMs: 1 }, fetchFn: async () => new Response('{}', { status: 503 }),
    })
    await client500.importLicense(lic19)
    const cachePath = join(homeR19, 'licenses', verifyLicense(lic19, [authorKey.publicKey]).lid + '.license.json')
    const r500 = await capture(client500.renew({ id: PACK_ID, version: VERSION }, lic19))
    if (r500.error) errorTexts.push(messageOf(r500.error))
    record('server-5xx-backoff-keeps-license', r500.error instanceof LicenseDenied && r500.error.code === 'SERVER_UNAVAILABLE' && existsSync(cachePath), r500.error ? messageOf(r500.error) : 'unexpectedly renewed')
    const client429 = new LicenseClient({
      serverUrl: 'http://127.0.0.1:9', serverProofPubB64: proofPubB64, keystore: ks19, homeDir: homeR19, trustedLicenseKeys: [authorKey.publicKey],
      retry: { attempts: 1, baseMs: 1, maxMs: 1 },
      fetchFn: async () => new Response(JSON.stringify({ error: { code: 'RATE_LIMITED', message: 'too many requests' } }), { status: 429, headers: { 'content-type': 'application/json' } }),
    })
    const r429 = await capture(client429.renew({ id: PACK_ID, version: VERSION }, lic19))
    if (r429.error) errorTexts.push(messageOf(r429.error))
    record('rate-limited-keeps-license', r429.error instanceof LicenseDenied && r429.error.code === 'SERVER_REJECTED' && existsSync(cachePath), r429.error ? messageOf(r429.error) : 'unexpectedly renewed')
  }

  // nonce 重放 -> 该次续期被拒.
  {
    const homeR20 = join(scratch, 'r20'); mkdirSync(homeR20, { recursive: true })
    const ks20 = new FileKeystore({ dir: homeR20 }); await ks20.createDeviceKey()
    const lic20 = makeTrialLicense({
      manifest, master, devicePublicKey: x25519PublicFromRaw(await ks20.loadDevicePublicKey()),
      trialEntryIds, days: 7, signingKey: authorKey.privateKey,
    })
    const client = new LicenseClient({
      serverUrl: 'http://127.0.0.1:9', keystore: ks20, homeDir: homeR20, trustedLicenseKeys: [authorKey.publicKey],
      serverProofPubB64: proofPubB64, retry: { attempts: 1, baseMs: 1, maxMs: 1 },
      fetchFn: async () => new Response(JSON.stringify({ error: { code: 'REPLAY', message: 'this nonce was already used' } }), { status: 409, headers: { 'content-type': 'application/json' } }),
    })
    const r = await capture(client.renew({ id: PACK_ID, version: VERSION }, lic20))
    if (r.error) errorTexts.push(messageOf(r.error))
    record('nonce-replay-refused', r.error instanceof LicenseDenied && r.error.code === 'SERVER_REJECTED', r.error ? messageOf(r.error) : 'unexpectedly renewed')
  }

  // 插件卸载/进程退出 -> 零化内存中的明文缓冲.
  {
    const reveal = createPlaintextReveal()
    reveal.save(ENTRY_BODY, body)
    const before = reveal.reveal(ENTRY_BODY, SEALED_REDACTED_ALG)
    reveal.dispose()
    const after = reveal.reveal(ENTRY_BODY, SEALED_REDACTED_ALG)
    record('dispose-zeroizes-plaintext', typeof before === 'string' && before.includes(canary) && after === undefined, 'after dispose: ' + (after === undefined ? 'zeroized' : 'STILL PRESENT'))
  }

  // 错误消息/遥测不得携带受保护明文（Task 6 违规消息 + 类型走私探针）.
  {
    const violation = findSealedPlaintext({ type: 'tool/result', seq: 3, data: { text: canary } }, (text) => text.includes(canary), 24)
    errorTexts.push(String(violation))
    record('invariant-message-body-free', violation !== undefined && !violation.includes(canary), violation ?? 'no violation detected')
    const smuggled = findSealedPlaintext({ type: canary, seq: 4, data: {} }, (text) => text.includes(canary), 24)
    errorTexts.push(String(smuggled))
    record('invariant-type-field-redacted', smuggled === undefined || !smuggled.includes(canary), smuggled ?? 'no violation detected')
  }

  // ---- real in-process license server: publish, seat limit, trial reuse, revocation -------------
  {
    const serverKeys = loadServerKeys({
      SEALED_SERVER_LICENSE_KEY: generateKeyPairSync('ed25519').privateKey.export({ format: 'jwk' }).d,
      SEALED_SERVER_PROOF_KEY: rawPrivateBytes(proofKeys.privateKey).toString('base64url'),
      SEALED_SERVER_MASTER_KEY: b64u(Buffer.alloc(32, 7)),
    })
    const store = openStore(':memory:')
    const server = createApp({ store, keys: serverKeys, adminToken: 'admin' })
    await new Promise((done) => server.listen(0, '127.0.0.1', done))
    const serverUrl = 'http://127.0.0.1:' + server.address().port
    const trustedServerKeys = [createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: serverLicensePublicB64(serverKeys) }, format: 'jwk' })]
    const adminHeaders = { 'content-type': 'application/json', authorization: 'Bearer admin' }
    try {
      const published = await fetch(serverUrl + '/v1/admin/packs', {
        method: 'POST', headers: adminHeaders,
        body: JSON.stringify({
          pack: { id: PACK_ID, version: VERSION }, author_pub: authorPub, label: 'leak-gate',
          master_b64: master.toString('base64url'), trial_entries: trialEntryIds,
          entries: manifest.entries.map((entry) => ({ id: entry.id, type: entry.type, size: entry.size })),
        }),
      })
      record('license-server-publish', published.status === 200, 'publish status ' + published.status)

      store.putPurchase({ token: 'purchase-seats', sub: 'cust-seats', packId: PACK_ID, version: VERSION, plan: 'pro', seats: 1 })
      const homeSeatA = join(scratch, 'seat-a'); mkdirSync(homeSeatA, { recursive: true })
      const homeSeatB = join(scratch, 'seat-b'); mkdirSync(homeSeatB, { recursive: true })
      const ksSeatA = new FileKeystore({ dir: homeSeatA }); await ksSeatA.createDeviceKey()
      const ksSeatB = new FileKeystore({ dir: homeSeatB }); await ksSeatB.createDeviceKey()
      const clientSeatA = new LicenseClient({ serverUrl, serverProofPubB64: serverKeys.proofPublicB64, keystore: ksSeatA, homeDir: homeSeatA, trustedLicenseKeys: trustedServerKeys })
      const clientSeatB = new LicenseClient({ serverUrl, serverProofPubB64: serverKeys.proofPublicB64, keystore: ksSeatB, homeDir: homeSeatB, trustedLicenseKeys: trustedServerKeys })
      const seatA = await capture(clientSeatA.activate({ id: PACK_ID, version: VERSION }, 'purchase-seats'))
      const seatB = await capture(clientSeatB.activate({ id: PACK_ID, version: VERSION }, 'purchase-seats'))
      if (seatB.error) errorTexts.push(messageOf(seatB.error))
      record('seat-limit-409', seatA.value !== undefined && seatB.error instanceof LicenseDenied && seatB.error.code === 'SERVER_REJECTED', seatB.error ? messageOf(seatB.error) : 'second seat unexpectedly granted')

      const homeTrial = join(scratch, 'trial-used'); mkdirSync(homeTrial, { recursive: true })
      const ksTrial = new FileKeystore({ dir: homeTrial }); await ksTrial.createDeviceKey()
      const clientTrial = new LicenseClient({ serverUrl, serverProofPubB64: serverKeys.proofPublicB64, keystore: ksTrial, homeDir: homeTrial, trustedLicenseKeys: trustedServerKeys })
      const trialFirst = await capture(clientTrial.activateTrial({ id: PACK_ID, version: VERSION }))
      const trialSecond = await capture(clientTrial.activateTrial({ id: PACK_ID, version: VERSION }))
      if (trialSecond.error) errorTexts.push(messageOf(trialSecond.error))
      record('trial-already-used-409', trialFirst.value !== undefined && trialSecond.error instanceof LicenseDenied && trialSecond.error.code === 'SERVER_REJECTED', trialSecond.error ? messageOf(trialSecond.error) : 'second trial unexpectedly granted')

      if (seatA.value !== undefined) {
        const revoked = await fetch(serverUrl + '/v1/revoke', { method: 'POST', headers: adminHeaders, body: JSON.stringify({ license_id: seatA.value.payload.lid }) })
        const revokedBody = await revoked.json()
        const renewAfterRevoke = await capture(clientSeatA.renew({ id: PACK_ID, version: VERSION }, seatA.value.license))
        if (renewAfterRevoke.error) errorTexts.push(messageOf(renewAfterRevoke.error))
        record('revoked-403', revoked.status === 200 && revokedBody.revoked === 1 && renewAfterRevoke.error instanceof LicenseDenied && renewAfterRevoke.error.code === 'LICENSE_REVOKED', renewAfterRevoke.error ? messageOf(renewAfterRevoke.error) : 'renew after revoke unexpectedly succeeded')
        const revokedCache = join(homeSeatA, 'licenses', seatA.value.payload.lid + '.license.json')
        record('revoked-drops-local-license', !existsSync(revokedCache), existsSync(revokedCache) ? 'cache still present' : 'cache removed')
      }
    } finally {
      server.close()
    }
  }

  // 限流 -> 服务端以 429 直接拒绝.
  {
    const serverKeys = loadServerKeys({
      SEALED_SERVER_LICENSE_KEY: generateKeyPairSync('ed25519').privateKey.export({ format: 'jwk' }).d,
      SEALED_SERVER_PROOF_KEY: rawPrivateBytes(proofKeys.privateKey).toString('base64url'),
      SEALED_SERVER_MASTER_KEY: b64u(Buffer.alloc(32, 7)),
    })
    const rlServer = createApp({ store: openStore(':memory:'), keys: serverKeys, adminToken: 'admin', rateLimit: { windowMs: 60_000, max: 1 } })
    await new Promise((done) => rlServer.listen(0, '127.0.0.1', done))
    try {
      const rlUrl = 'http://127.0.0.1:' + rlServer.address().port
      const headers = { 'content-type': 'application/json' }
      const body = JSON.stringify({ device_pub: 'x', pack: { id: 'a', version: '1' } })
      const first = await fetch(rlUrl + '/v1/trial', { method: 'POST', headers, body })
      const second = await fetch(rlUrl + '/v1/trial', { method: 'POST', headers, body })
      record('rate-limit-429', first.status !== 429 && second.status === 429, 'statuses ' + first.status + ',' + second.status)
    } finally {
      rlServer.close()
    }
  }
  // ---- write the runtime log/telemetry surfaces, then the real-machine (gated) session ----------
  writeFileSync(join(logsDir, 'plugin.log'), ['[sealed-skills] log-mask ready', ...rows.map((row) => '[' + row.id + '] ' + row.detail)].join('\n') + '\n')
  writeFileSync(join(telemetryDir, 'events.json'), JSON.stringify({ rows: rows.map((row) => ({ id: row.id, ok: row.ok })) }, null, 2) + '\n')
  const gated = await runGatedRealSession({ scratch, canary, plaintext, entryId: ENTRY_BODY, failures, note })

  // ---- scanner self-check (positive control): a raw and a zstd-borne canary MUST be detected ----
  const selfcheck = join(scratch, 'selfcheck')
  mkdirSync(selfcheck, { recursive: true })
  writeFileSync(join(selfcheck, 'needle.bin'), Buffer.concat([Buffer.from('prefix'), Buffer.from(canary), Buffer.from('suffix')]))
  writeFileSync(join(selfcheck, 'needle.jsonl.zstd'), zstdCompressSync(Buffer.from('{"x":"' + canary + '"}\n')))
  const selfHits = scanFilesForNeedles(listFiles(selfcheck), needles)
  if (!selfHits.some((hit) => hit.how === 'raw')) failures.push('scanner self-check failed: a raw canary was not detected')
  if (!selfHits.some((hit) => hit.how === 'zstd')) failures.push('scanner self-check failed: a zstd-compressed canary was not detected')
  rmSync(selfcheck, { recursive: true, force: true })

  // The author source dir is an INPUT, not a runtime artifact: remove it, then the whole scratch
  // tree is scanned. A failure to remove it would itself be a real "plaintext left on disk" find.
  rmSync(author, { recursive: true, force: true })

  const files = listFiles(scratch)
  const hits = scanFilesForNeedles(files, needles)
  for (const hit of hits) failures.push('plaintext found on disk: ' + hit.file + ' (' + hit.label + '/' + hit.how + ')')

  const leakedCorpus = errorTexts.filter((text) => needles.some((entry) => Buffer.from(String(text), 'utf8').includes(entry.needle)))
  if (leakedCorpus.length > 0) failures.push('an error/telemetry message carried protected plaintext (' + leakedCorpus.length + ' message(s))')

  note('scanned ' + files.length + ' file(s); §8 rows ' + rows.filter((row) => row.ok).length + '/' + rows.length + ' ok; gated=' + gated)
  return { failures, rows, gated, scannedFiles: files.length }
}

// --- helpers ------------------------------------------------------------------------------------

function writeAuthorTree(dir, bodyLine, scriptSource, resourceText) {
  mkdirSync(join(dir, 'scripts'), { recursive: true })
  mkdirSync(join(dir, 'resources'), { recursive: true })
  const skillMarkdown = [
    '---',
    'name: ' + SKILL,
    'description: leak-gate canary skill',
    'whenToUse: internal leak-gate only',
    '---',
    '',
    bodyLine,
    '',
  ].join('\n')
  writeFileSync(join(dir, 'SKILL.md'), skillMarkdown, 'utf8')
  writeFileSync(join(dir, 'scripts', 'run.mjs'), scriptSource, 'utf8')
  writeFileSync(join(dir, 'resources', 'blob.txt'), resourceText, 'utf8')
}

function delay(ms) {
  return new Promise((done) => setTimeout(done, ms))
}

/** Wait until the child writes `token` on stdout (or the deadline passes). Resolves a boolean. */
function waitForStdout(child, token, timeoutMs) {
  return new Promise((resolveDone) => {
    let seen = ''
    const timer = setTimeout(() => { cleanup(); resolveDone(false) }, timeoutMs)
    const onData = (chunk) => {
      seen += String(chunk)
      if (seen.includes(token)) { cleanup(); resolveDone(true) }
    }
    const cleanup = () => {
      clearTimeout(timer)
      child.stdout?.off?.('data', onData)
    }
    child.stdout?.on('data', onData)
  })
}

function waitForExit(child, timeoutMs) {
  return new Promise((resolveDone) => {
    const timer = setTimeout(() => resolveDone('timeout'), timeoutMs)
    child.once('exit', () => { clearTimeout(timer); resolveDone('exited') })
  })
}

/**
 * Crash safety: a child decrypts the sealed body in memory and is SIGKILLed mid-flight. Nothing
 * may reach disk. The child receives only ciphertext paths + the author's PUBLIC key (never the
 * canary), and its program arrives on stdin, not on argv.
 */
async function runCrashResidue({ scratch, packPath, licensePath, home, authorPubB64 }, failures) {
  const crashDir = join(scratch, 'crash')
  mkdirSync(crashDir, { recursive: true })
  const distIndex = pathToFileURL(join(ROOT, 'packages', 'dsh-sealed-skills', 'dist', 'index.js')).href
  const program = [
    "import { readFileSync } from 'node:fs'",
    "import { createPublicKey } from 'node:crypto'",
    'const [packPath, licensePath, homeDir, authorPubB64, entryId, skillName] = process.argv.slice(2)',
    '  void entryId',
    'const mod = await import(' + JSON.stringify(distIndex) + ')',
    'const trusted = [createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: authorPubB64 }, format: "jwk" })]',
    'const core = new mod.SealedCore({ pack: readFileSync(packPath), license: readFileSync(licensePath, "utf8"), trustedLicenseKeys: trusted, keystore: new mod.FileKeystore({ dir: homeDir }) })',
    "process.stdout.write('START\\n')",
    'for (;;) { const skill = await core.readSkill(skillName); void skill.content.length }',
    '',
  ].join('\n')

  const child = spawn(process.execPath, ['--input-type=module', '-', packPath, licensePath, home, authorPubB64, ENTRY_BODY, SKILL], {
    cwd: crashDir, stdio: ['pipe', 'pipe', 'pipe'],
  })
  child.stdout?.on('data', () => {})
  child.stderr?.on('data', () => {})
  try { child.stdin?.end(program) } catch { /* surfaced through the START wait below */ }

  const started = await waitForStdout(child, 'START', 5000)
  if (!started) failures.push('crash-residue: the decrypting child never reported START')
  await delay(150)
  try { child.kill('SIGKILL') } catch { /* already gone */ }
  await waitForExit(child, 5000)
}
/**
 * The opt-in REAL-machine sub-check. Uses a genuine `@deepseek-ai/dsh-session` Session (absolute
 * path from the out-of-tree lab — never added to the dependency graph) with the real projection:
 * the durable log must stay placeholder-only while `deriveMessages()` reveals the canary. The
 * durable snapshot is written as both `session.jsonl` and a real zstd `session.jsonl.zstd`, then
 * swept by the main scan. A missing lab is a LOUD skip (UNVERIFIED), never a pass.
 */
async function runGatedRealSession({ scratch, canary, plaintext, entryId, failures, note }) {
  if (process.env.SEALED_DSH_LAB !== '1') {
    note('gated real-machine check SKIPPED (UNVERIFIED): SEALED_DSH_LAB is not set to 1')
    return 'skipped:no-env'
  }
  if (!existsSync(LAB_SESSION)) {
    note('gated real-machine check SKIPPED (UNVERIFIED): the dsh lab is not installed at ' + LAB_SESSION)
    return 'skipped:no-lab'
  }
  try {
    const sessionModule = await import(pathToFileURL(LAB_SESSION).href)
    const Session = sessionModule.Session
    const known = sessionModule.KNOWN_SESSION_EVENT_TYPES
    if (typeof Session?.create !== 'function' || !(known instanceof Set)) {
      note('gated real-machine check SKIPPED (UNVERIFIED): the lab dsh-session does not export the expected surface')
      return 'skipped:no-api'
    }
    // The Task 5 Ruling: a harness WITH this plugin must admit the marker type.
    known.add(SEALED_REDACTED)
    const { token } = renderPlaceholder(entryId)
    const placeholder = placeholderFor(token)
    const projection = createLogMaskProjection({ reveal: plaintext.reveal })
    const session = Session.create('leak-gate', undefined, undefined, undefined, [projection])
    const appended = session.append(
      'tool/result',
      { turn: 0, step: 0, message: { id: 'lg-real-1', role: 'tool', content: [{ type: 'text', text: placeholder }] } },
      { surfaceOp: 'append' },
    )
    session.append(SEALED_REDACTED, sealedRedactedData(appended.seq, entryId, token))
    const durable = session.snapshotEvents()
    const derived = session.deriveMessages().find((message) => message.id === 'lg-real-1')
    const revealed = derived?.content?.[0]?.text ?? ''
    if (!revealed.includes(canary)) failures.push('gated: the real dsh-session did not reveal the sealed body to the model view')
    if (JSON.stringify(durable).includes(canary)) failures.push('gated: the real dsh-session durable log contains the sealed body')
    const gatedDir = join(scratch, 'gated-session')
    mkdirSync(gatedDir, { recursive: true })
    const jsonl = Buffer.from(durable.map((event) => JSON.stringify(event)).join('\n') + '\n', 'utf8')
    writeFileSync(join(gatedDir, 'session.jsonl'), jsonl)
    writeFileSync(join(gatedDir, 'session.jsonl.zstd'), zstdCompressSync(jsonl))
    note('gated real-machine check PASSED (real dsh-session: durable log placeholder-only, model view reveals the canary)')
    return 'passed'
  } catch (error) {
    failures.push('gated: the real dsh-session check threw (' + (error instanceof Error ? error.name : 'unknown') + ')')
    return 'failed'
  }
}

export { main, runGate, writeAuthorTree, runCrashResidue, runGatedRealSession }

if (invokedDirectly) await main()
