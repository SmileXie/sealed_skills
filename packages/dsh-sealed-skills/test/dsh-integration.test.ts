import { spawnSync } from 'node:child_process'
import { generateKeyPairSync, randomBytes, type KeyObject } from 'node:crypto'
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import type { AddressInfo } from 'node:net'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import {
  deriveEntryKey, encodeManifest, entryAad, sealEntry, signManifest, writeContainer,
  type PackEntryMeta, type PackManifest,
} from '@sealed/pack-format'
import { b64u, rawPrivateBytes } from '@sealed/license-format'
import { createApp, loadServerKeys, openStore, serverLicensePublicB64 } from '@sealed/license-server'
import { parsePlaceholder } from '../src/session-events.js'

/**
 * Real dsh 0.2.x runtime integration — closes M2's long-standing "plugin loader UNVERIFIED" gap.
 *
 * Two layers are driven, and the task report names exactly which:
 *  1. The app-boot *profile loader* (`loadProfile` / `evaluatePluginCompatibility` / `composeEntries`)
 *     resolves our shipped bundle `@sealed/dsh-sealed-skills` through its `dsh.bundle` declaration —
 *     no generated shim — and confirms our real package clears the dsh peer compatibility gate.
 *  2. A credential-free programmatic boot (`app-boot.boot`) of a minimal entry list
 *     (`@deepseek-ai/dsh-skill` + `@deepseek-ai/dsh-session` + `@sealed/dsh-sealed-skills`, all resolved by their genuine package
 *     names) runs `apply(ctx, config)` against the real `SkillRegistry`, with a real signed pack and a
 *     real license server.
 *
 * The full shipped profile (`@deepseek-ai/dsh-base` + `@deepseek-ai/dsh-headless`) is deliberately NOT
 * booted: its headless app requires model credentials (`MISSING_CREDENTIAL`), so the real `dsh` CLI is
 * driven only for credential-free config composition. Everything here needs the optional lab
 * (`SEALED_DSH_LAB=1`); a missing lab is UNVERIFIED, never a pass.
 */
const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..', '..')
const LAB = join(REPO_ROOT, '.dsh-lab')
const LAB_SCRIPT = join(REPO_ROOT, 'scripts', 'dsh-lab.mjs')
const PLUGIN_DIR = join(REPO_ROOT, 'packages', 'dsh-sealed-skills')
const DSH_BIN = join(LAB, 'node_modules', '@deepseek-ai', 'dsh', 'lib', 'bin.js')
const DSH_MANIFEST = join(LAB, 'node_modules', '@deepseek-ai', 'dsh', 'package.json')
const APP_BOOT = join(LAB, 'node_modules', '@deepseek-ai', 'dsh-app-boot', 'lib', 'index.js')
const SESSION_ENTRY = join(LAB, 'node_modules', '@deepseek-ai', 'dsh-session', 'lib', 'index.js')
const DSH_HOME = join(LAB, 'home')
/**
 * A profile name dedicated to this test file. Vitest runs test files in parallel and
 * `test/dsh-lab.test.ts` regenerates the shared default profile; a dedicated directory keeps the
 * two writers from clobbering each other's `cordis.patch.yml` (intermittent false-RED under
 * `SEALED_DSH_LAB=1`). Passed to the lab via `SEALED_DSH_LAB_PROFILE_NAME`.
 */
const PROFILE_NAME = 'm3-lab-integration'
const PROFILE_DIR = join(DSH_HOME, 'profiles', PROFILE_NAME)
const SEALED_HOME = join(LAB, 'sealed')
const VERIFY_DIR = join(LAB, 'verify')
const BUNDLE_NAME = '@sealed/dsh-sealed-skills'
const PLUGIN_ID = 'sealed-skills'
const PACK_ID = 'com.example.translate'
const VERSION = '1.0.0'
const PURCHASE = 'purchase-lab'
const ADMIN = 'admin-token'
const BODY = '把用户输入翻译成英文。\n'

const requested = process.env.SEALED_DSH_LAB === '1'
const installed = existsSync(DSH_BIN)
const enabled = requested && installed
const skipReason = requested
  ? `the dsh lab is not installed at ${DSH_BIN} (run: node scripts/dsh-lab.mjs --ensure)`
  : 'SEALED_DSH_LAB is not set to 1 (the dsh lab is opt-in)'

const toPosix = (value: string) => value.replace(/\\/g, '/')

const flushMicrotasks = () => new Promise<void>((resolve) => setTimeout(resolve, 0))

function readJson(file: string): any {
  return JSON.parse(readFileSync(file, 'utf8'))
}

/** A genuinely signed pack whose body entry is withheld from the trial set. */
function buildPack(authorPrivate: KeyObject): { file: Buffer; manifest: PackManifest; masterB64: string } {
  const entries: { id: string; type: PackEntryMeta['type']; body: string }[] = [
    {
      id: 'meta',
      type: 'meta',
      body: JSON.stringify({
        skills: [{
          name: 'translate',
          description: '翻译',
          invocation: { modelInvocable: true, userInvocable: true },
          entries: ['skill:translate:body'],
        }],
        resources: {},
      }),
    },
    { id: 'skill:translate:body', type: 'text', body: BODY },
  ]
  const master = randomBytes(32)
  const manifest: PackManifest = { pack_id: PACK_ID, version: VERSION, label: '翻译', entry_count: entries.length, entries: [] }
  const chunks = entries.map((entry) => {
    const key = deriveEntryKey(master, PACK_ID, VERSION, entry.id)
    const sealed = sealEntry(key, entryAad(PACK_ID, VERSION, entry.id), Buffer.from(entry.body, 'utf8'))
    manifest.entries.push({ id: entry.id, type: entry.type, size: sealed.ct.length, trial: entry.id !== 'skill:translate:body' })
    return { id: entry.id, nonce: sealed.nonce, ct: sealed.ct }
  })
  const signature = signManifest(encodeManifest(manifest), authorPrivate)
  return { file: writeContainer({ manifest, chunks, signature }), manifest, masterB64: master.toString('base64url') }
}
let server: { close: () => void } | undefined
let packPath = ''
let pluginConfig: Record<string, unknown> = {}
let licensePublicB64 = ''
let proofPublicB64 = ''
let serverUrl = ''

describe('real dsh 0.2.x runtime integration', () => {
  if (!enabled) {
    // Loud, explicit skip: a missing lab is UNVERIFIED, never a pass.
    console.warn(`[dsh-integration] SKIPPED — ${skipReason}`)
    it.skip(`skips because ${skipReason}`, () => {})
    return
  }

  beforeAll(async () => {
    const author = generateKeyPairSync('ed25519')
    const authorPub = (author.publicKey.export({ format: 'jwk' }) as { x: string }).x
    const proofKey = generateKeyPairSync('x25519')
    const keys = loadServerKeys({
      SEALED_SERVER_LICENSE_KEY: (generateKeyPairSync('ed25519').privateKey.export({ format: 'jwk' }) as { d: string }).d,
      SEALED_SERVER_PROOF_KEY: rawPrivateBytes(proofKey.privateKey).toString('base64url'),
      SEALED_SERVER_MASTER_KEY: b64u(Buffer.alloc(32, 4)),
    } as NodeJS.ProcessEnv)
    const store = openStore(':memory:')
    const app = createApp({ store, keys, adminToken: ADMIN })
    app.listen(0, '127.0.0.1')
    server = app
    await new Promise<void>((ready) => app.once('listening', () => ready()))
    serverUrl = 'http://127.0.0.1:' + (app.address() as AddressInfo).port
    licensePublicB64 = serverLicensePublicB64(keys)
    proofPublicB64 = keys.proofPublicB64

    const { file, manifest, masterB64 } = buildPack(author.privateKey)
    const published = await fetch(serverUrl + '/v1/admin/packs', {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: 'Bearer ' + ADMIN },
      body: JSON.stringify({
        pack: { id: PACK_ID, version: VERSION },
        author_pub: authorPub,
        label: '翻译',
        master_b64: masterB64,
        trial_entries: manifest.entries.filter((entry) => entry.trial).map((entry) => entry.id),
        entries: manifest.entries.map((entry) => ({ id: entry.id, type: entry.type, size: entry.size })),
      }),
    })
    expect(published.status).toBe(200)
    store.putPurchase({ token: PURCHASE, sub: 'cust', packId: PACK_ID, version: VERSION, plan: 'pro', seats: 1 })

    mkdirSync(SEALED_HOME, { recursive: true })
    mkdirSync(VERIFY_DIR, { recursive: true })
    // Deterministic fresh machine: drop any device key / cached licenses from a previous run so the
    // plugin must provision the device key on demand inside the real runtime (spec section 7.2 step 1).
    rmSync(join(SEALED_HOME, 'device.json'), { force: true })
    rmSync(join(SEALED_HOME, 'licenses'), { recursive: true, force: true })
    packPath = join(SEALED_HOME, 'translate.sealedpack')
    writeFileSync(packPath, file)

    const mountsFile = join(VERIFY_DIR, 'mounts.json')
    writeFileSync(mountsFile, JSON.stringify([{ packPath, purchaseToken: PURCHASE }]))
    pluginConfig = {
      trustedLicenseKeysB64: [licensePublicB64],
      serverUrl,
      serverProofPubB64: proofPublicB64,
      // The lab junctions this package, so the bare `@deepseek-ai/dsh-session` specifier cannot
      // resolve from our realpath; point the plugin's dynamic import at the installed entry.
      dshSessionModule: pathToFileURL(SESSION_ENTRY).href,
    }
    const configFile = join(VERIFY_DIR, 'plugin-config.json')
    writeFileSync(configFile, JSON.stringify(pluginConfig))

    const ensure = spawnSync(process.execPath, [LAB_SCRIPT, '--ensure'], {
      cwd: REPO_ROOT,
      encoding: 'utf8',
      env: {
        ...process.env,
        SEALED_DSH_LAB_PROFILE_NAME: PROFILE_NAME,
        SEALED_DSH_LAB_MOUNTS_FILE: mountsFile,
        SEALED_DSH_LAB_PLUGIN_CONFIG_FILE: configFile,
      },
    })
    expect(ensure.status, ensure.stderr ?? '').toBe(0)
  })

  afterAll(() => {
    server?.close()
    server = undefined
  })

  it('resolves our real bundle identity and passes the dsh peer compatibility gate', async () => {
    const appBoot = await import(pathToFileURL(APP_BOOT).href)
    const profile = appBoot.loadProfile('dsh', PROFILE_NAME, DSH_MANIFEST, DSH_HOME)
    // No skipped bundle at all: our real package resolves and its dsh peers satisfy the runtime.
    expect(profile.skippedBundles).toEqual([])
    expect(profile.layers.map((layer: any) => layer.packageName)).toContain(BUNDLE_NAME)
    // The peer gate itself, run against the manifest we actually ship.
    expect(appBoot.evaluatePluginCompatibility(readJson(join(PLUGIN_DIR, 'package.json')))).toBeUndefined()
    // The composed entry list carries our real entry, configured by the profile's own patch layer.
    const entries = appBoot.composeEntries([...profile.layers.map((layer: any) => layer.patches), profile.patches])
    const row = entries.filter((entry: any) => entry.id === PLUGIN_ID)
    expect(row).toHaveLength(1)
    expect(row[0].name).toBe(BUNDLE_NAME)
    expect(row[0].config.keystoreDir).toBe(toPosix(SEALED_HOME))
    expect(row[0].config.mounts).toHaveLength(1)
  })

  it('runs apply() in a real runtime and serves the licensed pack with no path', async () => {
    const appBoot = await import(pathToFileURL(APP_BOOT).href)
    const config = { ...pluginConfig, keystoreDir: toPosix(SEALED_HOME), mounts: [{ packPath, purchaseToken: PURCHASE }] }
    const cfg = join(VERIFY_DIR, 'cordis-apply.yml')
    writeFileSync(cfg, [
      '- id: skill',
      "  name: '@deepseek-ai/dsh-skill'",
      '- id: session',
      "  name: '@deepseek-ai/dsh-session'",
      `- id: ${PLUGIN_ID}`,
      `  name: '${BUNDLE_NAME}'`,
      `  config: ${JSON.stringify(config)}`,
      '',
    ].join('\n'))

    const changes: number[] = []
    const ctx: any = await appBoot.boot(
      'sealed-verify',
      cfg,
      [],
      (host: any) => { host.on('skills/change', () => changes.push(Date.now())) },
      pathToFileURL(PROFILE_DIR + '/').href,
    )
    try {
      // Registration invalidated the catalog: proof apply() reached the real registry.
      expect(changes.length).toBeGreaterThanOrEqual(1)
      const skills = ctx.get('skills')
      const summaries = await skills.list({ cwd: REPO_ROOT })
      const summary = summaries.find((item: any) => item.name === 'translate')
      expect(summary).toBeDefined()
      expect(summary.provider).toBe('sealed')
      expect(summary.source).toBe('custom')
      // The 0.2.x virtual-skill contract: no `path` key and no `resourceBase`.
      expect('path' in summary).toBe(false)
      expect(summary.path).toBeUndefined()
      expect(summary.resourceBase).toBeUndefined()
      expect(summary.description).toBe('翻译')

      const definition = await skills.get('translate', { cwd: REPO_ROOT })
      expect(definition?.provider).toBe('sealed')
      expect('path' in definition).toBe(false)
      expect(definition?.resourceBase).toBeUndefined()
      // Task 5: the provider serves an unguessable placeholder, never the body.
      const placeholder = definition?.content ?? ''
      expect(parsePlaceholder(placeholder)).toHaveLength(1)
      expect(placeholder).not.toContain(BODY)
      // The device key was provisioned on demand inside the real runtime.
      expect(existsSync(join(SEALED_HOME, 'device.json'))).toBe(true)

      // Task 5 end-to-end: both landing paths on a REAL session. The durable log holds only the
      // placeholder plus our marker; the model's derived view holds the plaintext.
      const sessions = ctx.get('sessions')
      const session = sessions.create('m3-landing-path')
      session.append(
        'tool/result',
        { turn: 0, step: 0, message: { id: 'tool-1', role: 'tool', content: [{ type: 'text', text: placeholder }] } },
        { surfaceOp: 'append' },
      )
      await flushMicrotasks()
      const durable = session.snapshotEvents()
      expect(durable.map((event: any) => event.type)).toEqual(['tool/result', 'sealed/redacted'])
      expect(durable[0].data.message.content[0].text).toBe(placeholder)
      expect(durable[0].data.message.content[0].text).not.toBe(BODY)
      const derivedTool = session.deriveMessages().find((message: any) => message.id === 'tool-1')
      expect(derivedTool.content[0].text).toBe(BODY)

      // /name path: a skill-invocation user/message carrying the same placeholder.
      session.append(
        'user/message',
        {
          id: 'user-1',
          role: 'user',
          source: { kind: 'skill-invocation', name: 'translate', form: 'instructions' },
          content: [{ type: 'text', text: placeholder }],
        },
        { surfaceOp: 'append' },
      )
      await flushMicrotasks()
      expect(session.snapshotEvents().map((event: any) => event.type)).toEqual([
        'tool/result', 'sealed/redacted', 'user/message', 'sealed/redacted',
      ])
      const derivedUser = session.deriveMessages().find((message: any) => message.id === 'user-1')
      expect(derivedUser.content[0].text).toBe(BODY)
    } finally {
      await ctx.fiber.dispose()
    }
  })
})
