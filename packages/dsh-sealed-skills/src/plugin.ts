import { readFileSync } from 'node:fs'
import { createPublicKey } from 'node:crypto'
import { join } from 'node:path'
import { pathToFileURL } from 'node:url'
import { readContainer } from '@sealed/pack-format'
import { SealedCore } from './core.js'
import { FileKeystore } from './keystore.js'
import { LicenseClient, LicenseDenied, type Entitlement } from './license-client.js'
import {
  createCachingContentFor,
  createDshSkillProvider,
  skillBodyEntryId,
  type DshSkillProvider,
  type DshSkillProviderControl,
} from './provider.js'
import { createPlaceholderRegistry, SEALED_REDACTED, SEALED_REDACTED_ALG } from './session-events.js'
import {
  assertLogMaskReady,
  createLogMaskProjection,
  createPlaintextReveal,
  createSealedMarkerObserver,
  LogMaskNotReadyError,
  type SealedMessageProjection,
  type SealedSessionEventLike,
  type SealedSessionLike,
} from './log-mask.js'
import {
  createSealedPlaintextInvariant,
  installSealedInvariant,
  type InvariantInstaller,
  type InvariantRegistry,
} from './invariant.js'

/**
 * dsh entrypoint for the `dsh-sealed-skills` bundle.
 *
 * VERIFICATION: the `SkillProvider` / `SkillProviderControl` /
 * `ctx.skills.registerProvider()` shapes this file targets were verified against the
 * published `@deepseek-ai/dsh-skill@0.2.0-rc.2` type declarations (see provider.ts for
 * the exact file + line map; the cordis service name is still `skills`, and the class was
 * renamed `SkillService` -> `SkillRegistry`). The package declares the matching dsh peer
 * dependencies (optional, so it still builds/tests without dsh), ships a `dsh.bundle` patch
 * (`cordis.patch.yml`), and was exercised inside a real `@deepseek-ai/dsh@0.2.0-rc.2` profile by
 * `test/dsh-integration.test.ts` (M3 Task 3): the profile loader resolves this bundle with no
 * skipped bundle, `apply()` registers through the real `SkillRegistry`, and a licensed pack
 * decrypts. The full shipped headless profile is still unverified (it needs model credentials) —
 * see `docs/sealed-skills/notes/dsh-skill-provider.md` section 6.
 */

/**
 * One installed pack.
 *
 * Provide `licensePath` for an offline, pre-issued license, or `purchaseToken` / `trial`
 * for online activation against the license server. The pack author key is never supplied
 * here: it is read from the signed license (`pack.author_pub`).
 */
export interface SealedPackMount {
  /** Absolute path to a `.sealedpack` container. */
  readonly packPath: string
  /** Absolute path to a signed license binding this pack to this device (offline import). */
  readonly licensePath?: string
  /** Purchase token used to activate online when no cached/offline license exists. */
  readonly purchaseToken?: string
  /** Request a server-issued trial when no cached/offline license exists. */
  readonly trial?: boolean
}

export interface SealedSkillsConfig {
  /** Packs to expose. Each mount is licensed lazily on first use. */
  readonly mounts?: SealedPackMount[]
  /** base64url raw Ed25519 public keys trusted to sign licenses (the license server keys). */
  readonly trustedLicenseKeysB64?: string[]
  /** License server base URL; falls back to `SEALED_SERVER_URL`. */
  readonly serverUrl?: string
  /** base64url raw X25519 public key used for device-proof on renew; falls back to `SEALED_SERVER_PROOF_PUB`. */
  readonly serverProofPubB64?: string
  /** Directory for the file-backed device keystore. Defaults to `$SEALED_HOME` or `<cwd>/.sealed-home`. */
  readonly keystoreDir?: string
  /** Candidate precedence rank. Defaults to 600, the published `BUNDLED_SKILL_RANK`. */
  readonly rank?: number
  /** Injectable clock (ms since epoch) used for cache refresh timing; defaults to `Date.now`. */
  readonly now?: () => number
  /**
   * Test/lab seam: register the marker event type with the running harness's authoritative
   * catalog. Defaults to dynamically importing `@deepseek-ai/dsh-session` and adding
   * `sealed/redacted` to its exported `KNOWN_SESSION_EVENT_TYPES` set — the Task 5 Ruling: dsh
   * 0.2.x offers no append-with-ignorable, so runtime registration is the only way a harness WITH
   * this plugin can reopen a session log.
   */
  readonly registerSessionEventType?: (type: string) => void | Promise<void>
  /**
   * Absolute path or `file:` URL to the installed `@deepseek-ai/dsh-session` entry. The bare
   * specifier default resolves when this package sits beside dsh in one node_modules tree; the
   * out-of-tree lab junctions this package, so its tests pass the resolved path. Falls back to
   * `SEALED_DSH_SESSION_MODULE`.
   */
  readonly dshSessionModule?: string
}

/** The only part of the dsh context surface this plugin depends on. */
export interface SkillsContext {
  readonly skills: {
    registerProvider(create: (control: DshSkillProviderControl) => DshSkillProvider): () => void
  }
  /** Log-mask seam (Task 5). Optional so M1/M2-style fake contexts still typecheck. */
  readonly sessions?: {
    registerMessageProjection(projection: SealedMessageProjection): () => Promise<void>
  }
  /** Committed-event observer seam; cordis `ctx.on`. */
  readonly on?: (
    name: 'session/event',
    listener: (session: SealedSessionLike, event: SealedSessionEventLike) => void,
  ) => () => void
  /**
   * Runtime-invariant seam (Task 6). Optional: when absent the sealed-plaintext sentinel is
   * skipped with a redacted warning — it must NEVER gate the skill provider (unlike the log-mask).
   */
  readonly invariants?: InvariantRegistry
  /**
   * cordis effect scope. When present the sentinel registration is owned by the plugin fiber
   * (disposed with it); when absent `apply` keeps the disposer and tears it down itself.
   */
  readonly effect?: (callback: () => (() => void) | void, label?: string) => (() => void) | void
  /** Optional redacted-failure sink; falls back to `console.warn`. */
  readonly logger?: { warn(message: string): void }
}

export const name = 'sealed-skills'
// `invariants` is deliberately NOT a required inject: cordis aborts/deferrs a plugin whose required
// service is missing, which would stop the provider from serving in profiles that ship without
// `@deepseek-ai/dsh-invariants`. The sentinel is defense-in-depth, so we read `ctx.invariants`
// opportunistically AFTER the log-mask is ready (the service is visible to this fiber when present,
// `undefined` when absent) and degrade to a redacted warning + no-op disposer.
export const inject = ['skills', 'sessions']

/**
 * Register the sealed provider on `ctx.skills` during plugin apply and return the dsh
 * effect disposer so the loader can order teardown.
 *
 * Cores are built lazily on first use (online activation or offline import) and cached per
 * pack path. The cache is refreshed lazily on access once every 24h, which re-runs license
 * acquisition (renewal when due, or a fresh offline import) — so a long-running process keeps
 * a paid license alive and observes revocation at the next refresh, not instantly. A mount
 * whose pack is missing/corrupt, whose license cannot be obtained or imported, or that is
 * bound to another device is skipped (fail-closed per mount): neither core construction nor
 * `list()` rejects, and the provider reports only the healthy packs.
 */
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

  const nowMs = config.now ?? Date.now
  const REFRESH_INTERVAL_MS = 24 * 60 * 60 * 1000
  const cores = new Map<string, Promise<SealedCore>>()
  const refreshedAt = new Map<string, number>()
  const coreFor = (mount: SealedPackMount): Promise<SealedCore> => {
    const last = refreshedAt.get(mount.packPath)
    if (last !== undefined && nowMs() - last >= REFRESH_INTERVAL_MS) {
      // 刷新窗口已到：丢弃缓存并在本次访问时重建，重跑 ensureLicense（续期 / 重新导入离线
      // license）。刻意用惰性检查而非定时器，避免插件存活期间后台常驻定时器。
      cores.delete(mount.packPath)
      refreshedAt.delete(mount.packPath)
    }
    let pending = cores.get(mount.packPath)
    if (!pending) {
      // Cache the in-flight promise so concurrent callers share one activation, and drop it on
      // failure so a later call can retry (e.g. after the network or a license file is fixed).
      pending = buildCore(mount).then((core) => {
        refreshedAt.set(mount.packPath, nowMs())
        return core
      }).catch((error: unknown) => {
        cores.delete(mount.packPath)
        refreshedAt.delete(mount.packPath)
        throw error
      })
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

  // Aggregate the mounted packs behind the single `Pick<SealedCore, 'list' | 'readSkill'>` seam.
  const aggregate = {
    async list() {
      const summaries = []
      for (const mount of mounts) {
        try {
          summaries.push(...await (await coreFor(mount)).list())
        } catch {
          // Fail closed for THIS mount only: a missing/corrupt pack, an unobtainable license or an
          // unavailable keystore must never take down list() for the healthy mounts.
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

  // --- Log-mask wiring (Task 5) ---------------------------------------------------------------
  // The provider serves ONLY placeholders; the durable log holds placeholders plus a marker; the
  // registered projection rewrites the derived view back to plaintext. `apply` must register the
  // provider synchronously (the loader and existing tests depend on it), so readiness is enforced
  // by a gate in front of every list()/get(): until the projection, event-type registration and
  // session/event subscription are all in place, the provider REFUSES to serve (fail-closed).
  const registry = createPlaceholderRegistry()
  const plaintext = createPlaintextReveal()
  const projection = createLogMaskProjection({ reveal: plaintext.reveal })
  const contentFor = createCachingContentFor(registry, plaintext, { alg: SEALED_REDACTED_ALG })
  const observer = createSealedMarkerObserver({ registry })

  let disposeProjection: (() => Promise<void>) | undefined
  let disposeListener: (() => void) | undefined
  let ready = false
  let disposeInvariant: (() => void) | undefined

  const warn = (message: string): void => {
    if (ctx.logger !== undefined && typeof ctx.logger.warn === 'function') ctx.logger.warn(message)
    else console.warn(message)
  }

  // Task 6 sentinel: registered only AFTER the log-mask is ready, and never allowed to affect the
  // gate. `isPlaintext` reads Task 5's cache in place (no second copy of any body). Absence of
  // `ctx.invariants`, a filtered registration, or an "already registered" reload all degrade to a
  // redacted warning / no-op disposer -- they must NOT stop the skill provider from serving.
  const registerSealedInvariantSentinel = (): void => {
    let installer: InvariantInstaller
    try {
      installer = createSealedPlaintextInvariant({ isPlaintext: (text) => plaintext.contains(text) })
    } catch {
      warn('[sealed-skills] the sealed-plaintext sentinel could not be constructed')
      return
    }
    const register = (): (() => void) => installSealedInvariant(ctx.invariants, installer, warn)
    const effect = ctx.effect
    if (typeof effect === 'function') {
      try {
        effect(register, 'sealed.invariant')
        return
      } catch {
        // Fall through: keep the disposer ourselves so a missing/broken effect cannot lose it.
      }
    }
    disposeInvariant = register()
  }

  const readiness: Promise<void> = (async () => {
    const registerType = config.registerSessionEventType
      ?? ((type: string) => registerDshSessionEventType(type, config.dshSessionModule))
    await registerType(SEALED_REDACTED)
    const sessions = ctx.sessions
    if (sessions === undefined || typeof sessions.registerMessageProjection !== 'function') {
      throw new LogMaskNotReadyError('the dsh sessions service is unavailable')
    }
    disposeProjection = sessions.registerMessageProjection(projection)
    const on = ctx.on
    if (typeof on !== 'function') {
      throw new LogMaskNotReadyError('the dsh context cannot observe session events')
    }
    disposeListener = on('session/event', (session, event) => observer.onSessionEvent(session, event))
    assertLogMaskReady({ projection, reveal: plaintext.reveal })
    ready = true
    try {
      registerSealedInvariantSentinel()
    } catch {
      // Defense-in-depth only: a sentinel wiring failure must never close the fail-closed gate.
    }
  })()

  // Never let a readiness failure surface as an unhandled rejection; make it visible (redacted).
  const settled = readiness.then(
    () => undefined,
    (error: unknown) => {
      const detail = error instanceof Error ? error.message : 'unknown error'
      const line = '[sealed-skills] log-mask is not ready; the skill provider will refuse to serve (' + detail + ')'
      if (ctx.logger !== undefined && typeof ctx.logger.warn === 'function') ctx.logger.warn(line)
      else console.warn(line)
    },
  )
  void settled

  const gatedCore = {
    async list() {
      await settled
      return ready ? aggregate.list() : []
    },
    async readSkill(skillName: string) {
      await settled
      if (!ready) throw new Error('sealed skill service is unavailable: the log-mask is not ready')
      return aggregate.readSkill(skillName)
    },
  }

  // Best-effort warm: populate the plaintext cache so a session restored after this plugin loads
  // can still derive plaintext. Never blocks startup; a failure is silent and leaks nothing.
  void settled.then(() => {
    if (!ready) return
    void (async () => {
      try {
        for (const summary of await aggregate.list()) {
          try {
            const definition = await aggregate.readSkill(summary.name)
            plaintext.save(skillBodyEntryId(definition.name), definition.content)
          } catch {
            // Per-skill best-effort.
          }
        }
      } catch {
        // Best-effort.
      }
    })()
  })

  // Synchronous registration; the gate above refuses service until the log-mask is ready.
  const disposeProvider = ctx.skills.registerProvider((control) =>
    createDshSkillProvider(gatedCore, { rank: config.rank, signal: control.signal, contentFor }))

  // The dsh contract returns the exact Cordis effect disposer; hand it back so the plugin loader
  // can order teardown (unregister provider -> abort signal -> listener/projection drop -> zeroize).
  return () => {
    try {
      disposeProvider()
    } catch {
      // Best-effort teardown.
    }
    try {
      disposeListener?.()
    } catch {
      // Best-effort teardown.
    }
    try {
      void disposeProjection?.()
    } catch {
      // Best-effort teardown.
    }
    try {
      disposeInvariant?.()
    } catch {
      // Best-effort teardown (only set when ctx.effect was unavailable).
    }
    plaintext.dispose()
    registry.clear()
  }
}

// --- Runtime event-type registration (the Task 5 Ruling) ----------------------------------------

const DSH_SESSION_SPECIFIER: string = '@deepseek-ai/dsh-session'
const DSH_SESSION_MODULE_ENV = 'SEALED_DSH_SESSION_MODULE'

async function loadDshSession(moduleRef: string | undefined): Promise<{ KNOWN_SESSION_EVENT_TYPES?: unknown }> {
  const explicit = moduleRef ?? process.env[DSH_SESSION_MODULE_ENV]
  if (typeof explicit === 'string' && explicit.length > 0) {
    const url = explicit.startsWith('file:') || explicit.startsWith('node:') || explicit.startsWith('data:')
      ? explicit
      : pathToFileURL(explicit).href
    return await import(/* @vite-ignore */ url)
  }
  return await import(/* @vite-ignore */ DSH_SESSION_SPECIFIER)
}

/**
 * Add `sealed/redacted` to the harness's own `KNOWN_SESSION_EVENT_TYPES`. Dynamic (never a static
 * import) so this package builds and tests with dsh absent; the specifier is a `string` variable
 * so tsc never tries to resolve the optional peer. Injectable via
 * `SealedSkillsConfig.registerSessionEventType` for tests.
 */
export async function registerDshSessionEventType(type: string, moduleRef?: string): Promise<void> {
  const mod = await loadDshSession(moduleRef)
  const known = mod.KNOWN_SESSION_EVENT_TYPES
  if (!(known instanceof Set)) {
    throw new LogMaskNotReadyError('@deepseek-ai/dsh-session does not export KNOWN_SESSION_EVENT_TYPES')
  }
  known.add(type)
}

export const plugin = { name, inject, apply }
export default plugin
