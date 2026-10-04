import { existsSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { describe, expect, it } from 'vitest'
import { createSealedPlaintextInvariant, SEALED_PACKAGE_NAME } from '../src/invariant.js'

/**
 * Gated REAL-machine proof of the Task 6 sentinel semantics on `@deepseek-ai/dsh@0.2.0-rc.2`.
 *
 * Uses the lab's genuine `dsh-invariants` + `dsh-session` (never added to the repo dependency
 * graph). Without SEALED_DSH_LAB=1 (or without an installed lab) this file skips loudly — a missing
 * lab is UNVERIFIED, never a pass.
 *
 * It pins the CORRECTED semantics the review probe found: the real `fail` throws `InvariantError`,
 * but `dsh-session` runs `session/event` listeners inside `invokeContainedSessionObservers`
 * (`dsh-session/lib/index.js:1228`), which catches the throw and only calls `ctx.logger.warn(...)`.
 * Therefore `append()` does not throw, the registration is NOT torn down (re-register still throws
 * "already registered"), the sentinel stays armed, and the only observable signal is the warn line —
 * which must never contain the offending body, even when it was smuggled into `event.type`.
 */
const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..', '..')
const LAB_NODE_MODULES = join(REPO_ROOT, '.dsh-lab', 'node_modules')
const DSH_BIN = join(LAB_NODE_MODULES, '@deepseek-ai', 'dsh', 'lib', 'bin.js')
const CORDIS_ENTRY = join(LAB_NODE_MODULES, '@deepseek-ai', 'cordis', 'lib', 'index.js')
const INVARIANTS_ENTRY = join(LAB_NODE_MODULES, '@deepseek-ai', 'dsh-invariants', 'lib', 'index.js')
const SESSION_ENTRY = join(LAB_NODE_MODULES, '@deepseek-ai', 'dsh-session', 'lib', 'index.js')

const requested = process.env.SEALED_DSH_LAB === '1'
const installed = existsSync(DSH_BIN) && existsSync(INVARIANTS_ENTRY) && existsSync(SESSION_ENTRY)
const enabled = requested && installed
const skipReason = requested
  ? `the dsh lab is not installed at ${join(REPO_ROOT, '.dsh-lab')} (run: node scripts/dsh-lab.mjs --ensure)`
  : 'SEALED_DSH_LAB is not set to 1 (the dsh lab is opt-in)'

const CANARY = 'CANARY-canary-body-do-not-log-me-1234567890'
const SHAPED_CANARY = 'canary-body-do-not-log-me-1234567890'

const flush = () => new Promise<void>((resolve) => setTimeout(resolve, 25))

describe('sealed-plaintext invariant on the real dsh runtime (out-of-tree lab)', () => {
  if (!enabled) {
    console.warn(`[dsh-invariant] SKIPPED — ${skipReason}`)
    it.skip(`skips because ${skipReason}`, () => {})
    return
  }

  it('swallows the InvariantError into a warn, keeps the sentinel armed, and never logs the canary', async () => {
    const { Context } = await import(pathToFileURL(CORDIS_ENTRY).href)
    const { default: InvariantRegistry } = await import(pathToFileURL(INVARIANTS_ENTRY).href)
    const { SessionStore } = await import(pathToFileURL(SESSION_ENTRY).href)

    const ctx = new Context()
    const warns: string[] = []
    const originalWarn = ctx.logger.warn.bind(ctx.logger)
    ctx.logger.warn = (message: unknown) => {
      warns.push(String(message))
      originalWarn(String(message))
    }

    const registry = new InvariantRegistry(ctx)
    const store = new SessionStore(ctx)

    const installer = createSealedPlaintextInvariant({ isPlaintext: (text) => CANARY.includes(text) })
    const dispose = registry.register(SEALED_PACKAGE_NAME, installer)
    await flush()

    const session = store.create('invariant-lab')
    // (a) a canary in data; (b) a canary smuggled into the event type.
    expect(() => session.append('sealed/probe', { note: CANARY })).not.toThrow()
    expect(() => session.append(CANARY, {})).not.toThrow()
    expect(() => session.append(SHAPED_CANARY, {})).not.toThrow()
    await flush()

    // The sentinel fired for every leak...
    expect(warns.length).toBeGreaterThanOrEqual(3)
    // ...but the observable warn lines carry no body text, even the ones forged into `type`.
    for (const line of warns) {
      expect(line).not.toContain(CANARY)
      expect(line).not.toContain(SHAPED_CANARY)
    }

    // dsh-session swallowed the throw: the registration was NOT torn down.
    expect(() => registry.register(SEALED_PACKAGE_NAME, installer)).toThrow(/already registered/)

    // Still armed: a further leak still fires.
    const before = warns.length
    session.append('sealed/probe', { note: CANARY })
    await flush()
    expect(warns.length).toBeGreaterThan(before)

    dispose()
  })
})
