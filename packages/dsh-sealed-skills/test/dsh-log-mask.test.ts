import { existsSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { describe, expect, it } from 'vitest'
import { placeholderFor, renderPlaceholder, SEALED_REDACTED, SEALED_REDACTED_ALG, sealedRedactedData } from '../src/session-events.js'
import { createLogMaskProjection } from '../src/log-mask.js'

/**
 * Gated REAL-machine proof of the log-mask on `@deepseek-ai/dsh-session@0.2.0-rc.2`.
 *
 * Uses the lab's genuine session + persistence packages (never added to the repo dependency graph).
 * Without SEALED_DSH_LAB=1 (or without an installed lab) this file skips loudly — a missing lab is
 * UNVERIFIED, never a pass.
 *
 * The two assertions that matter:
 *  1. The durable log keeps ONLY the unguessable placeholder while `deriveMessages()` returns the
 *     plaintext for the same `message.id` (both landing paths: `tool/result` and `user/message`).
 *  2. `validateStoredEvents` REFUSES the log before and ADMITS it after the runtime
 *     `KNOWN_SESSION_EVENT_TYPES.add('sealed/redacted')` — the Task 5 Ruling.
 */
const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..', '..')
const LAB_NODE_MODULES = join(REPO_ROOT, '.dsh-lab', 'node_modules')
const DSH_BIN = join(LAB_NODE_MODULES, '@deepseek-ai', 'dsh', 'lib', 'bin.js')
const SESSION_ENTRY = join(LAB_NODE_MODULES, '@deepseek-ai', 'dsh-session', 'lib', 'index.js')
const PERSISTENCE_ENTRY = join(LAB_NODE_MODULES, '@deepseek-ai', 'dsh-session-persistence', 'lib', 'index.js')

const requested = process.env.SEALED_DSH_LAB === '1'
const installed = existsSync(DSH_BIN) && existsSync(SESSION_ENTRY) && existsSync(PERSISTENCE_ENTRY)
const enabled = requested && installed
const skipReason = requested
  ? `the dsh lab is not installed at ${join(REPO_ROOT, '.dsh-lab')} (run: node scripts/dsh-lab.mjs --ensure)`
  : 'SEALED_DSH_LAB is not set to 1 (the dsh lab is opt-in)'

const PLAINTEXT = '把用户输入翻译成英文。\n'
const ENTRY = 'skill:translate:body'

function plaintextReveal(entryId: string, alg: string): string | undefined {
  return entryId === ENTRY && alg === SEALED_REDACTED_ALG ? PLAINTEXT : undefined
}

describe('log-mask on the real dsh session (out-of-tree lab)', () => {
  if (!enabled) {
    // Loud, explicit skip: a missing lab is UNVERIFIED, never a pass.
    console.warn(`[dsh-log-mask] SKIPPED — ${skipReason}`)
    it.skip(`skips because ${skipReason}`, () => {})
    return
  }

  it('keeps the durable tool/result on the placeholder while deriveMessages() shows plaintext', async () => {
    const { Session } = await import(pathToFileURL(SESSION_ENTRY).href)
    const { token } = renderPlaceholder(ENTRY)
    const placeholder = placeholderFor(token)
    const projection = createLogMaskProjection({ reveal: plaintextReveal })
    const session = Session.create('t-tool', undefined, undefined, undefined, [projection])

    const seq = session.append(
      'tool/result',
      { turn: 0, step: 0, message: { id: 'm1', role: 'tool', content: [{ type: 'text', text: placeholder }] } },
      { surfaceOp: 'append' },
    ).seq
    session.append(SEALED_REDACTED, sealedRedactedData(seq, ENTRY, token))

    const durable = session.snapshotEvents()
    expect(durable.map((event: any) => event.type)).toEqual(['tool/result', SEALED_REDACTED])
    const durableText = JSON.stringify(durable[0])
    expect(durableText).toContain(token)
    expect(durableText).not.toContain(PLAINTEXT)

    const derived = session.deriveMessages()
    const message = derived.find((item: any) => item.id === 'm1')
    expect(message).toBeDefined()
    expect(message.content[0].text).toBe(PLAINTEXT)
  })

  it('keeps the durable /name user/message on the placeholder while deriveMessages() shows plaintext', async () => {
    const { Session } = await import(pathToFileURL(SESSION_ENTRY).href)
    const { token } = renderPlaceholder(ENTRY)
    const placeholder = placeholderFor(token)
    const projection = createLogMaskProjection({ reveal: plaintextReveal })
    const session = Session.create('t-user', undefined, undefined, undefined, [projection])

    const seq = session.append(
      'user/message',
      {
        id: 'u1',
        role: 'user',
        source: { kind: 'skill-invocation', name: 'translate', form: 'instructions' },
        content: [{ type: 'text', text: placeholder }],
      },
      { surfaceOp: 'append' },
    ).seq
    session.append(SEALED_REDACTED, sealedRedactedData(seq, ENTRY, token))

    const durable = session.snapshotEvents()
    expect(durable.map((event: any) => event.type)).toEqual(['user/message', SEALED_REDACTED])
    expect(JSON.stringify(durable[0])).not.toContain(PLAINTEXT)

    const derived = session.deriveMessages()
    const message = derived.find((item: any) => item.id === 'u1')
    expect(message.content[0].text).toBe(PLAINTEXT)
  })

  it('refuses the stored log before, and admits it after, runtime type registration', async () => {
    const sessionModule = await import(pathToFileURL(SESSION_ENTRY).href)
    const { validateStoredEvents } = await import(pathToFileURL(PERSISTENCE_ENTRY).href)
    const known = sessionModule.KNOWN_SESSION_EVENT_TYPES
    const meta = { id: 't-persist', version: sessionModule.SESSION_FORMAT_VERSION }
    const events = [{ type: SEALED_REDACTED, seq: 0, time: Date.now(), data: sealedRedactedData(0, ENTRY, 'token') }]

    known.delete(SEALED_REDACTED)
    expect(known.has(SEALED_REDACTED)).toBe(false)
    expect(() => validateStoredEvents(meta, structuredClone(events))).toThrow(/unknown to this harness/)

    known.add(SEALED_REDACTED)
    expect(() => validateStoredEvents(meta, structuredClone(events))).not.toThrow()
  })
})
