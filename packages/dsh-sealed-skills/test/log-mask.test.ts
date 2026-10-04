import { describe, expect, it } from 'vitest'
import {
  assertLosslessEventData,
  createPlaceholderRegistry,
  parsePlaceholder,
  renderPlaceholder,
  sealedRedactedData,
  SealedEventError,
  SEALED_REDACTED,
  SEALED_REDACTED_ALG,
} from '../src/session-events.js'
import {
  assertLogMaskReady,
  createLogMaskProjection,
  LogMaskNotReadyError,
  registerLogMaskProjection,
  type SealedMessage,
  type SealedMessageProjection,
  type SealedProjectionContext,
  type SealedSeq,
  type SealedSessionsSurface,
} from '../src/log-mask.js'
import { createDshSkillProvider, createPlaceholderContentFor, skillBodyEntryId } from '../src/provider.js'
import type { SkillDefinition, SkillSummary } from '../src/core.js'

const PLAINTEXT = 'the quick brown fox jumps over the lazy dog'
const ENTRY = 'skill:translate:body'

function textMessage(id: string, text: string): SealedMessage {
  return { id, content: [{ type: 'text', text }] }
}

function contextOf(entries: [SealedSeq, SealedMessage][]): SealedProjectionContext {
  return { nodes: entries.map(([seq]) => seq), events: [], messages: new Map(entries) }
}

function marker(refSeq: number, token: string, entryId: string = ENTRY) {
  return { type: SEALED_REDACTED, data: sealedRedactedData(refSeq, entryId, token), ignorable: true as const }
}

function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === 'object') {
    Object.freeze(value)
    for (const key of Object.keys(value as Record<string, unknown>)) {
      deepFreeze((value as Record<string, unknown>)[key])
    }
  }
  return value
}

describe('placeholder codec', () => {
  it('renders an unguessable base64url token and parses it back', () => {
    const a = renderPlaceholder(ENTRY)
    const b = renderPlaceholder(ENTRY)
    expect(a.token).toMatch(/^[A-Za-z0-9_-]{22}$/)
    expect(a.token).not.toBe(b.token)
    expect(parsePlaceholder(a.text)).toEqual([a.token])
  })

  it('extracts every occurrence, including the same token twice', () => {
    const a = renderPlaceholder(ENTRY)
    const b = renderPlaceholder(ENTRY)
    expect(parsePlaceholder(a.text + ' x ' + b.text + ' y ' + a.text)).toEqual([a.token, b.token, a.token])
    expect(parsePlaceholder('ordinary skill body')).toEqual([])
  })

  it('carries no plaintext and no entry id', () => {
    const { text } = renderPlaceholder('skill:translate:body')
    expect(text).not.toContain('translate')
    expect(text).not.toContain(PLAINTEXT)
  })
})

describe('sealed/redacted event data', () => {
  it('is lossless JSON and free of plaintext', () => {
    const data = sealedRedactedData(7, ENTRY, 'token', SEALED_REDACTED_ALG)
    expect(Object.keys(data).sort()).toEqual(['alg', 'entryId', 'refSeq', 'token'])
    expect(JSON.parse(JSON.stringify(data))).toEqual(data)
    expect(() => assertLosslessEventData(data)).not.toThrow()
    expect(JSON.stringify(data)).not.toContain(PLAINTEXT)
  })

  it('rejects non-lossless payloads the way session.append would', () => {
    expect(() => assertLosslessEventData({ a: 1n })).toThrow(SealedEventError)
    expect(() => assertLosslessEventData({ a: Number.NaN })).toThrow(SealedEventError)
    expect(() => assertLosslessEventData({ a: Number.POSITIVE_INFINITY })).toThrow(SealedEventError)
    expect(() => assertLosslessEventData({ a: -0 })).toThrow(SealedEventError)
    expect(() => assertLosslessEventData({ a: undefined })).toThrow(SealedEventError)
    expect(() => assertLosslessEventData({ a: new Map() })).toThrow(SealedEventError)
    const sparse: unknown[] = []
    sparse[2] = 1
    expect(() => assertLosslessEventData(sparse)).toThrow(SealedEventError)
    const cyclic: Record<string, unknown> = {}
    cyclic.self = cyclic
    expect(() => assertLosslessEventData(cyclic)).toThrow(SealedEventError)
  })
})

describe('createLogMaskProjection', () => {
  it('rewrites the referenced seq to plaintext, preserves the id, and never mutates the input', () => {
    const { token, text } = renderPlaceholder(ENTRY)
    const target = deepFreeze(textMessage('msg-1', 'prefix ' + text))
    const context = deepFreeze(contextOf([[7, target]]))
    const projection = createLogMaskProjection({ reveal: () => PLAINTEXT })

    const updates = projection.project(marker(7, token), context)
    expect(updates.size).toBe(1)
    const next = updates.get(7)
    expect(next).toBeDefined()
    expect(next?.id).toBe('msg-1')
    expect(next?.content[0]?.text).toBe('prefix ' + PLAINTEXT)
    expect(next).not.toBe(target)
    expect(next?.content).not.toBe(target.content)

    // The durable copy is untouched: still the placeholder, never the plaintext.
    expect(target.content[0]?.text).toBe('prefix ' + text)
    expect(parsePlaceholder(target.content[0]?.text ?? '')).toEqual([token])
    expect(target.content[0]?.text).not.toContain(PLAINTEXT)
  })

  it('rewrites only the referenced seq and leaves other messages alone', () => {
    const { token, text } = renderPlaceholder(ENTRY)
    const target = textMessage('msg-1', text)
    const other = textMessage('msg-2', 'unrelated body')
    const context = contextOf([[7, target], [9, other]])
    const projection = createLogMaskProjection({ reveal: () => PLAINTEXT })

    const updates = projection.project(marker(7, token), context)
    expect([...updates.keys()]).toEqual([7])
    expect(updates.has(9)).toBe(false)
    expect(other.content[0]?.text).toBe('unrelated body')
  })

  it('fails closed when the reveal source is unavailable, missing, or mismatched', () => {
    const { token, text } = renderPlaceholder(ENTRY)
    const target = textMessage('m', text)
    const context = contextOf([[7, target]])

    const unconfigured = createLogMaskProjection({} as never)
    expect(unconfigured.project(marker(7, token), context).size).toBe(0)

    const unavailable = createLogMaskProjection({ reveal: () => undefined })
    expect(unavailable.project(marker(7, token), context).size).toBe(0)

    const throwing = createLogMaskProjection({ reveal: () => { throw new Error('not authorized') } })
    expect(throwing.project(marker(7, token), context).size).toBe(0)

    const usable = createLogMaskProjection({ reveal: () => PLAINTEXT })
    expect(usable.project(marker(42, token), context).size).toBe(0)
    expect(usable.project(marker(7, 'a-different-token'), context).size).toBe(0)

    // Placeholder survives every fallback.
    expect(target.content[0]?.text).toBe(text)
  })

  it('renders plaintext when replaying the durable log after a restore', () => {
    const { token, text } = renderPlaceholder(ENTRY)
    const restored = contextOf([[3, textMessage('restored-3', text)]])
    const projection = createLogMaskProjection({
      reveal: (entryId, alg) => (entryId === ENTRY && alg === SEALED_REDACTED_ALG ? PLAINTEXT : undefined),
    })
    const updates = projection.project(marker(3, token), restored)
    expect(updates.get(3)?.content[0]?.text).toBe(PLAINTEXT)
  })

  it('is stable across repeated and concurrent markers for the same seq', () => {
    const { token, text } = renderPlaceholder(ENTRY)
    const target = textMessage('msg-1', text)
    const context = contextOf([[7, target]])
    const projection = createLogMaskProjection({ reveal: () => PLAINTEXT })

    const first = projection.project(marker(7, token), context)
    const second = projection.project(marker(7, token), context)
    expect(second).toEqual(first)
    expect(first.get(7)).not.toBe(second.get(7))
    expect(second.get(7)?.content[0]?.text).toBe(PLAINTEXT)
    expect(target.content[0]?.text).toBe(text)
  })
})

describe('provider placeholder hook', () => {
  const summary: SkillSummary = { name: 'a', description: 'd', invocation: { modelInvocable: true, userInvocable: true } }
  const definition: SkillDefinition = { ...summary, content: 'real body' }
  const core = { list: async () => [summary], readSkill: async () => definition }

  it('returns a recorded placeholder when a contentFor hook is injected', async () => {
    const registry = createPlaceholderRegistry()
    const provider = createDshSkillProvider(core, { contentFor: createPlaceholderContentFor(registry) })
    const candidates = await provider.list({})
    const loaded = await provider.get(candidates[0] as never, {})
    expect(loaded).toBeDefined()
    const tokens = parsePlaceholder(loaded?.content ?? '')
    expect(tokens).toHaveLength(1)
    expect(loaded?.content).not.toContain('real body')
    expect(registry.lookup(tokens[0] ?? '')).toEqual({ entryId: skillBodyEntryId('a'), alg: SEALED_REDACTED_ALG })
  })

  it('returns the real content by default (regression guard)', async () => {
    const provider = createDshSkillProvider(core)
    const candidates = await provider.list({})
    const loaded = await provider.get(candidates[0] as never, {})
    expect(loaded?.content).toBe('real body')
  })
})

describe('log-mask readiness and registration', () => {
  it('assertLogMaskReady throws a structured error until both parts are present', () => {
    const projection = createLogMaskProjection({ reveal: () => PLAINTEXT })
    const reveal = () => PLAINTEXT
    expect(() => assertLogMaskReady({ reveal })).toThrow(LogMaskNotReadyError)
    expect(() => assertLogMaskReady({ projection })).toThrow(LogMaskNotReadyError)
    const wrong: SealedMessageProjection = { type: 'other/event', project: () => new Map() }
    expect(() => assertLogMaskReady({ projection: wrong, reveal })).toThrow(LogMaskNotReadyError)
    expect(() => assertLogMaskReady({ projection, reveal })).not.toThrow()
  })

  it('registerLogMaskProjection forwards the projection and yields its disposer', async () => {
    let registered: SealedMessageProjection | undefined
    let disposed = 0
    const surface: SealedSessionsSurface = {
      registerMessageProjection: (projection) => {
        registered = projection
        return async () => { disposed += 1 }
      },
    }
    const projection = createLogMaskProjection({ reveal: () => PLAINTEXT })
    const dispose = registerLogMaskProjection(surface, projection)
    expect(registered).toBe(projection)
    await dispose()
    expect(disposed).toBe(1)
  })
})
