import { describe, expect, it } from 'vitest'
import {
  assertLosslessEventData,
  createPlaceholderRegistry,
  parsePlaceholder,
  placeholderFor,
  renderPlaceholder,
  sealedRedactedData,
  SealedEventError,
  SEALED_REDACTED,
  SEALED_REDACTED_ALG,
} from '../src/session-events.js'
import {
  assertLogMaskReady,
  createLogMaskProjection,
  createPlaintextReveal,
  createSealedMarkerObserver,
  LogMaskNotReadyError,
  registerLogMaskProjection,
  type SealedMessage,
  type SealedMessageProjection,
  type SealedProjectionContext,
  type SealedSeq,
  type SealedSessionEventLike,
  type SealedSessionsSurface,
} from '../src/log-mask.js'
import {
  createCachingContentFor,
  createDshSkillProvider,
  createPlaceholderContentFor,
  skillBodyEntryId,
} from '../src/provider.js'
import type { SkillDefinition, SkillSummary } from '../src/core.js'

const PLAINTEXT = 'the quick brown fox jumps over the lazy dog'
const ENTRY = 'skill:translate:body'

function textMessage(id: string, text: string): SealedMessage {
  return { id, content: [{ type: 'text', text }] }
}

type LandingType = 'tool/result' | 'user/message'

function sourceEvent(seq: number, message: SealedMessage, type: LandingType = 'tool/result'): unknown {
  return type === 'user/message' ? { type, seq, data: message } : { type, seq, data: { message } }
}

/**
 * The REAL `SessionMessageProjectionContext` shape: an unprojected target lives in `events`
 * (`events[refSeq - baseSeq]`), and `messages` holds only PRIOR projection outputs. Task 4's
 * original tests wrongly placed the target in `messages`; dsh's own `image/offload` projection
 * reads the durable event window (`dsh-compaction-image-offload/lib/index.js:116`).
 */
function contextOf(
  entries: readonly [SealedSeq, SealedMessage, LandingType?][],
  opts: { projected?: readonly [SealedSeq, SealedMessage][]; baseSeq?: number; nodes?: readonly SealedSeq[] } = {},
): SealedProjectionContext {
  const baseSeq = opts.baseSeq ?? 0
  const events: unknown[] = []
  for (const [seq, message, type] of entries) events[seq - baseSeq] = sourceEvent(seq, message, type)
  return {
    nodes: opts.nodes ?? entries.map(([seq]) => seq),
    events,
    baseSeq,
    messages: new Map(opts.projected ?? []),
  }
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
  it('rewrites the referenced seq from context.events (the real shape), preserving id and inputs', () => {
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

  it('rewrites the /name user/message landing path from context.events', () => {
    const { token, text } = renderPlaceholder(ENTRY)
    const context = contextOf([[3, textMessage('user-1', text), 'user/message']])
    const updates = createLogMaskProjection({ reveal: () => PLAINTEXT }).project(marker(3, token), context)
    expect(updates.get(3)?.id).toBe('user-1')
    expect(updates.get(3)?.content[0]?.text).toBe(PLAINTEXT)
  })

  it('prefers an earlier projected message over the durable source (image/offload parity)', () => {
    const { token, text } = renderPlaceholder(ENTRY)
    const projectedTarget = textMessage('msg-1', 'projected ' + text)
    const context = contextOf([[7, textMessage('msg-1', text)]], { projected: [[7, projectedTarget]] })
    const updates = createLogMaskProjection({ reveal: () => PLAINTEXT }).project(marker(7, token), context)
    expect(updates.get(7)?.content[0]?.text).toBe('projected ' + PLAINTEXT)
  })

  it('rewrites only the referenced seq and leaves other messages untouched', () => {
    const { token, text } = renderPlaceholder(ENTRY)
    const target = textMessage('msg-1', text)
    const other = textMessage('msg-9', 'unrelated body')
    const context = contextOf([[7, target], [9, other]])
    const updates = createLogMaskProjection({ reveal: () => PLAINTEXT }).project(marker(7, token), context)
    expect([...updates.keys()]).toEqual([7])
    expect(updates.has(9)).toBe(false)
    expect(other.content[0]?.text).toBe('unrelated body')
  })

  it('honors a nonzero baseSeq (fork / restore window)', () => {
    const { token, text } = renderPlaceholder(ENTRY)
    const context = contextOf([[12, textMessage('m', text)]], { baseSeq: 5 })
    const updates = createLogMaskProjection({ reveal: () => PLAINTEXT }).project(marker(12, token), context)
    expect(updates.get(12)?.content[0]?.text).toBe(PLAINTEXT)
  })

  it('fails closed on a non-current seq, wrong source type, token mismatch, or unavailable reveal', () => {
    const { token, text } = renderPlaceholder(ENTRY)
    const target = textMessage('m', text)
    const usable = createLogMaskProjection({ reveal: () => PLAINTEXT })

    // The referenced seq is no longer a current surface node.
    expect(usable.project(marker(7, token), contextOf([[7, target]], { nodes: [] })).size).toBe(0)
    // The source event is neither user/message nor tool/result.
    const wrongType: SealedProjectionContext = {
      nodes: [7],
      events: [{ type: 'assistant/message', data: { message: target } }],
      baseSeq: 0,
      messages: new Map(),
    }
    expect(usable.project(marker(7, token), wrongType).size).toBe(0)
    // The seq falls outside the provided event window.
    expect(usable.project(marker(99, token), contextOf([[7, target]])).size).toBe(0)
    // The marker token is not actually present in the target body.
    expect(usable.project(marker(7, 'a-different-token'), contextOf([[7, target]])).size).toBe(0)
    // Reveal is unavailable / missing / throws.
    expect(createLogMaskProjection({ reveal: () => undefined }).project(marker(7, token), contextOf([[7, target]])).size).toBe(0)
    expect(createLogMaskProjection({} as never).project(marker(7, token), contextOf([[7, target]])).size).toBe(0)
    expect(
      createLogMaskProjection({ reveal: () => { throw new Error('not authorized') } }).project(marker(7, token), contextOf([[7, target]])).size,
    ).toBe(0)

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

describe('createSealedMarkerObserver', () => {
  function registered() {
    const registry = createPlaceholderRegistry()
    const { token } = renderPlaceholder(ENTRY)
    registry.record(token, { entryId: ENTRY, alg: SEALED_REDACTED_ALG })
    return { registry, token }
  }

  function toolResultEvent(seq: number, text: string): SealedSessionEventLike {
    return { type: 'tool/result', seq, data: { turn: 0, step: 0, message: { id: 'm' + seq, role: 'tool', content: [{ type: 'text', text }] } } }
  }

  function skillUserEvent(seq: number, text: string): SealedSessionEventLike {
    return {
      type: 'user/message',
      seq,
      data: {
        id: 'u' + seq,
        role: 'user',
        source: { kind: 'skill-invocation', name: 'translate', form: 'instructions' },
        content: [{ type: 'text', text }],
      },
    }
  }

  function plainUserEvent(seq: number, text: string): SealedSessionEventLike {
    return { type: 'user/message', seq, data: { id: 'p' + seq, role: 'user', content: [{ type: 'text', text }] } }
  }

  function fakeSession() {
    const appended: { type: string; data: unknown }[] = []
    const session = {
      publishing: false,
      appended,
      append(type: string, data: unknown) {
        if (session.publishing) throw new Error('session append cannot reenter while another append is being published')
        appended.push({ type, data })
        return { type, seq: appended.length - 1, data }
      },
    }
    return session
  }

  it('defers the marker past the publish boundary for a committed tool/result placeholder', async () => {
    const { registry, token } = registered()
    const session = fakeSession()
    const observer = createSealedMarkerObserver({ registry })

    session.publishing = true // dsh invokes session/event listeners inside this boundary
    expect(() => observer.onSessionEvent(session, toolResultEvent(7, placeholderFor(token)))).not.toThrow()
    expect(observer.pending).toBe(1)
    // The hazard the deferral avoids: a synchronous append inside the boundary is rejected.
    expect(() => session.append(SEALED_REDACTED, {})).toThrow(/reenter/)
    session.publishing = false // dsh clears `appending` in the append's finally, before microtasks run
    await Promise.resolve()

    expect(session.appended).toHaveLength(1)
    expect(session.appended[0]?.type).toBe(SEALED_REDACTED)
    expect(session.appended[0]?.data).toEqual({ refSeq: 7, entryId: ENTRY, token, alg: SEALED_REDACTED_ALG })
    expect(observer.pending).toBe(0)
  })

  it('appends for the /name user/message path only with a skill-invocation source', async () => {
    const { registry, token } = registered()
    const session = fakeSession()
    const observer = createSealedMarkerObserver({ registry })

    observer.onSessionEvent(session, skillUserEvent(4, placeholderFor(token)))
    observer.onSessionEvent(session, plainUserEvent(9, placeholderFor(token)))
    await Promise.resolve()

    expect(session.appended).toHaveLength(1)
    expect((session.appended[0]?.data as { refSeq: number }).refSeq).toBe(4)
  })

  it('ignores other event types, unknown tokens, and token-free bodies', async () => {
    const { registry, token } = registered()
    const session = fakeSession()
    const observer = createSealedMarkerObserver({ registry })

    observer.onSessionEvent(session, { type: 'assistant/message', seq: 1, data: { message: { content: [{ type: 'text', text: placeholderFor(token) }] } } })
    observer.onSessionEvent(session, toolResultEvent(2, 'ordinary skill body'))
    observer.onSessionEvent(session, toolResultEvent(3, placeholderFor('unknown-token')))
    await Promise.resolve()

    expect(session.appended).toHaveLength(0)
  })

  it('appends each (refSeq, token) at most once', async () => {
    const { registry, token } = registered()
    const session = fakeSession()
    const observer = createSealedMarkerObserver({ registry })
    const event = toolResultEvent(7, placeholderFor(token))

    observer.onSessionEvent(session, event)
    observer.onSessionEvent(session, event)
    await Promise.resolve()

    expect(session.appended).toHaveLength(1)
  })

  it('is fail-safe when the deferred append throws', () => {
    const { registry, token } = registered()
    const session = fakeSession()
    const observer = createSealedMarkerObserver({
      registry,
      defer: (task) => task(),
      append: () => { throw new Error('append refused') },
    })

    session.publishing = true
    expect(() => observer.onSessionEvent(session, toolResultEvent(1, placeholderFor(token)))).not.toThrow()
    expect(session.appended).toHaveLength(0)
    expect(observer.pending).toBe(0)
  })
})

describe('plaintext reveal cache', () => {
  it('round-trips a body and zeroizes it on dispose', () => {
    const reveal = createPlaintextReveal()
    expect(reveal.reveal(ENTRY, SEALED_REDACTED_ALG)).toBeUndefined()
    reveal.save(ENTRY, PLAINTEXT)
    expect(reveal.reveal(ENTRY, SEALED_REDACTED_ALG)).toBe(PLAINTEXT)
    reveal.dispose()
    expect(reveal.reveal(ENTRY, SEALED_REDACTED_ALG)).toBeUndefined()
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

  it('caches the plaintext for reveal while returning only the placeholder', async () => {
    const registry = createPlaceholderRegistry()
    const reveal = createPlaintextReveal()
    const provider = createDshSkillProvider(core, { contentFor: createCachingContentFor(registry, reveal) })
    const candidates = await provider.list({})
    const loaded = await provider.get(candidates[0] as never, {})
    const tokens = parsePlaceholder(loaded?.content ?? '')
    expect(tokens).toHaveLength(1)
    expect(loaded?.content).not.toContain('real body')
    expect(reveal.reveal(skillBodyEntryId('a'), SEALED_REDACTED_ALG)).toBe('real body')
    reveal.dispose()
    expect(reveal.reveal(skillBodyEntryId('a'), SEALED_REDACTED_ALG)).toBeUndefined()
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
