import {
  assertLosslessEventData,
  parsePlaceholder,
  placeholderFor,
  revealPlaceholder,
  sealedRedactedData,
  SEALED_REDACTED,
  type SealedPlaceholderRegistry,
  type SealedRedactedData,
} from './session-events.js'

// Structural mirror of the REAL dsh 0.2.x surface. Re-declared (never imported) so this package
// keeps no dependency on `@deepseek-ai/dsh*` and stays unit-testable in isolation; same style as
// `provider.ts`. Verified against `@deepseek-ai/dsh-session@0.2.0-rc.2`:
//   lib/types/surface.d.ts:13-37  SessionMessageProjectionContext / SessionMessageProjection
//   lib/types/index.d.ts:339-347  messageProjections / registerMessageProjection
// Doc contract (surface.d.ts:28-35): validate the COMPLETE durable decision before returning any
// updates; preserve message identities; publish immutable copies without mutating the input;
// @returns changed current messages keyed by their original sequences.
//   lib/index.js:422-470  a projecting event's own seq is NOT added to `nodes` (log-only); only
//   already-committed message seqs may be rewritten.
//   lib/types/index.d.ts:246 `append(...)`. `append` cannot set `ignorable`, so `sealed/redacted`
//   is registered into `KNOWN_SESSION_EVENT_TYPES` at apply time (section 9.7; see plugin.ts).

export type SealedSeq = number

export interface SealedContentBlock {
  readonly type: string
  readonly text?: string
}

export interface SealedMessage {
  readonly id: string
  readonly content: readonly SealedContentBlock[]
}

export interface SealedProjectionContext {
  /** Current message-producing seqs, in model order. A marker may only rewrite a CURRENT node. */
  readonly nodes: readonly SealedSeq[]
  /** Contiguous committed event window; `events[refSeq - baseSeq]` is the durable source event. */
  readonly events: readonly unknown[]
  /** Log offset of `events[0]` (0 for a created session, `inheritedEventCount` on a fork). */
  readonly baseSeq: number
  /** Previously projected messages by original seq (a projection's own prior rewrite target). */
  readonly messages: ReadonlyMap<SealedSeq, SealedMessage>
}

/**
 * The subset of the marker envelope a projection needs (the real event carries seq/time too).
 * No `ignorable`: dsh 0.2.x `append` cannot set it and the real snapshot omits it (section 9.7).
 */
export interface SealedRedactedEvent {
  readonly type: string
  readonly data: SealedRedactedData
}

/** The subset of a durable source event the projection reads (parity with dsh `image/offload`). */
interface SealedSourceEvent {
  readonly type?: unknown
  readonly data?: unknown
}

export interface SealedMessageProjection {
  readonly type: string
  project(event: SealedRedactedEvent, context: SealedProjectionContext): ReadonlyMap<SealedSeq, SealedMessage>
}

export interface SealedSessionsSurface {
  registerMessageProjection(projection: SealedMessageProjection): () => Promise<void>
}

export interface LogMaskDeps {
  /**
   * Resolve the plaintext for an entry. Implemented by Task 5 (core decryption, caching, restore
   * re-registration); the projection only consumes it. MUST return `undefined` when the key/grant is
   * unavailable — the projection then keeps the placeholder and emits no plaintext.
   */
  readonly reveal: (entryId: string, alg: string) => string | undefined
}

function empty(): ReadonlyMap<SealedSeq, SealedMessage> {
  return new Map<SealedSeq, SealedMessage>()
}

/**
 * The one projection this package registers for its own `sealed/redacted` event type.
 *
 * Fail-closed by construction: malformed marker data, a missing reveal source, a missing target
 * seq, a token that is not actually present in the target body, or a throwing reveal all yield an
 * EMPTY map (placeholder preserved, no plaintext, no throw). It never manufactures a surface node
 * and never mutates its inputs.
 */
export function createLogMaskProjection(deps: LogMaskDeps): SealedMessageProjection {
  return {
    type: SEALED_REDACTED,
    project(event, context) {
      try {
        return projectSealedRedacted(deps, event, context)
      } catch {
        return empty()
      }
    },
  }
}

function projectSealedRedacted(
  deps: LogMaskDeps,
  event: SealedRedactedEvent,
  context: SealedProjectionContext,
): ReadonlyMap<SealedSeq, SealedMessage> {
  const reveal = deps?.reveal
  if (typeof reveal !== 'function') return empty()
  if (event === null || typeof event !== 'object' || event.type !== SEALED_REDACTED) return empty()
  const data = event.data
  if (data === null || typeof data !== 'object') return empty()
  const { refSeq, entryId, token, alg } = data
  if (typeof refSeq !== 'number' || !Number.isInteger(refSeq) || refSeq < 0) return empty()
  if (typeof entryId !== 'string' || entryId.length === 0) return empty()
  if (typeof token !== 'string' || token.length === 0) return empty()
  if (typeof alg !== 'string' || alg.length === 0) return empty()

  // (1) The marker may only rewrite a CURRENT surface node (never a shadowed/unknown seq).
  const nodes = context?.nodes
  if (!Array.isArray(nodes) || !nodes.includes(refSeq)) return empty()
  // (2)+(3) Read the durable source exactly like dsh's own `image/offload` projection
  // (`dsh-compaction-image-offload/lib/index.js:116`): the target message is usually NOT in
  // `context.messages` (that map only holds prior projection outputs), so fall back to the
  // committed event window keyed by `refSeq - context.baseSeq`.
  const events = context?.events
  const baseSeq = context?.baseSeq
  if (!Array.isArray(events) || typeof baseSeq !== 'number' || !Number.isInteger(baseSeq) || baseSeq < 0) return empty()
  const source = events[refSeq - baseSeq] as SealedSourceEvent | undefined
  if (source === null || typeof source !== 'object') return empty()
  let baseMessage: SealedMessage | undefined
  if (source.type === 'user/message') baseMessage = source.data as SealedMessage | undefined
  else if (source.type === 'tool/result') baseMessage = (source.data as { message?: SealedMessage } | undefined)?.message
  else return empty()
  const projected = context.messages?.get?.(refSeq)
  const target = projected ?? baseMessage
  if (target === undefined || target === null) return empty()
  const blocks = target.content
  if (!Array.isArray(blocks)) return empty()

  // Only rewrite when the marker's token is ACTUALLY present in the target body (contract #4).
  const sentinel = placeholderFor(token)
  let matched = false
  for (const block of blocks) {
    if (block !== null && typeof block === 'object' && typeof block.text === 'string' && block.text.includes(sentinel)) {
      matched = true
      break
    }
  }
  if (!matched) return empty()

  // Reveal only after the match (no side effects for unrelated markers); undefined => keep the
  // placeholder (contract #3).
  const plaintext = reveal(entryId, alg)
  if (typeof plaintext !== 'string') return empty()

  const nextBlocks = blocks.map((block) => {
    if (block !== null && typeof block === 'object' && typeof block.text === 'string' && block.text.includes(sentinel)) {
      return Object.freeze({ ...block, text: revealPlaceholder(block.text, token, plaintext) })
    }
    return block
  })
  const nextMessage: SealedMessage = Object.freeze({
    ...target,
    id: target.id,
    content: Object.freeze(nextBlocks),
  })
  const updates = new Map<SealedSeq, SealedMessage>()
  updates.set(refSeq, nextMessage)
  return updates
}

/** Register the projection on the real sessions surface; returns its disposer unchanged. */
export function registerLogMaskProjection(
  sessions: SealedSessionsSurface,
  projection: SealedMessageProjection,
): () => Promise<void> {
  return sessions.registerMessageProjection(projection)
}

export class LogMaskNotReadyError extends Error {
  readonly code = 'LOG_MASK_NOT_READY'
  constructor(message: string) {
    super(message)
    this.name = 'LogMaskNotReadyError'
  }
}

export interface LogMaskReady {
  readonly projection: SealedMessageProjection
  readonly reveal: LogMaskDeps['reveal']
}

/**
 * Fail-closed readiness probe for Task 5: a usable log-mask needs BOTH a reveal source and a
 * projection registered for `sealed/redacted`. Throws a structured error (never a plaintext one)
 * otherwise, so callers can refuse to serve rather than degrade silently.
 */
export function assertLogMaskReady(candidate: {
  readonly projection?: SealedMessageProjection | undefined
  readonly reveal?: LogMaskDeps['reveal'] | undefined
}): asserts candidate is LogMaskReady {
  if (typeof candidate.reveal !== 'function') {
    throw new LogMaskNotReadyError('log-mask reveal is not configured')
  }
  const projection = candidate.projection
  if (projection === undefined || projection === null) {
    throw new LogMaskNotReadyError('log-mask projection is not registered')
  }
  if (projection.type !== SEALED_REDACTED) {
    throw new LogMaskNotReadyError('log-mask projection type is not ' + SEALED_REDACTED)
  }
}

// --- Landing-path marker observer -------------------------------------------------------------
//
// Both skill-content landing paths commit a message carrying our unguessable placeholder:
//   * `tool/result`  — the built-in skill tool's frozen result (`data.message.content`).
//   * `user/message` — the `/name` gesture injection (`data.source.kind === 'skill-invocation'`).
// After such an event commits, this observer appends the `sealed/redacted` marker so the
// registered projection can rewrite the earlier seq back to plaintext for the model.
//
// NON-REENTRANCY (dsh 0.2.x contract, `dsh-session/lib/index.js:1452`): a `session/event`
// observer runs INSIDE the append's publication boundary (`entry.appending === true`), so a
// synchronous `append` throws `session append cannot reenter while another append is being
// published`. We therefore only ever SCHEDULE the append (default `queueMicrotask`) and swallow
// any failure: a lost marker leaves the placeholder visible to the model — never a plaintext leak.

export interface SealedSessionLike {
  append(type: string, data: SealedRedactedData): unknown
}

export interface SealedSessionEventLike {
  readonly type?: unknown
  readonly seq?: unknown
  readonly data?: unknown
}

export interface SealedMarkerObserverDeps {
  readonly registry: SealedPlaceholderRegistry
  /** Schedule the append outside the current publication boundary; defaults to `queueMicrotask`. */
  readonly defer?: (task: () => void) => void
  /** Perform the append; defaults to `session.append(SEALED_REDACTED, data)`. */
  readonly append?: (session: SealedSessionLike, data: SealedRedactedData) => void
}

export interface SealedMarkerObserver {
  readonly onSessionEvent: (session: SealedSessionLike, event: SealedSessionEventLike) => void
  /** Scheduled-but-not-yet-executed marker appends (test/diagnostic visibility). */
  readonly pending: number
}

/** Text blocks of a message-shaped payload, in order. */
function messageTexts(message: unknown): readonly string[] {
  if (message === null || typeof message !== 'object') return []
  const content = (message as { content?: unknown }).content
  if (!Array.isArray(content)) return []
  const texts: string[] = []
  for (const block of content) {
    if (block === null || typeof block !== 'object') continue
    const text = (block as { text?: unknown }).text
    if (typeof text === 'string') texts.push(text)
  }
  return texts
}

/** Placeholder tokens present in the committed message of an eligible landing-path event. */
function placeholderTokensInEvent(event: SealedSessionEventLike): readonly string[] {
  if (event === null || typeof event !== 'object') return []
  const data = event.data
  if (data === null || typeof data !== 'object') return []
  if (event.type === 'tool/result') {
    return messageTexts((data as { message?: unknown }).message).flatMap((text) => parsePlaceholder(text))
  }
  if (event.type === 'user/message') {
    const source = (data as { source?: unknown }).source
    if (source === null || typeof source !== 'object' || (source as { kind?: unknown }).kind !== 'skill-invocation') return []
    return messageTexts(data).flatMap((text) => parsePlaceholder(text))
  }
  return []
}

export function createSealedMarkerObserver(deps: SealedMarkerObserverDeps): SealedMarkerObserver {
  const registry = deps.registry
  const defer = deps.defer ?? ((task: () => void) => queueMicrotask(task))
  const append = deps.append ?? ((session: SealedSessionLike, data: SealedRedactedData) => { session.append(SEALED_REDACTED, data) })
  const seen = new Set<string>()
  let pending = 0
  return {
    get pending() {
      return pending
    },
    onSessionEvent(session, event) {
      try {
        if (session === null || typeof session !== 'object') return
        const refSeq = event?.seq
        if (typeof refSeq !== 'number' || !Number.isInteger(refSeq) || refSeq < 0) return
        for (const token of placeholderTokensInEvent(event)) {
          const record = registry.lookup(token)
          if (record === undefined) continue
          const key = refSeq + ':' + token
          if (seen.has(key)) continue
          seen.add(key)
          const data = sealedRedactedData(refSeq, record.entryId, token, record.alg)
          try {
            assertLosslessEventData(data)
          } catch {
            continue
          }
          pending += 1
          const run = () => {
            pending -= 1
            try {
              append(session, data)
            } catch {
              // Fail-safe: no marker => the model keeps the placeholder; never plaintext, never a throw.
            }
          }
          try {
            defer(run)
          } catch {
            pending -= 1
          }
        }
      } catch {
        // A session/event listener must never throw into the append publisher's observer loop.
      }
    },
  }
}

// --- Plaintext reveal cache -------------------------------------------------------------------
//
// The provider stores each decrypted body as a single Buffer here; the projection reads it back as
// a string. `dispose()` zeroizes every buffer (spec section 8). Nothing else retains plaintext.

export interface SealedPlaintextReveal {
  readonly reveal: NonNullable<LogMaskDeps['reveal']>
  /**
   * Whether `text` occurs inside any cached body. Reads the SAME per-entry buffers as `reveal`
   * (no second copy of any body) and returns only a boolean — it never hands plaintext back.
   * This is the `isPlaintext` source for the Task 6 runtime sentinel.
   */
  contains(text: string): boolean
  save(entryId: string, content: string): void
  dispose(): void
}

export function createPlaintextReveal(): SealedPlaintextReveal {
  const buffers = new Map<string, Buffer>()
  return {
    reveal(entryId) {
      const buffer = buffers.get(entryId)
      return buffer === undefined ? undefined : buffer.toString('utf8')
    },
    contains(text) {
      if (typeof text !== 'string' || text.length === 0) return false
      for (const buffer of buffers.values()) {
        if (buffer.includes(text)) return true
      }
      return false
    },
    save(entryId, content) {
      if (typeof entryId !== 'string' || entryId.length === 0) return
      const previous = buffers.get(entryId)
      if (previous !== undefined) previous.fill(0)
      buffers.set(entryId, Buffer.from(content, 'utf8'))
    },
    dispose() {
      for (const buffer of buffers.values()) buffer.fill(0)
      buffers.clear()
    },
  }
}
