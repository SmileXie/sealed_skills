import {
  placeholderFor,
  revealPlaceholder,
  SEALED_REDACTED,
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
//   lib/types/index.d.ts:246 `append(...)`, and surrogate `ignorable` compatibility per types.d.ts:497-507.

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
  readonly nodes: readonly SealedSeq[]
  readonly events: readonly unknown[]
  readonly messages: ReadonlyMap<SealedSeq, SealedMessage>
}

/** The subset of the marker envelope a projection needs (the real event carries seq/time too). */
export interface SealedRedactedEvent {
  readonly type: string
  readonly data: SealedRedactedData
  readonly ignorable?: true
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

  const messages = context?.messages
  if (messages === undefined || typeof messages.get !== 'function') return empty()
  const target = messages.get(refSeq)
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
