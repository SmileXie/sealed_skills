import { randomBytes } from 'node:crypto'

/**
 * `sealed/redacted` — the log-mask marker session event.
 *
 * A skill body is persisted ONLY as an unguessable placeholder. After the message carrying the
 * placeholder is committed, the plugin appends this marker so a registered message projection can
 * rewrite the derived `Message` back to plaintext for the model while the durable log keeps only
 * the placeholder. Task 4 ships the event shape, the placeholder codec and the projection;
 * appending the marker on the two landing paths is Task 5.
 *
 * The marker is appended WITHOUT `ignorable`: dsh 0.2.x `session.append` builds the event envelope
 * itself (`dsh-session/lib/index.js:1448-1457`) and its `...opts` only carries surface metadata, so
 * a non-surface event cannot set `ignorable`. The plugin instead registers this type into dsh's
 * exported `KNOWN_SESSION_EVENT_TYPES` at apply time (`registerDshSessionEventType()` in
 * `plugin.ts`), the Set the persistence read path consults. Cost: a harness WITHOUT this plugin
 * refuses to reconstruct the whole log instead of degrading to the placeholder copy. See
 * `docs/sealed-skills/notes/dsh-0.2-seams.md` section 9.7.
 *
 * The augmentation below is emitted verbatim into `dist/session-events.d.ts`. In a consumer that
 * has the real `@deepseek-ai/dsh-session` it is a module AUGMENTATION and merges with the in-tree
 * `SessionEventMap`; the local compile target is the `paths` stub in `tsconfig.json`.
 *
 * Verified against `@deepseek-ai/dsh-session@0.2.0-rc.2` `lib/types/types.d.ts`:
 *  - `:255`  `export interface SessionEventMap {`
 *  - `:435`  `export type SessionEventType = keyof SessionEventMap;`
 *  - `:489-512` `SessionEvent<T> = { type; seq; time; data; ignorable?: true }`
 *  - `:497-507` a reader meeting an unrecognized type WITHOUT `ignorable: true` MUST refuse to
 *    reconstruct the session. Our event cannot set `ignorable`, so the type is made known through
 *    the runtime registry described above (section 9.7).
 */
declare module '@deepseek-ai/dsh-session/types' {
  interface SessionEventMap {
    'sealed/redacted': { refSeq: number; entryId: string; token: string; alg: string }
  }
}

/** Session event type name. Owned by this package; the type is registered at apply time (section 9.7). */
export const SEALED_REDACTED = 'sealed/redacted' as const

/**
 * Algorithm label carried by a marker. The real entry crypto is X25519 (device key) + HKDF-SHA256
 * (per-entry key) + AES-256-GCM (`packages/pack-format/src/aead.ts`); the label is informational
 * for `reveal()` and is validated by the reveal implementation, not by the projection.
 */
export const SEALED_REDACTED_ALG = 'x25519-hkdf-sha256-aes-256-gcm' as const

/**
 * Data payload of a `sealed/redacted` marker: LOSSLESS JSON and free of any plaintext.
 *
 * `session.append` snapshots the data and rejects BigInt / function / symbol / undefined /
 * negative zero / non-finite number / circular reference / sparse array / Map / Set / Date /
 * class instance — `assertLosslessEventData` mirrors that rule so Task 5 can fail closed before
 * ever touching the log.
 */
export interface SealedRedactedData {
  /** Sequence of the already-committed message carrying the placeholder (never the marker's own). */
  readonly refSeq: number
  /** Entry id the plaintext lives under, e.g. `skill:<name>:body`. Not secret. */
  readonly entryId: string
  /** Unguessable placeholder token bound to the persisted body (128-bit, base64url). */
  readonly token: string
  /** Algorithm label for `reveal()` (see `SEALED_REDACTED_ALG`). */
  readonly alg: string
}

/** Build the marker payload. Pure shaping only — never reads or embeds plaintext. */
export function sealedRedactedData(
  refSeq: number,
  entryId: string,
  token: string,
  alg: string = SEALED_REDACTED_ALG,
): SealedRedactedData {
  return { refSeq, entryId, token, alg }
}

export class SealedEventError extends Error {
  readonly code = 'SEALED_EVENT_INVALID'
  constructor(message: string) {
    super(message)
    this.name = 'SealedEventError'
  }
}

/**
 * Reject anything `session.append` would reject, before it reaches the durable log. Error messages
 * never include the offending value (zero plaintext in errors/logs/telemetry).
 */
export function assertLosslessEventData(data: unknown): void {
  checkLossless(data, new Set<object>())
}

function checkLossless(value: unknown, seen: Set<object>): void {
  if (value === null) return
  switch (typeof value) {
    case 'string':
    case 'boolean':
      return
    case 'number':
      if (!Number.isFinite(value) || Object.is(value, -0)) {
        throw new SealedEventError('sealed event data contains a non-lossless number')
      }
      return
    case 'bigint':
    case 'function':
    case 'symbol':
    case 'undefined':
      throw new SealedEventError('sealed event data contains a non-lossless ' + typeof value)
    case 'object':
      break
    default:
      throw new SealedEventError('sealed event data contains an unsupported value')
  }
  const obj = value as object
  if (seen.has(obj)) throw new SealedEventError('sealed event data contains a circular reference')
  seen.add(obj)
  try {
    if (Array.isArray(obj)) {
      if (Object.keys(obj).length !== obj.length) {
        throw new SealedEventError('sealed event data contains a sparse array')
      }
      for (const item of obj) checkLossless(item, seen)
      return
    }
    const proto = Object.getPrototypeOf(obj)
    if (proto !== Object.prototype && proto !== null) {
      throw new SealedEventError('sealed event data contains an exotic object')
    }
    for (const key of Object.keys(obj)) checkLossless((obj as Record<string, unknown>)[key], seen)
  } finally {
    seen.delete(obj)
  }
}

// --- Placeholder codec -----------------------------------------------------------------------
//
// Sentinel: U+2063 INVISIBLE SEPARATOR + `[sealed:redacted:v1:<token>]`. The invisible separator
// makes an accidental collision with a normal skill body effectively impossible while staying a
// plain string (lossless JSON, survives tool-result rendering).

const PLACEHOLDER_OPEN = '\u2063[sealed:redacted:v1:'
const PLACEHOLDER_CLOSE = ']'
const PLACEHOLDER_PATTERN = /\u2063\[sealed:redacted:v1:([A-Za-z0-9_-]+)\]/g

export interface SealedPlaceholder {
  readonly text: string
  readonly token: string
}

/** Render an unguessable (128-bit random, base64url) placeholder for an entry id. */
export function renderPlaceholder(entryId: string): SealedPlaceholder {
  if (typeof entryId !== 'string' || entryId.length === 0) {
    throw new SealedEventError('placeholder requires a non-empty entry id')
  }
  const token = randomBytes(16).toString('base64url')
  return { token, text: placeholderFor(token) }
}

/** The exact sentinel text for a token; used for matching/replacement, never for guessing. */
export function placeholderFor(token: string): string {
  if (typeof token !== 'string' || token.length === 0) {
    throw new SealedEventError('placeholder requires a non-empty token')
  }
  return PLACEHOLDER_OPEN + token + PLACEHOLDER_CLOSE
}

/** All tokens found in `text`, in order (handles the same token appearing more than once). */
export function parsePlaceholder(text: string): readonly string[] {
  if (typeof text !== 'string' || text.length === 0) return []
  const tokens: string[] = []
  PLACEHOLDER_PATTERN.lastIndex = 0
  let match: RegExpExecArray | null
  while ((match = PLACEHOLDER_PATTERN.exec(text)) !== null) tokens.push(match[1])
  return tokens
}

/** Replace every occurrence of `token`'s sentinel in `text` with `plaintext` (idempotent per run). */
export function revealPlaceholder(text: string, token: string, plaintext: string): string {
  return text.split(placeholderFor(token)).join(plaintext)
}

// --- Placeholder registry --------------------------------------------------------------------

export interface SealedPlaceholderRecord {
  readonly entryId: string
  readonly alg: string
}

/**
 * Token -> entry bookkeeping shared between the placeholder renderer and the Task 5 marker
 * append. The provider side records what it rendered; the landing-path observer looks a token
 * back up to learn which entry (and algorithm) a committed placeholder belongs to.
 */
export interface SealedPlaceholderRegistry {
  record(token: string, record: SealedPlaceholderRecord): void
  lookup(token: string): SealedPlaceholderRecord | undefined
  delete(token: string): boolean
  readonly size: number
  tokens(): readonly string[]
  clear(): void
}

export function createPlaceholderRegistry(): SealedPlaceholderRegistry {
  const entries = new Map<string, SealedPlaceholderRecord>()
  return {
    record(token, record) {
      if (typeof token !== 'string' || token.length === 0) {
        throw new SealedEventError('placeholder registry requires a non-empty token')
      }
      entries.set(token, { entryId: record.entryId, alg: record.alg })
    },
    lookup(token) {
      return entries.get(token)
    },
    delete(token) {
      return entries.delete(token)
    },
    get size() {
      return entries.size
    },
    tokens() {
      return [...entries.keys()]
    },
    clear() {
      entries.clear()
    },
  }
}
