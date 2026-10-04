import { parsePlaceholder, placeholderFor, SEALED_REDACTED_ALG } from './session-events.js'

/**
 * M3 Task 6 — the sealed-plaintext runtime invariant.
 *
 * A package-owned, DEFENSE-IN-DEPTH sentinel: it subscribes to committed `session/event`s and
 * asserts that no decrypted skill body (or canary) ever reaches the durable log. Detection only —
 * unlike the Task 5 log-mask it must never gate the skill provider.
 *
 * Structural mirror of the REAL `@deepseek-ai/dsh-invariants@0.2.0-rc.2` surface. Re-declared
 * (never imported) so this package keeps no dependency on `@deepseek-ai/dsh*` and stays
 * unit-testable in isolation; same style as `provider.ts` / `log-mask.ts`. Verified against the
 * published tarball, `lib/types/index.d.ts`:
 *   :51-53  `declare module '@deepseek-ai/cordis' { interface Context { invariants: InvariantRegistry } }`
 *   :25     `InvariantFailure = (message: string) => never`
 *   :27-37  `interface InvariantInstaller { (ctx, fail): void | Promise<void>; readonly inject?: Inject }`
 *   :39-47  `InvariantError { code: 'INVARIANT'; packageName: string }` (thrown by the real `fail`)
 *   :80     `register(packageName: string, installer: InvariantInstaller): () => void`
 * `register` can be filtered by config (`enabled:false` / allowlist / blocklist); a filtered
 * registration returns a no-op disposer and does NOT throw.
 *
 * CORRECTED FAILURE SEMANTICS (real-runtime probe, dsh 0.2.0-rc.2). The real `fail` does throw
 * `InvariantError` (`dsh-invariants/lib/index.js:92`), but our listener runs inside a
 * `session/event` dispatch, and `dsh-session` wraps every observer in
 * `invokeContainedSessionObservers` (`dsh-session/lib/index.js:1228`): a synchronous listener throw
 * is caught and merely logged as `session "<id>": session/event listener threw: ...`. It does NOT
 * reach `InvariantRegistry`, the child fiber is NOT failed, and the registration is NOT torn down —
 * the sentinel stays armed. The only observable signal on this path is the warn log, which is why
 * the violation message is hard-scrubbed of the offending body (see `describeViolation`). The
 * installer's child-fiber failure would only matter for a NON-swallowed dispatch path. This exact
 * behavior is pinned by the `SEALED_DSH_LAB=1`-gated `test/dsh-invariant.test.ts`. See
 * `docs/sealed-skills/notes/dsh-0.2-seams.md` section 9.6.
 */

/** The package name this invariant registers under. Must be non-empty and whitespace-free. */
export const SEALED_PACKAGE_NAME = '@sealed/dsh-sealed-skills'

/**
 * Strings shorter than this are never treated as plaintext candidates. Guards against a cached body
 * trivially "containing" a short, common field such as `type`, `alg` or an entry id.
 */
export const SEALED_PLAINTEXT_MIN_LENGTH = 24

/**
 * Conservative event-type shape. The violation message echoes the event type ONLY when it matches
 * this pattern; anything else (including an attacker-controlled string) is dropped, so a body
 * smuggled into `event.type` can never reach a log line through the message.
 */
const EVENT_TYPE_PATTERN = /^[a-z][a-z0-9/_.-]{0,63}$/

/** The real `fail` never returns; it throws `InvariantError`. */
export type InvariantFailure = (message: string) => never

/** The subset of the child `Context` the installer uses; the cordis `ctx.on` observer seam. */
export interface SealedInvariantContext {
  readonly on: (
    name: 'session/event',
    listener: (session: unknown, event: unknown) => void,
  ) => () => void
}

export interface InvariantInstaller {
  (ctx: SealedInvariantContext, fail: InvariantFailure): void | Promise<void>
  readonly inject?: readonly string[]
}

export interface InvariantRegistry {
  register(packageName: string, installer: InvariantInstaller): () => void
}

/** A committed session event envelope, as far as this sentinel cares. */
export interface SealedInvariantEvent {
  readonly type: string
  readonly seq: number
  readonly data: unknown
}

function isCommittedEvent(value: unknown): value is SealedInvariantEvent {
  if (value === null || typeof value !== 'object') return false
  const candidate = value as { type?: unknown; seq?: unknown }
  if (typeof candidate.type !== 'string') return false
  if (typeof candidate.seq !== 'number' || !Number.isInteger(candidate.seq) || candidate.seq < 0) return false
  return 'data' in (value as object)
}

/** Remove every occurrence of our placeholder sentinels, leaving only the surrounding text. */
function stripPlaceholders(text: string, tokens: readonly string[]): string {
  let remainder = text
  for (const token of tokens) remainder = remainder.split(placeholderFor(token)).join('')
  return remainder
}

/**
 * The first string leaf of `value` judged plaintext, or `undefined`. Recurses through objects and
 * arrays (never `JSON.stringify`s the whole event: concatenation across fields would manufacture
 * false hits). A leaf that merely CONTAINS a placeholder is stripped and its remainder tested, so
 * `placeholder + body` is still caught while a pure placeholder is not. Strings below `minLength`
 * are ignored, and the known structural constant `SEALED_REDACTED_ALG` is never plaintext.
 */
function findPlaintextLeaf(
  value: unknown,
  minLength: number,
  isPlaintext: (text: string) => boolean,
  seen: Set<object>,
): string | undefined {
  if (typeof value === 'string') {
    if (value.length < minLength) return undefined
    const tokens = parsePlaceholder(value)
    const candidate = tokens.length === 0 ? value : stripPlaceholders(value, tokens)
    if (candidate.length < minLength) return undefined
    if (candidate === SEALED_REDACTED_ALG) return undefined
    return isPlaintext(candidate) === true ? candidate : undefined
  }
  if (value === null || typeof value !== 'object') return undefined
  const obj = value as object
  if (seen.has(obj)) return undefined
  seen.add(obj)
  try {
    if (Array.isArray(obj)) {
      for (const item of obj) {
        const hit = findPlaintextLeaf(item, minLength, isPlaintext, seen)
        if (hit !== undefined) return hit
      }
      return undefined
    }
    for (const key of Object.keys(obj)) {
      const hit = findPlaintextLeaf((obj as Record<string, unknown>)[key], minLength, isPlaintext, seen)
      if (hit !== undefined) return hit
    }
    return undefined
  } finally {
    seen.delete(obj)
  }
}

/**
 * The violation message. It names `seq` always, and the event `type` ONLY when the type is a
 * conservative, log-safe identifier AND is not itself the matched leaf. The offending body (or any
 * body text smuggled into `event.type`) therefore never appears in the message.
 */
function describeViolation(event: SealedInvariantEvent, matchedLeaf: string): string {
  const type = event.type === matchedLeaf || !EVENT_TYPE_PATTERN.test(event.type) ? undefined : event.type
  return type === undefined
    ? 'sealed plaintext reached a committed session event at seq ' + String(event.seq)
    : 'sealed plaintext reached committed session event "' + type + '" at seq ' + String(event.seq)
}

/**
 * The pure decision function. Returns a body-free violation message when a committed session event
 * carries plaintext; `undefined` otherwise.
 *
 * The sentinel itself NEVER throws: a malformed/foreign event, a throwing `isPlaintext`, a cycle,
 * or any unexpected shape all fold into `undefined`.
 */
export function findSealedPlaintext(
  event: unknown,
  isPlaintext: (text: string) => boolean,
  minLength: number = SEALED_PLAINTEXT_MIN_LENGTH,
): string | undefined {
  try {
    if (typeof isPlaintext !== 'function') return undefined
    if (!isCommittedEvent(event)) return undefined
    const floor = Number.isInteger(minLength) && minLength >= 0 ? minLength : SEALED_PLAINTEXT_MIN_LENGTH
    const matched = findPlaintextLeaf(event, floor, isPlaintext, new Set<object>())
    if (matched === undefined) return undefined
    return describeViolation(event, matched)
  } catch {
    return undefined
  }
}

export interface SealedInvariantDeps {
  /** `true` when `text` occurs inside any cached sealed body (Task 5's reveal cache). */
  readonly isPlaintext: (text: string) => boolean
  /** Minimum string length to test; defaults to {@link SEALED_PLAINTEXT_MIN_LENGTH}. */
  readonly minLength?: number
}

/**
 * Build the installer registered under {@link SEALED_PACKAGE_NAME}. It subscribes to committed
 * `session/event`s in its own child fiber (hence `inject: ['sessions']`); on a hit it calls `fail`,
 * which throws `InvariantError`.
 *
 * NOTE (probe-verified): on the `session/event` dispatch path dsh-session SWALLOWS that throw into a
 * warn log, so the registration stays live and the sentinel stays armed. See the module header.
 * The listener itself must never throw except for that deliberate `fail`.
 */
export function createSealedPlaintextInvariant(deps: SealedInvariantDeps): InvariantInstaller {
  const isPlaintext = deps.isPlaintext
  const minLength = deps.minLength ?? SEALED_PLAINTEXT_MIN_LENGTH
  const installer = ((ctx: SealedInvariantContext, fail: InvariantFailure): void => {
    if (ctx === null || typeof ctx !== 'object' || typeof ctx.on !== 'function') return
    ctx.on('session/event', (_session: unknown, event: unknown) => {
      let message: string | undefined
      try {
        message = findSealedPlaintext(event, isPlaintext, minLength)
      } catch {
        message = undefined
      }
      if (message !== undefined && typeof fail === 'function') fail(message)
    })
  }) as InvariantInstaller
  Object.assign(installer, { inject: ['sessions'] as readonly string[] })
  return installer
}

/** Thin forwarder: register `installer` under {@link SEALED_PACKAGE_NAME}, returning the disposer verbatim. */
export function registerSealedInvariant(
  invariants: InvariantRegistry,
  installer: InvariantInstaller,
): () => void {
  return invariants.register(SEALED_PACKAGE_NAME, installer)
}

/**
 * Registrations this module owns, keyed by the registry object. Used only to make reloads
 * idempotent: if a second install hits the real "already registered" error, we dispose our own
 * prior registration and retry once. A WeakMap keeps no reference to the registry once it is gone.
 */
const activeRegistrations = new WeakMap<object, () => void>()

export type SealedInvariantWarning = (message: string) => void

function attemptRegister(
  registry: object & InvariantRegistry,
  installer: InvariantInstaller,
): (() => void) | undefined {
  try {
    const dispose = registry.register(SEALED_PACKAGE_NAME, installer)
    return typeof dispose === 'function' ? dispose : undefined
  } catch {
    return undefined
  }
}

/**
 * Wiring guard used by `plugin.ts`. The invariant is defense-in-depth, so this NEVER throws and
 * NEVER blocks the plugin:
 *  - no `ctx.invariants` (absent service) → one redacted warning, no-op disposer;
 *  - a filtered registration returns a no-op disposer and is accepted silently (not an error);
 *  - an "already registered" throw (plugin reload) → dispose our prior registration if we own one
 *    and retry; otherwise one redacted warning and a no-op disposer.
 * The warning text contains no plaintext.
 */
export function installSealedInvariant(
  invariants: InvariantRegistry | undefined | null,
  installer: InvariantInstaller,
  warn?: SealedInvariantWarning,
): () => void {
  const report: SealedInvariantWarning = typeof warn === 'function' ? warn : () => {}
  if (invariants === undefined || invariants === null || typeof invariants.register !== 'function') {
    report('[sealed-skills] the invariants service is unavailable; the sealed-plaintext sentinel is inactive')
    return () => {}
  }
  const registry = invariants as object & InvariantRegistry
  let dispose = attemptRegister(registry, installer)
  if (dispose === undefined) {
    const previous = activeRegistrations.get(registry)
    if (previous !== undefined) {
      try {
        previous()
      } catch {
        // A stale disposer is best-effort; never let teardown block re-registration.
      }
      activeRegistrations.delete(registry)
      dispose = attemptRegister(registry, installer)
    }
  }
  if (dispose === undefined) {
    report('[sealed-skills] the sealed-plaintext sentinel is already registered; re-registration skipped')
    return () => {}
  }
  activeRegistrations.set(registry, dispose)
  return () => {
    try {
      dispose?.()
    } catch {
      // Best-effort teardown.
    }
    if (activeRegistrations.get(registry) === dispose) activeRegistrations.delete(registry)
  }
}
