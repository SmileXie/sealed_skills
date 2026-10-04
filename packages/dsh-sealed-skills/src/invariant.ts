import { parsePlaceholder } from './session-events.js'

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
 * Runtime (`lib/index.js:92-94`) implements `fail` as `throw new InvariantError(packageName, message)`;
 * the installer runs in a CHILD fiber (`ctx.plugin(...)`), so its failure tears down only this
 * registration. `register` can be filtered by config (`enabled:false` / allowlist / blocklist); a
 * filtered registration returns a no-op disposer and does NOT throw. See
 * `docs/sealed-skills/notes/dsh-0.2-seams.md` section 9.6.
 */

/** The package name this invariant registers under. Must be non-empty and whitespace-free. */
export const SEALED_PACKAGE_NAME = '@sealed/dsh-sealed-skills'

/**
 * Strings shorter than this are never treated as plaintext candidates. Guards against a cached body
 * trivially "containing" a short, common field such as `type`, `alg` or an entry id.
 */
export const SEALED_PLAINTEXT_MIN_LENGTH = 24

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

/**
 * Whether any string leaf of `value` is judged plaintext. Recurses through objects/arrays (never
 * `JSON.stringify`s the whole event: concatenation across fields would manufacture false hits) and
 * skips our own placeholder sentinels. Strings below `minLength` are ignored.
 */
function containsPlaintextLeaf(
  value: unknown,
  minLength: number,
  isPlaintext: (text: string) => boolean,
  seen: Set<object>,
): boolean {
  if (typeof value === 'string') {
    if (value.length < minLength) return false
    if (parsePlaceholder(value).length > 0) return false
    return isPlaintext(value) === true
  }
  if (value === null || typeof value !== 'object') return false
  const obj = value as object
  if (seen.has(obj)) return false
  seen.add(obj)
  try {
    if (Array.isArray(obj)) {
      for (const item of obj) {
        if (containsPlaintextLeaf(item, minLength, isPlaintext, seen)) return true
      }
      return false
    }
    for (const key of Object.keys(obj)) {
      if (containsPlaintextLeaf((obj as Record<string, unknown>)[key], minLength, isPlaintext, seen)) return true
    }
    return false
  } finally {
    seen.delete(obj)
  }
}

/**
 * The pure decision function. Returns a violation message that names ONLY `type` and `seq` (never
 * the offending body) when a committed session event carries plaintext; `undefined` otherwise.
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
    if (!containsPlaintextLeaf(event, floor, isPlaintext, new Set<object>())) return undefined
    return 'sealed plaintext reached committed session event "' + event.type + '" at seq ' + String(event.seq)
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
 * `session/event`s in its own child fiber (hence `inject: ['sessions']`); a hit calls `fail`, which
 * throws `InvariantError` and tears down only this registration. The listener itself must never
 * throw except for that deliberate `fail`.
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
