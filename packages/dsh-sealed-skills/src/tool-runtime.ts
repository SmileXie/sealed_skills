import { spawn as nodeSpawn } from 'node:child_process'

/**
 * M3 Task 7 — the sandboxed sealed-script tool.
 *
 * A sealed skill may ship `script:<name>:<path>` entries. This module turns them into dsh tools
 * (`sealed_script_*`) that run the decrypted script source inside the harness sandbox WITHOUT ever
 * writing the source to disk or putting it on the child's argv:
 *
 *   readEntry(entryId) -> source Buffer
 *   argv = ['node', '--input-type=module', '-']        (or ['python3', '-'])
 *   confined = await ctx.sandbox.confine(argv, policy, signal)
 *   spawn(confined.argv[0], confined.argv.slice(1), { cwd: policy.workspaceRoot, stdio: pipe*3 })
 *   child.stdin.end(source)                            <- the source arrives on stdin only
 *
 * The model-supplied `input` argument is appended AFTER the `-` separator, so it travels as an
 * ordinary argv element; the SOURCE never does. Real-machine probe (Node v24.14.1):
 *   `'console.log(1)' | node --input-type=module - arg1`
 *   -> process.argv = [nodePath, '-', 'arg1'], and the program on stdin executes as ESM.
 *
 * Structural mirror of the REAL `@deepseek-ai/dsh-tools@0.2.0-rc.2` / `dsh-sandbox` surfaces.
 * Re-declared (never imported) so this package keeps no dependency on `@deepseek-ai/dsh*` and stays
 * unit-testable in isolation; same style as `provider.ts` / `invariant.ts`. Verified against the
 * published tarballs:
 *   dsh-tools `lib/types/index.d.ts:32-35`    `ctx.tools: ToolRuntime`
 *   dsh-tools `lib/types/index.d.ts:630-636`  `register(definition: ToolDefinition): () => void`
 *   dsh-tools `lib/types/schema.d.ts:248`     `defineTool(options): ToolDefinition`
 *   dsh-tools `lib/types/schema.d.ts:178-240` DefineToolOptions { name, description, parameters,
 *                                             output: { schema, render }, execute, timeoutMs, ... }
 *   dsh-sandbox `lib/types/index.d.ts:141`    `confine(argv, policy, signal?): Promise<ConfinedArgv>`
 *   dsh-sandbox `lib/types/index.d.ts:27-58`  SandboxPolicy { mode: 'read-only'|'workspace-write',
 *                                             workspaceRoot, sessionId? }
 *   dsh-sandbox `lib/types/index.d.ts:107-115` SANDBOX_UNAVAILABLE / SandboxUnavailableError
 *
 * Presentation: a plain tool registered under the `sealed_script_*` name (never the reserved
 * `run_code`). `dsh-tools` `mode: 'ptc'` only lets a MODEL-DIRECT call name the reserved `run_code`
 * transport, so `ptc` cannot reach this tool directly (it stays callable as a nested sub-dispatch);
 * under `native` / `both` it is an ordinary model-callable tool. There is NO per-tool presentation
 * field in `DefineToolOptions` (`dsh-tools/lib/types/schema.d.ts:178-240`): an earlier draft passed
 * a dead `presentation: 'native'` key, now removed.
 *
 * Zero-plaintext guarantees: the SECRET here is the decrypted script SOURCE. It never reaches argv,
 * a temp file, a log line, or an error message — the child only sees it on stdin, and the source
 * Buffer is zeroized (`fill(0)`) in a `finally`. Error results carry a fixed per-reason message,
 * never the underlying error text.
 */

/** Every generated tool name starts with this prefix (`sealed_script_<sanitized-entry>`). */
export const SEALED_SCRIPT_TOOL_PREFIX = 'sealed_script_'

/** Entry id convention (spec §entry ids): `script:<name>:<path>`. */
export const SEALED_SCRIPT_ENTRY_PREFIX = 'script:'

/** Fallback time limit for one sealed script run when a spec declares none. */
export const SEALED_SCRIPT_DEFAULT_TIMEOUT_MS = 30_000

/** Combined stdout+stderr cap; exceeding it kills the child and fails closed. */
export const SEALED_SCRIPT_MAX_OUTPUT_BYTES = 1_048_576

/** A trimmed, non-empty source line at least this long is a leak signature (Node code frames echo lines). */
export const SEALED_SCRIPT_LEAK_LINE_MIN = 16
/** A contiguous slice of source at least this long is a leak signature (partial / normalized echo). */
export const SEALED_SCRIPT_LEAK_WINDOW_MIN = 32
/** Step between window starts; sealed script sources are tiny, so dense coverage stays cheap. */
export const SEALED_SCRIPT_LEAK_WINDOW_STEP = 8
/** Upper bound on windows scanned, so a pathological multi-MB source cannot stall the tool. */
export const SEALED_SCRIPT_LEAK_MAX_WINDOWS = 8192

/**
 * True when a child stream (stdout or stderr) echoes sealed SOURCE material. Deliberately
 * conservative: a false positive only withholds output, a false negative would put source into the
 * model context and the durable session log, where neither the log-mask nor the plaintext sentinel
 * can catch it (scripts are never placeholder-redacted).
 *
 *  - LINE signature: any non-empty trimmed source line of >= {@link SEALED_SCRIPT_LEAK_LINE_MIN}
 *    chars that appears in the output. This is what Node's syntax-error code frame leaks.
 *  - WINDOW signature: any contiguous {@link SEALED_SCRIPT_LEAK_WINDOW_MIN}-char source window that
 *    appears in the output (catches whitespace-normalized or partial echoes), scanning at most
 *    {@link SEALED_SCRIPT_LEAK_MAX_WINDOWS} starts.
 */
export function leaksSealedSource(output: string, sourceText: string): boolean {
  if (output.length === 0 || sourceText.length === 0) return false
  for (const rawLine of sourceText.split('\n')) {
    const line = rawLine.trim()
    if (line.length >= SEALED_SCRIPT_LEAK_LINE_MIN && output.includes(line)) return true
  }
  let windows = 0
  for (let start = 0; start + SEALED_SCRIPT_LEAK_WINDOW_MIN <= sourceText.length; start += SEALED_SCRIPT_LEAK_WINDOW_STEP) {
    if (windows >= SEALED_SCRIPT_LEAK_MAX_WINDOWS) break
    windows += 1
    if (output.includes(sourceText.slice(start, start + SEALED_SCRIPT_LEAK_WINDOW_MIN))) return true
  }
  return false
}

/**
 * Node-only prelude prepended to the stdin program. It replaces Node's default uncaught-error dump
 * (a code frame containing the offending source line) with a fixed, body-free line, so an ordinary
 * runtime throw or unhandled rejection cannot leak the source. SYNTAX errors fail before it runs,
 * which is why {@link leaksSealedSource} remains the authoritative gate.
 * Probe-verified on Node v24.14.1: normal scripts are unaffected; `import` declarations after the
 * prelude still hoist correctly.
 */
export const SEALED_SCRIPT_NODE_PRELUDE = [
  "process.on('uncaughtException', () => {",
  '  process.exitCode = 1',
  "  process.stderr.write('[sealed-script] the sealed script threw; its diagnostics were withheld\\n')",
  '})',
  "process.on('unhandledRejection', () => {",
  '  process.exitCode = 1',
  "  process.stderr.write('[sealed-script] the sealed script rejected; its diagnostics were withheld\\n')",
  '})',
  '',
].join('\n')

/** The exact program delivered on stdin: the node prelude precedes the secret source. */
export function sealedScriptProgram(runtime: 'node' | 'python', sourceText: string): string {
  return runtime === 'node' ? SEALED_SCRIPT_NODE_PRELUDE + sourceText : sourceText
}

/** Structured failure reasons. `message` is always the matching fixed, plaintext-free text. */
export type SealedScriptFailureReason =
  | 'sandbox-unavailable'
  | 'entry-unavailable'
  | 'spawn-failed'
  | 'timeout'
  | 'aborted'
  | 'output-limit'
  | 'output-redacted'
  | 'sandbox-not-enforcing'

export type SealedScriptResult =
  | { readonly ok: true; readonly stdout: string; readonly stderr: string; readonly exitCode: number }
  | { readonly ok: false; readonly reason: SealedScriptFailureReason; readonly message: string }

const SAFE_MESSAGES: Record<SealedScriptFailureReason, string> = {
  'sandbox-unavailable': 'the host sandbox is unavailable, so the sealed script was not executed',
  'entry-unavailable': 'the sealed script entry could not be read',
  'spawn-failed': 'the sealed script process could not be started',
  timeout: 'the sealed script exceeded its time limit',
  aborted: 'the sealed script was cancelled',
  'output-limit': 'the sealed script produced too much output',
  'output-redacted': 'the sealed script output was withheld because it contained script source',
  'sandbox-not-enforcing': 'the host sandbox could not fully enforce the requested policy, so the sealed script was not executed',
}

function failure(reason: SealedScriptFailureReason): SealedScriptResult {
  return { ok: false, reason, message: SAFE_MESSAGES[reason] }
}

// --- Structural dsh mirrors ---------------------------------------------------------------------

/** Mirrors `dsh-sandbox` `SandboxPolicy` (`lib/types/index.d.ts:27-58`). */
export interface SandboxPolicy {
  readonly mode: 'read-only' | 'workspace-write'
  readonly workspaceRoot: string
  readonly sessionId?: string
}

/** Mirrors `dsh-sandbox` `ConfinedArgv` (`lib/types/index.d.ts:79-100`); extra fields are opaque. */
export interface ConfinedArgv {
  readonly argv: readonly string[]
  readonly enforcement: 'full' | 'partial'
  readonly denialSignatures?: readonly string[]
  readonly runnerFailureRules?: readonly unknown[]
}

export interface SandboxProviderLike {
  confine(argv: readonly string[], policy: SandboxPolicy, signal?: AbortSignal): Promise<ConfinedArgv>
}

/** A `HarnessError` carrying `SANDBOX_UNAVAILABLE`; matched structurally, never imported. */
export interface SandboxUnavailableErrorLike {
  readonly code?: string
  readonly name?: string
}

// --- Injectable child-process seam --------------------------------------------------------------

export interface SealedReadableLike {
  on(event: 'data', listener: (chunk: unknown) => void): unknown
}

export interface SealedWritableLike {
  end(data?: unknown): unknown
  on?(event: 'error', listener: (error: Error) => void): unknown
}

export interface SealedChildProcessLike {
  readonly stdin: SealedWritableLike | null
  readonly stdout: SealedReadableLike | null
  readonly stderr: SealedReadableLike | null
  kill(signal?: string): boolean
  on(event: 'error', listener: (error: Error) => void): unknown
  on(event: 'close', listener: (code: number | null, signal: string | null) => void): unknown
}

export interface SealedSpawnOptions {
  readonly cwd: string
  readonly stdio: readonly ['pipe', 'pipe', 'pipe']
}

export type SealedSpawnLike = (
  command: string,
  args: readonly string[],
  options: SealedSpawnOptions,
) => SealedChildProcessLike

/** The real `node:child_process.spawn`, narrowed to the seam above. */
const defaultSpawn: SealedSpawnLike = (command, args, options) =>
  nodeSpawn(command, [...args], { cwd: options.cwd, stdio: ['pipe', 'pipe', 'pipe'] }) as unknown as SealedChildProcessLike

// --- Pure execution core ------------------------------------------------------------------------

export interface SealedScriptDeps {
  /** Decrypts one entry id to a fresh Buffer the caller owns (and this module zeroizes). */
  readEntry(entryId: string): Promise<Buffer>
  /** The host sandbox wrapper. Fail-closed by contract. */
  confine(argv: readonly string[], policy: SandboxPolicy, signal?: AbortSignal): Promise<ConfinedArgv>
  /** Test-only injection; defaults to the real `node:child_process.spawn`. */
  spawn?: SealedSpawnLike
}

export interface SealedScriptSpec {
  readonly name: string
  readonly entryId: string
  readonly runtime: 'node' | 'python'
  readonly policy: SandboxPolicy
  readonly timeoutMs?: number
}

/** `['node','--input-type=module','-', ...args]` / `['python3','-', ...args]`. */
export function sealedScriptArgv(runtime: 'node' | 'python', args: readonly string[] = []): string[] {
  const base = runtime === 'python' ? ['python3', '-'] : ['node', '--input-type=module', '-']
  return [...base, ...args]
}

/** `'script:translate:run.mjs'` -> `{ skillName: 'translate', path: 'run.mjs' }`, or undefined. */
export function parseSealedScriptEntryId(entryId: string): { skillName: string; path: string } | undefined {
  if (!entryId.startsWith(SEALED_SCRIPT_ENTRY_PREFIX)) return undefined
  const rest = entryId.slice(SEALED_SCRIPT_ENTRY_PREFIX.length)
  const split = rest.indexOf(':')
  if (split <= 0 || split === rest.length - 1) return undefined
  return { skillName: rest.slice(0, split), path: rest.slice(split + 1) }
}

/** Deterministic, collision-resistant-enough tool name: `sealed_script_translate_run_mjs`. */
export function sealedScriptToolName(entryId: string): string {
  const rest = entryId.startsWith(SEALED_SCRIPT_ENTRY_PREFIX)
    ? entryId.slice(SEALED_SCRIPT_ENTRY_PREFIX.length)
    : entryId
  const sanitized = rest.replace(/[^A-Za-z0-9]+/g, '_').replace(/^_+|_+$/g, '').toLowerCase()
  const tail = sanitized.length > 0 ? sanitized.slice(0, 56) : 'script'
  return SEALED_SCRIPT_TOOL_PREFIX + tail
}

/** `.py` -> CPython; everything else -> Node. v1 heuristic (see report for the supported surface). */
export function inferSealedScriptRuntime(entryId: string): 'node' | 'python' {
  return entryId.toLowerCase().endsWith('.py') ? 'python' : 'node'
}

function isSandboxUnavailable(error: unknown): boolean {
  if (error === null || typeof error !== 'object') return false
  const shaped = error as SandboxUnavailableErrorLike
  return shaped.code === 'SANDBOX_UNAVAILABLE' || shaped.name === 'SandboxUnavailableError'
}

type ConfinementVerdict = 'ok' | 'unavailable' | 'not-enforcing'

/**
 * Conservative classification of a `confine()` result. Only `enforcement: 'full'` is trusted:
 * `'partial'` means the backend cannot govern every promised file effect, so we refuse rather than
 * run a sealed script behind a weaker boundary than the policy claims. A malformed/non-string argv
 * is treated as unavailable.
 */
function classifyConfinement(value: unknown): ConfinementVerdict {
  if (value === null || typeof value !== 'object') return 'unavailable'
  const candidate = value as { argv?: unknown; enforcement?: unknown }
  const argv = candidate.argv
  if (!Array.isArray(argv) || argv.length === 0) return 'unavailable'
  if (!argv.every((part) => typeof part === 'string' && part.length > 0)) return 'unavailable'
  return candidate.enforcement === 'full' ? 'ok' : 'not-enforcing'
}

function isEnforcingArgv(value: unknown): value is ConfinedArgv {
  return classifyConfinement(value) === 'ok'
}

function appendChunk(target: Buffer[], chunk: unknown): number {
  const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk))
  target.push(buffer)
  return buffer.length
}

/**
 * Decrypt -> confine -> spawn -> feed stdin. Never throws: every fault folds into a structured,
 * plaintext-free {@link SealedScriptResult}. The source Buffer is zeroized before returning.
 */
export async function executeSealedScript(
  deps: SealedScriptDeps,
  spec: SealedScriptSpec,
  args: readonly string[] = [],
  signal?: AbortSignal,
): Promise<SealedScriptResult> {
  const spawn = deps.spawn ?? defaultSpawn
  let source: Buffer | undefined
  try {
    if (signal?.aborted) return failure('aborted')
    try {
      source = await deps.readEntry(spec.entryId)
    } catch {
      return failure('entry-unavailable')
    }
    if (signal?.aborted) return failure('aborted')

    let confined: ConfinedArgv
    try {
      confined = await deps.confine(sealedScriptArgv(spec.runtime, args), spec.policy, signal)
    } catch (error) {
      // A malformed/absent confinement result is a refusal, never a silent unconfined passthrough.
      return failure(isSandboxUnavailable(error) ? 'sandbox-unavailable' : 'spawn-failed')
    }
    if (!isEnforcingArgv(confined)) {
      return failure(classifyConfinement(confined) === 'not-enforcing' ? 'sandbox-not-enforcing' : 'sandbox-unavailable')
    }

    return await runConfined(spawn, confined, source, spec, signal)
  } catch {
    return failure('spawn-failed')
  } finally {
    source?.fill(0)
  }
}

function runConfined(
  spawn: SealedSpawnLike,
  confined: ConfinedArgv,
  source: Buffer,
  spec: SealedScriptSpec,
  signal?: AbortSignal,
): Promise<SealedScriptResult> {
  // The secret source lives only until the output is collected; the caller zeroizes the Buffer in
  // its own `finally`. `program` (prelude + source for node) is what actually reaches the child.
  const sourceText = source.toString('utf8')
  const program = sealedScriptProgram(spec.runtime, sourceText)
  return new Promise<SealedScriptResult>((resolve) => {
    let child: SealedChildProcessLike
    try {
      child = spawn(confined.argv[0], confined.argv.slice(1), {
        cwd: spec.policy.workspaceRoot,
        stdio: ['pipe', 'pipe', 'pipe'],
      })
    } catch {
      resolve(failure('spawn-failed'))
      return
    }

    const stdoutChunks: Buffer[] = []
    const stderrChunks: Buffer[] = []
    let totalBytes = 0
    let overflowed = false
    let settled = false
    let timer: ReturnType<typeof setTimeout> | undefined

    const kill = (): void => {
      try {
        child.kill('SIGKILL')
      } catch {
        // Best-effort: a process that is already gone cannot be killed again.
      }
    }
    const finish = (result: SealedScriptResult): void => {
      if (settled) return
      settled = true
      if (timer !== undefined) clearTimeout(timer)
      if (signal !== undefined && typeof signal.removeEventListener === 'function') {
        signal.removeEventListener('abort', onAbort)
      }
      resolve(result)
    }
    const onAbort = (): void => {
      kill()
      finish(failure('aborted'))
    }
    const collect = (target: Buffer[]) => (chunk: unknown): void => {
      totalBytes += appendChunk(target, chunk)
      if (totalBytes > SEALED_SCRIPT_MAX_OUTPUT_BYTES) {
        overflowed = true
        kill()
      }
    }

    try {
      child.stdout?.on('data', collect(stdoutChunks))
      child.stderr?.on('data', collect(stderrChunks))
      child.stdin?.on?.('error', () => {
        // The child died before reading stdin; surface it through the close/error path only.
      })
      child.on('error', () => {
        kill()
        finish(failure('spawn-failed'))
      })
      child.on('close', (code) => {
        const dropChunks = (): void => {
          for (const chunk of stdoutChunks) chunk.fill(0)
          for (const chunk of stderrChunks) chunk.fill(0)
        }
        if (overflowed) {
          dropChunks()
          finish(failure('output-limit'))
          return
        }
        const stdout = Buffer.concat(stdoutChunks).toString('utf8')
        const stderr = Buffer.concat(stderrChunks).toString('utf8')
        if (leaksSealedSource(stdout, sourceText) || leaksSealedSource(stderr, sourceText)) {
          // Fail closed: never surface a stream that echoes sealed source (a Node code frame, a
          // deliberate echo, ...). The bytes are dropped and the buffers zeroized.
          dropChunks()
          finish(failure('output-redacted'))
          return
        }
        finish({ ok: true, stdout, stderr, exitCode: typeof code === 'number' ? code : -1 })
      })
    } catch {
      kill()
      finish(failure('spawn-failed'))
      return
    }

    const timeoutMs = typeof spec.timeoutMs === 'number' && Number.isFinite(spec.timeoutMs) && spec.timeoutMs > 0
      ? spec.timeoutMs
      : SEALED_SCRIPT_DEFAULT_TIMEOUT_MS
    timer = setTimeout(() => {
      kill()
      finish(failure('timeout'))
    }, timeoutMs)

    if (signal !== undefined) {
      if (signal.aborted) {
        kill()
        finish(failure('aborted'))
        return
      }
      if (typeof signal.addEventListener === 'function') signal.addEventListener('abort', onAbort, { once: true })
    }

    if (child.stdin === null || child.stdin === undefined) {
      kill()
      finish(failure('spawn-failed'))
      return
    }
    try {
      child.stdin.end(program)
    } catch {
      kill()
      finish(failure('spawn-failed'))
    }
  })
}

// --- dsh tool definition production -------------------------------------------------------------

export interface SealedScriptContentBlock {
  readonly type: 'text'
  readonly text: string
}

export interface SealedToolParameterProperty {
  readonly type: string
  readonly description?: string
  readonly required?: boolean
}

export type SealedParameterSchemaSpec = Record<string, SealedToolParameterProperty>

export interface SealedToolRunContextLike {
  readonly signal?: AbortSignal
}

export interface SealedToolOutputDefinition {
  readonly schema: unknown
  render(args: unknown, value: unknown): readonly SealedScriptContentBlock[]
}

export interface SealedScriptToolOptions {
  readonly name: string
  readonly description: string
  readonly parameters: SealedParameterSchemaSpec
  readonly output: SealedToolOutputDefinition
  readonly timeoutMs?: number
  execute(args: unknown, exec: SealedToolRunContextLike): Promise<unknown>
}

export interface SealedToolDefinition {
  readonly name: string
  readonly description: string
  readonly parameters: unknown
  readonly output: SealedToolOutputDefinition
  execute(args: unknown, exec: SealedToolRunContextLike): Promise<unknown>
}

export type DefineToolLike = (options: SealedScriptToolOptions) => SealedToolDefinition

/** `null` explicitly disables the builder (test seam); `undefined` loads the real dsh module. */
export type DefineToolInput = DefineToolLike | null | undefined

export interface ToolRuntimeLike {
  register(definition: SealedToolDefinition): () => void
}

/** Error raised when the structural contract is violated (channel unavailable, no builder). */
export class SealedScriptToolError extends Error {
  constructor(readonly code: 'TOOL_BUILDER_UNAVAILABLE' | 'TOOL_RUNTIME_UNAVAILABLE', message: string) {
    super(message)
    this.name = 'SealedScriptToolError'
  }
}

const DSH_TOOLS_SPECIFIER: string = '@deepseek-ai/dsh-tools'

/**
 * Dynamically import the real `defineTool` (never a static import: dsh is an optional peer and the
 * specifier is held in a `string` so tsc never tries to resolve it). Returns `undefined` when dsh
 * is absent, so the caller degrades instead of crashing.
 */
export async function loadDefineTool(): Promise<DefineToolLike | undefined> {
  try {
    const mod = (await import(/* @vite-ignore */ DSH_TOOLS_SPECIFIER)) as { defineTool?: unknown }
    return typeof mod.defineTool === 'function' ? (mod.defineTool as DefineToolLike) : undefined
  } catch {
    return undefined
  }
}

const RESULT_SCHEMA = {
  type: 'object',
  properties: {
    ok: { type: 'boolean', description: 'Whether the sealed script ran to completion.', required: true },
    stdout: { type: 'string', description: 'The script standard output.' },
    stderr: { type: 'string', description: 'The script standard error.' },
    exitCode: { type: 'integer', description: 'The script process exit code.' },
    reason: { type: 'string', description: 'Structured refusal reason when the script did not run.' },
    message: { type: 'string', description: 'Plaintext-free explanation when the script did not run.' },
  },
  additionalProperties: true,
} as const

function scriptRelativePath(entryId: string): string {
  return parseSealedScriptEntryId(entryId)?.path ?? entryId
}

function scriptToolDescription(spec: SealedScriptSpec): string {
  return 'Run the sealed skill "' + spec.name + '" script "' + scriptRelativePath(spec.entryId) + '" inside the dsh sandbox. '
    + 'The optional "input" argument is delivered to the script as an argv element; the script prints its result to stdout.'
}

/** Pure, plaintext-free model rendering of one {@link SealedScriptResult}. */
export function renderSealedScriptResult(value: unknown): string {
  if (value === null || typeof value !== 'object') return 'The sealed script returned no result.'
  const result = value as {
    ok?: unknown
    stdout?: unknown
    stderr?: unknown
    exitCode?: unknown
    reason?: unknown
    message?: unknown
  }
  if (result.ok === false) {
    const reason = typeof result.reason === 'string' ? result.reason : 'failed'
    const message = typeof result.message === 'string' ? result.message : 'the sealed script did not run'
    return 'The sealed script did not run (' + reason + '): ' + message
  }
  const stdout = typeof result.stdout === 'string' ? result.stdout : ''
  const stderr = typeof result.stderr === 'string' ? result.stderr : ''
  const exitCode = typeof result.exitCode === 'number' ? result.exitCode : 0
  const lines = [stdout.trim().length > 0 ? stdout.trimEnd() : '(no output)']
  if (exitCode !== 0) lines.push('(exit code ' + exitCode + ')')
  if (stderr.trim().length > 0) lines.push('stderr: ' + stderr.trimEnd())
  return lines.join('\n')
}

function buildToolOptions(spec: SealedScriptSpec, deps: SealedScriptDeps): SealedScriptToolOptions {
  return {
    name: sealedScriptToolName(spec.entryId),
    description: scriptToolDescription(spec),
    parameters: {
      input: {
        type: 'string',
        description: 'Optional input passed to the sealed script as an argv element.',
      },
    },
    output: {
      schema: RESULT_SCHEMA,
      render: (_args, value) => [{ type: 'text', text: renderSealedScriptResult(value) }],
    },
    ...(typeof spec.timeoutMs === 'number' ? { timeoutMs: spec.timeoutMs } : {}),
    execute: async (args, exec) => {
      const input = args !== null && typeof args === 'object' ? (args as { input?: unknown }).input : undefined
      const argv = typeof input === 'string' && input.length > 0 ? [input] : []
      return await executeSealedScript(deps, spec, argv, exec?.signal)
    },
  }
}

/** Build one dsh `ToolDefinition`. Uses the injected builder, else the real dynamic import. */
export async function buildSealedScriptTool(
  spec: SealedScriptSpec,
  deps: SealedScriptDeps,
  defineTool?: DefineToolLike | null,
): Promise<SealedToolDefinition> {
  const define = defineTool === null ? undefined : (defineTool ?? await loadDefineTool())
  if (typeof define !== 'function') {
    throw new SealedScriptToolError('TOOL_BUILDER_UNAVAILABLE', 'the dsh tool builder is unavailable')
  }
  return define(buildToolOptions(spec, deps))
}

/** Build every spec; a spec whose definition cannot be built is skipped (never fatal). */
export async function createSealedScriptTools(
  specs: readonly SealedScriptSpec[],
  deps: SealedScriptDeps,
  defineTool?: DefineToolLike | null,
): Promise<SealedToolDefinition[]> {
  const define = defineTool === null ? undefined : (defineTool ?? await loadDefineTool())
  if (typeof define !== 'function') {
    throw new SealedScriptToolError('TOOL_BUILDER_UNAVAILABLE', 'the dsh tool builder is unavailable')
  }
  const tools: SealedToolDefinition[] = []
  for (const spec of specs) {
    try {
      tools.push(await buildSealedScriptTool(spec, deps, define))
    } catch {
      // A single malformed spec must not take down the rest of the sealed script tools.
    }
  }
  return tools
}

export type SealedScriptWarning = (message: string) => void

/**
 * Register one tool per spec and return ONE aggregate disposer. Registration is best-effort: a
 * missing tools service, an unavailable builder, or one bad registration degrades to a redacted
 * warning and a no-op for that item — it never gates the skill provider. The warning text contains
 * no plaintext.
 */
export async function registerSealedScriptTools(
  tools: ToolRuntimeLike | undefined | null,
  specs: readonly SealedScriptSpec[],
  deps: SealedScriptDeps,
  defineTool?: DefineToolLike | null,
  warn?: SealedScriptWarning,
): Promise<() => void> {
  const report: SealedScriptWarning = typeof warn === 'function' ? warn : () => {}
  if (tools === undefined || tools === null || typeof tools.register !== 'function') {
    report('[sealed-skills] the tools service is unavailable; sealed script tools are not registered')
    return () => {}
  }
  const define = defineTool === null ? undefined : (defineTool ?? await loadDefineTool())
  if (typeof define !== 'function') {
    report('[sealed-skills] the dsh tool builder is unavailable; sealed script tools are not registered')
    return () => {}
  }

  const disposers: (() => void)[] = []
  for (const spec of specs) {
    let definition: SealedToolDefinition
    try {
      definition = await buildSealedScriptTool(spec, deps, define)
    } catch {
      report('[sealed-skills] one sealed script tool could not be built; it was skipped')
      continue
    }
    try {
      const dispose = tools.register(definition)
      if (typeof dispose === 'function') disposers.push(dispose)
    } catch {
      report('[sealed-skills] one sealed script tool could not be registered; it was skipped')
    }
  }

  return () => {
    for (const dispose of disposers) {
      try {
        dispose()
      } catch {
        // Best-effort teardown.
      }
    }
    disposers.length = 0
  }
}