import { existsSync, readFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { describe, expect, it } from 'vitest'
import {
  buildSealedScriptTool,
  createSealedScriptTools,
  executeSealedScript,
  inferSealedScriptRuntime,
  leaksSealedSource,
  loadDefineTool,
  parseSealedScriptEntryId,
  registerSealedScriptTools,
  renderSealedScriptResult,
  sealedScriptArgv,
  sealedScriptProgram,
  sealedScriptToolName,
  SealedScriptToolError,
  SEALED_SCRIPT_MAX_OUTPUT_BYTES,
  SEALED_SCRIPT_TOOL_PREFIX,
  type ConfinedArgv,
  type DefineToolLike,
  type SandboxPolicy,
  type SealedChildProcessLike,
  type SealedScriptDeps,
  type SealedScriptResult,
  type SealedScriptSpec,
  type SealedScriptToolOptions,
  type SealedSpawnLike,
  type ToolRuntimeLike,
} from '../src/tool-runtime.js'

/**
 * Task 7 unit coverage. The hard guarantee under test is that the decrypted script SOURCE never
 * leaves stdin: not on argv, not in a temp file, not in a log line or an error message. The child
 * process and the sandbox are injected, so every assertion is deterministic and offline; a few
 * final cases drive the REAL `node` binary and the REAL dsh `defineTool` (lab-gated).
 */

const POLICY: SandboxPolicy = { mode: 'read-only', workspaceRoot: '/workspace' }
const SPEC: SealedScriptSpec = { name: 'translate', entryId: 'script:translate:run.mjs', runtime: 'node', policy: POLICY }
const SOURCE = 'export const n = 41\nconsole.log(JSON.stringify({ n: n + 1 }))\n'

interface RecordedCall {
  readonly command: string
  readonly args: string[]
  readonly cwd: string
  stdin: string | undefined
}

interface FakeSpawnOptions {
  readonly stdout?: string
  readonly stderr?: string
  readonly exitCode?: number
  readonly autoClose?: boolean
  readonly throwOnSpawn?: string
  readonly emitError?: string
}

function fakeSpawn(options: FakeSpawnOptions = {}): { spawn: SealedSpawnLike; calls: RecordedCall[]; kills: () => number } {
  const calls: RecordedCall[] = []
  let kills = 0
  const spawn: SealedSpawnLike = (command, args, spawnOptions) => {
    if (options.throwOnSpawn !== undefined) throw new Error(options.throwOnSpawn)
    const call: RecordedCall = { command, args: [...args], cwd: spawnOptions.cwd, stdin: undefined }
    calls.push(call)
    const data: Record<'stdout' | 'stderr', ((chunk: unknown) => void)[]> = { stdout: [], stderr: [] }
    const errors: ((error: Error) => void)[] = []
    const closes: ((code: number | null, signal: string | null) => void)[] = []
    const child = {
      stdin: {
        end(value?: unknown): void {
          call.stdin = value === undefined
            ? undefined
            : (Buffer.isBuffer(value) ? value.toString('utf8') : String(value))
          if (options.emitError !== undefined) {
            for (const listener of errors) listener(new Error(options.emitError))
            return
          }
          if (options.stdout !== undefined) for (const listener of data.stdout) listener(options.stdout)
          if (options.stderr !== undefined) for (const listener of data.stderr) listener(options.stderr)
          if (options.autoClose !== false) {
            queueMicrotask(() => { for (const listener of closes) listener(options.exitCode ?? 0, null) })
          }
        },
        on(): unknown { return child },
      },
      stdout: {
        on(_event: 'data', listener: (chunk: unknown) => void): unknown { data.stdout.push(listener); return child },
      },
      stderr: {
        on(_event: 'data', listener: (chunk: unknown) => void): unknown { data.stderr.push(listener); return child },
      },
      kill(): boolean {
        kills += 1
        queueMicrotask(() => { for (const listener of closes) listener(null, 'SIGKILL') })
        return true
      },
      on(event: string, listener: (...args: never[]) => void): unknown {
        if (event === 'error') errors.push(listener as unknown as (error: Error) => void)
        else closes.push(listener as unknown as (code: number | null, signal: string | null) => void)
        return child
      },
    }
    return child as unknown as SealedChildProcessLike
  }
  return { spawn, calls, kills: () => kills }
}

function baseDeps(overrides: Partial<SealedScriptDeps> = {}): SealedScriptDeps {
  return {
    readEntry: async () => Buffer.from(SOURCE),
    confine: async (argv): Promise<ConfinedArgv> => ({ argv: [...argv], enforcement: 'full' }),
    ...overrides,
  }
}

function canaryError(): Error {
  return new Error('boom CANARY-body-do-not-log-me-1234567890 ' + SOURCE)
}

describe('executeSealedScript — source never leaves stdin', () => {
  it('delivers the source on stdin only, never in argv and never through a temp path', async () => {
    const { spawn, calls } = fakeSpawn({ stdout: 'translated\n' })
    const result = await executeSealedScript(baseDeps({ spawn }), SPEC, ['hola'])

    expect(result).toEqual({ ok: true, stdout: 'translated\n', stderr: '', exitCode: 0 })
    expect(calls).toHaveLength(1)
    expect(calls[0].command).toBe('node')
    expect(calls[0].args).toEqual(['--input-type=module', '-', 'hola'])
    expect(calls[0].cwd).toBe('/workspace')
    expect(calls[0].stdin).toBe(sealedScriptProgram('node', SOURCE))
    expect(calls[0].stdin).toContain(SOURCE)

    const argvText = [calls[0].command, ...calls[0].args].join(' ')
    expect(argvText).not.toContain('export const n')
    expect(argvText).not.toMatch(/tmp|sealed-script/i)
  })

  it('never touches the filesystem from the runtime module itself', () => {
    const source = readFileSync(fileURLToPath(new URL('../src/tool-runtime.ts', import.meta.url)), 'utf8')
    expect(source).toMatch(/from 'node:child_process'/)
    expect(source).not.toMatch(/\b(writeFile|writeFileSync|createWriteStream|mkdtemp|mkdtempSync|tmpdir|openSync|appendFile|createTemp)\b/)
    expect(source).not.toMatch(/from 'node:fs'/)
  })

  it('zeroizes the decrypted source buffer after a successful run', async () => {
    const buffer = Buffer.from(SOURCE)
    const { spawn } = fakeSpawn({ stdout: 'ok' })
    await executeSealedScript(baseDeps({ readEntry: async () => buffer, spawn }), SPEC)
    expect(buffer.every((byte) => byte === 0)).toBe(true)
  })

  it('zeroizes the source even when the sandbox refuses', async () => {
    const buffer = Buffer.from(SOURCE)
    const result = await executeSealedScript(baseDeps({
      readEntry: async () => buffer,
      confine: async () => { throw Object.assign(new Error('no backend'), { code: 'SANDBOX_UNAVAILABLE' }) },
    }), SPEC)
    expect(result.ok).toBe(false)
    expect(buffer.every((byte) => byte === 0)).toBe(true)
  })

  it('returns a structured, plaintext-free refusal when the sandbox is unavailable', async () => {
    const result = await executeSealedScript(baseDeps({
      confine: async () => { throw Object.assign(canaryError(), { code: 'SANDBOX_UNAVAILABLE', name: 'SandboxUnavailableError' }) },
    }), SPEC)
    expect(result).toEqual({ ok: false, reason: 'sandbox-unavailable', message: expect.any(String) })
    if (!result.ok) {
      expect(result.message).not.toContain('CANARY')
      expect(result.message).not.toContain('export const n')
    }
  })

  it('refuses an empty argv from confine instead of silently running', async () => {
    const { spawn, calls } = fakeSpawn()
    const result = await executeSealedScript(baseDeps({
      spawn,
      confine: async () => ({ argv: [], enforcement: 'full' }) as unknown as ConfinedArgv,
    }), SPEC)
    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.reason).toBe('sandbox-unavailable')
    expect(calls).toHaveLength(0)
  })

  it('refuses a non-string argv element from confine', async () => {
    const { spawn, calls } = fakeSpawn()
    const result = await executeSealedScript(baseDeps({
      spawn,
      confine: async () => ({ argv: ['node', 7], enforcement: 'full' }) as unknown as ConfinedArgv,
    }), SPEC)
    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.reason).toBe('sandbox-unavailable')
    expect(calls).toHaveLength(0)
  })

  it('refuses a partial-enforcement confinement (conservative, never a weaker boundary)', async () => {
    const { spawn, calls } = fakeSpawn()
    const result = await executeSealedScript(baseDeps({
      spawn,
      confine: async (argv) => ({ argv: [...argv], enforcement: 'partial' }),
    }), SPEC)
    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.reason).toBe('sandbox-not-enforcing')
      expect(result.message).not.toContain('export const n')
    }
    expect(calls).toHaveLength(0)
  })

  it('never echoes source or entry text when readEntry fails', async () => {
    const result = await executeSealedScript(baseDeps({ readEntry: async () => { throw canaryError() } }), SPEC)
    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.reason).toBe('entry-unavailable')
      expect(result.message).not.toContain('CANARY')
      expect(result.message).not.toContain('export const n')
    }
  })

  it('never echoes source or error text when spawn fails', async () => {
    const { spawn } = fakeSpawn({ throwOnSpawn: 'spawn boom CANARY ' + SOURCE })
    const result = await executeSealedScript(baseDeps({ spawn }), SPEC)
    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.reason).toBe('spawn-failed')
      expect(result.message).not.toContain('CANARY')
      expect(result.message).not.toContain('spawn boom')
    }
  })

  it('never echoes a child error event message', async () => {
    const { spawn } = fakeSpawn({ emitError: 'child boom CANARY ' + SOURCE })
    const result = await executeSealedScript(baseDeps({ spawn }), SPEC)
    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.reason).toBe('spawn-failed')
      expect(result.message).not.toContain('CANARY')
    }
  })

  it('kills the child and reports a timeout', async () => {
    const { spawn, kills } = fakeSpawn({ autoClose: false })
    const result = await executeSealedScript(baseDeps({ spawn }), { ...SPEC, timeoutMs: 20 })
    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.reason).toBe('timeout')
    expect(kills()).toBeGreaterThanOrEqual(1)
  })

  it('reports aborted without reading the entry when the signal is already aborted', async () => {
    let read = false
    const controller = new AbortController()
    controller.abort()
    const result = await executeSealedScript(baseDeps({ readEntry: async () => { read = true; return Buffer.from(SOURCE) } }), SPEC, [], controller.signal)
    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.reason).toBe('aborted')
    expect(read).toBe(false)
  })

  it('withholds a stdout that echoes a source line (injected canary, detector proof)', async () => {
    const { spawn } = fakeSpawn({ stdout: 'preamble\n' + SOURCE.trim() + '\nmore\n' })
    const result = await executeSealedScript(baseDeps({ spawn }), SPEC)
    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.reason).toBe('output-redacted')
      expect(result.message).not.toContain('export const n')
      expect('stdout' in result).toBe(false)
      expect('stderr' in result).toBe(false)
    }
    expect(renderSealedScriptResult(result)).not.toContain('export const n')
  })

  it('withholds a stderr that echoes a source window', async () => {
    const { spawn } = fakeSpawn({ stderr: 'oops\n' + SOURCE.slice(0, 40) + '\n' })
    const result = await executeSealedScript(baseDeps({ spawn }), SPEC)
    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.reason).toBe('output-redacted')
  })

  it('leaksSealedSource only fires on real source material', () => {
    expect(leaksSealedSource('nothing here', SOURCE)).toBe(false)
    expect(leaksSealedSource('x' + SOURCE.trim() + 'y', SOURCE)).toBe(true)
    expect(leaksSealedSource(SOURCE.slice(0, 40), SOURCE)).toBe(true)
    expect(leaksSealedSource('a short line', 'a\n')).toBe(false)
    expect(leaksSealedSource('stderr text', SOURCE)).toBe(false)
  })

  it('treats any Node [evalN] code-frame locator as a leak (structural rule)', () => {
    // Node only emits an [evalN]:<line> locator when it echoes script context, so this rule refuses
    // even an echoed line far below the 16-char threshold (a short syntax-error line).
    expect(leaksSealedSource('file:///tmp/[eval1]:6\nconst x = = 2\n', 'x')).toBe(true)
    expect(leaksSealedSource('    at file:///tmp/[eval3]:12:1\n', 'x')).toBe(true)
    expect(leaksSealedSource('[eval1]:1\n', 'x')).toBe(true)
    expect(leaksSealedSource('no locator here', 'x')).toBe(false)
    expect(leaksSealedSource('', 'x')).toBe(false)
  })

  it('reports output-limit when the child floods a stream', async () => {
    const { spawn } = fakeSpawn({ stdout: 'x'.repeat(SEALED_SCRIPT_MAX_OUTPUT_BYTES + 1) })
    const result = await executeSealedScript(baseDeps({ spawn }), SPEC)
    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.reason).toBe('output-limit')
  })

  it('honors a nonzero exit code as a completed run (not an infra refusal)', async () => {
    const { spawn } = fakeSpawn({ stderr: 'nope', exitCode: 3 })
    const result = await executeSealedScript(baseDeps({ spawn }), SPEC)
    expect(result).toEqual({ ok: true, stdout: '', stderr: 'nope', exitCode: 3 })
  })

  it('runs the python runtime as ["python3","-"]', async () => {
    const { spawn, calls } = fakeSpawn()
    await executeSealedScript(baseDeps({ spawn }), { ...SPEC, runtime: 'python' })
    expect(calls[0].command).toBe('python3')
    expect(calls[0].args).toEqual(['-'])
  })
})

describe('entry id helpers', () => {
  it('parses script entry ids and rejects foreign shapes', () => {
    expect(parseSealedScriptEntryId('script:translate:run.mjs')).toEqual({ skillName: 'translate', path: 'run.mjs' })
    expect(parseSealedScriptEntryId('script:a:nested/dir/b.py')).toEqual({ skillName: 'a', path: 'nested/dir/b.py' })
    expect(parseSealedScriptEntryId('script:a:b/c:d')).toEqual({ skillName: 'a', path: 'b/c:d' })
    expect(parseSealedScriptEntryId('skill:translate:body')).toBeUndefined()
    expect(parseSealedScriptEntryId('script:nocolon')).toBeUndefined()
    expect(parseSealedScriptEntryId('script:name:')).toBeUndefined()
  })

  it('derives deterministic sealed_script_* names', () => {
    expect(sealedScriptToolName('script:translate:run.mjs')).toBe(SEALED_SCRIPT_TOOL_PREFIX + 'translate_run_mjs')
    expect(sealedScriptToolName('script:a:b/c d.py')).toBe(SEALED_SCRIPT_TOOL_PREFIX + 'a_b_c_d_py')
    expect(sealedScriptToolName('script:x:run.py').startsWith(SEALED_SCRIPT_TOOL_PREFIX)).toBe(true)
    expect(sealedScriptToolName('script:translate:run.mjs')).not.toBe('run_code')
  })

  it('infers the runtime from the entry path', () => {
    expect(inferSealedScriptRuntime('script:x:run.py')).toBe('python')
    expect(inferSealedScriptRuntime('script:x:RUN.PY')).toBe('python')
    expect(inferSealedScriptRuntime('script:x:run.mjs')).toBe('node')
    expect(inferSealedScriptRuntime('script:x:run.js')).toBe('node')
  })

  it('builds argv with the source separator before any model argument', () => {
    expect(sealedScriptArgv('node', ['a'])).toEqual(['node', '--input-type=module', '-', 'a'])
    expect(sealedScriptArgv('python')).toEqual(['python3', '-'])
  })

  it('renders results without echoing anything secret', () => {
    expect(renderSealedScriptResult({ ok: true, stdout: 'hi\n', stderr: '', exitCode: 0 })).toBe('hi')
    expect(renderSealedScriptResult({ ok: true, stdout: '', stderr: 'warn', exitCode: 2 })).toContain('(exit code 2)')
    expect(renderSealedScriptResult({ ok: false, reason: 'timeout', message: 'the sealed script exceeded its time limit' }))
      .toBe('The sealed script did not run (timeout): the sealed script exceeded its time limit')
  })
})

describe('tool definition production', () => {
  function fakeDefineTool(captured: SealedScriptToolOptions[]): DefineToolLike {
    return (options) => {
      captured.push(options)
      return {
        name: options.name,
        description: options.description,
        parameters: options.parameters,
        output: options.output,
        execute: options.execute,
      }
    }
  }

  it('registers under sealed_script_* (never run_code) and delegates to the sandboxed core', async () => {
    const captured: SealedScriptToolOptions[] = []
    const { spawn, calls } = fakeSpawn({ stdout: 'translated' })
    const tool = await buildSealedScriptTool(SPEC, baseDeps({ spawn }), fakeDefineTool(captured))

    expect(tool.name).toBe(SEALED_SCRIPT_TOOL_PREFIX + 'translate_run_mjs')
    expect(tool.name).not.toBe('run_code')
    // dsh DefineToolOptions has no presentation/mode field; we must not pass a dead key.
    expect('presentation' in captured[0]).toBe(false)
    expect('mode' in captured[0]).toBe(false)
    expect(captured[0].description).toContain('translate')

    const value = await tool.execute({ input: 'hola' }, { signal: new AbortController().signal })
    expect(value).toEqual({ ok: true, stdout: 'translated', stderr: '', exitCode: 0 })
    expect(calls[0].args).toEqual(['--input-type=module', '-', 'hola'])
  })

  it('omits the argv element when no input is supplied', async () => {
    const { spawn, calls } = fakeSpawn()
    const tool = await buildSealedScriptTool(SPEC, baseDeps({ spawn }), fakeDefineTool([]))
    await tool.execute({}, { signal: new AbortController().signal })
    expect(calls[0].args).toEqual(['--input-type=module', '-'])
  })

  it('createSealedScriptTools skips an unbuildable spec without taking down the rest', async () => {
    const define: DefineToolLike = (options) => {
      if (options.name.includes('bad')) throw new Error('bad schema')
      return { name: options.name, description: options.description, parameters: options.parameters, output: options.output, execute: options.execute }
    }
    const bad: SealedScriptSpec = { ...SPEC, entryId: 'script:translate:bad.mjs' }
    const tools = await createSealedScriptTools([SPEC, bad], baseDeps(), define)
    expect(tools.map((tool) => tool.name)).toEqual([SEALED_SCRIPT_TOOL_PREFIX + 'translate_run_mjs'])
  })

  it('loadDefineTool never throws and reports the builder as absent or callable', async () => {
    const loaded = await loadDefineTool()
    expect(loaded === undefined || typeof loaded === 'function').toBe(true)
  })
})

describe('registration', () => {
  const OTHER: SealedScriptSpec = { name: 'translate', entryId: 'script:translate:extra.py', runtime: 'python', policy: POLICY }

  function fakeRuntime(): { tools: ToolRuntimeLike; names: string[]; disposed: number[] } {
    const names: string[] = []
    const disposed: number[] = []
    let index = 0
    const tools: ToolRuntimeLike = {
      register(definition) {
        const id = index++
        names.push(definition.name)
        return () => { disposed.push(id) }
      },
    }
    return { tools, names, disposed }
  }

  it('registers one tool per spec and returns a single aggregate disposer', async () => {
    const { tools, names, disposed } = fakeRuntime()
    const dispose = await registerSealedScriptTools(tools, [SPEC, OTHER], baseDeps(), async (options) => ({
      name: options.name, description: options.description, parameters: options.parameters,
      output: options.output, execute: options.execute,
    }))
    expect(names).toEqual([SEALED_SCRIPT_TOOL_PREFIX + 'translate_run_mjs', SEALED_SCRIPT_TOOL_PREFIX + 'translate_extra_py'])
    dispose()
    expect(disposed).toEqual([0, 1])
  })

  it('keeps going when one registration throws, with a plaintext-free warning', async () => {
    const warnings: string[] = []
    let registrations = 0
    const tools: ToolRuntimeLike = {
      register() {
        registrations += 1
        if (registrations === 1) throw new Error('duplicate tool CANARY ' + SOURCE)
        return () => {}
      },
    }
    const define: DefineToolLike = (options) => ({
      name: options.name, description: options.description, parameters: options.parameters,
      output: options.output, execute: options.execute,
    })
    const dispose = await registerSealedScriptTools(tools, [SPEC, OTHER], baseDeps(), define, (message) => warnings.push(message))
    expect(registrations).toBe(2)
    expect(warnings.length).toBeGreaterThanOrEqual(1)
    expect(warnings.join(' ')).not.toContain('CANARY')
    expect(warnings.join(' ')).not.toContain('export const n')
    expect(() => dispose()).not.toThrow()
  })

  it('degrades to a redacted no-op when the tools service is unavailable', async () => {
    const warnings: string[] = []
    const dispose = await registerSealedScriptTools(undefined, [SPEC], baseDeps(), null, (message) => warnings.push(message))
    expect(typeof dispose).toBe('function')
    expect(() => dispose()).not.toThrow()
    expect(warnings).toHaveLength(1)
    expect(warnings[0]).toMatch(/tools service is unavailable/)
  })

  it('degrades when the dsh tool builder is unavailable', async () => {
    const warnings: string[] = []
    const { tools, names } = fakeRuntime()
    const dispose = await registerSealedScriptTools(tools, [SPEC], baseDeps(), null, (message) => warnings.push(message))
    expect(names).toEqual([])
    expect(warnings[0]).toMatch(/tool builder is unavailable/)
    expect(() => dispose()).not.toThrow()
    await expect(buildSealedScriptTool(SPEC, baseDeps(), null)).rejects.toBeInstanceOf(SealedScriptToolError)
  })
})

describe('real child process (node --input-type=module -)', () => {
  const REAL_SPEC: SealedScriptSpec = {
    ...SPEC,
    policy: { mode: 'read-only', workspaceRoot: process.cwd() },
    timeoutMs: 20_000,
  }

  function runReal(source: string, argv: readonly string[] = []): Promise<SealedScriptResult> {
    return executeSealedScript(
      {
        readEntry: async () => Buffer.from(source),
        confine: async (confined): Promise<ConfinedArgv> => ({ argv: [...confined], enforcement: 'full' }),
      },
      REAL_SPEC,
      argv,
    )
  }

  it('executes the stdin program as ESM, receives the argument on argv, and zeroizes the source', async () => {
    const source = 'export const n = 41\nconsole.log(JSON.stringify({ n: n + 1, arg: process.argv[2] }))\n'
    const buffer = Buffer.from(source)
    const result = await executeSealedScript(
      {
        readEntry: async () => buffer,
        confine: async (confined): Promise<ConfinedArgv> => ({ argv: [...confined], enforcement: 'full' }),
      },
      REAL_SPEC,
      ['hello'],
    )
    expect(result.ok).toBe(true)
    if (result.ok) {
      expect(result.exitCode).toBe(0)
      expect(JSON.parse(result.stdout)).toEqual({ n: 42, arg: 'hello' })
    }
    expect(buffer.every((byte) => byte === 0)).toBe(true)
  })

  it('leaves a normal successful script unaffected by the prelude', async () => {
    const result = await runReal('console.log(2 + 40)\n')
    expect(result).toEqual({ ok: true, stdout: '42\n', stderr: '', exitCode: 0 })
  })

  it('keeps import declarations working after the prelude', async () => {
    const result = await runReal("import { sep } from 'node:path'\nconsole.log(sep.length > 0)\n")
    expect(result.ok).toBe(true)
    if (result.ok) {
      expect(result.stdout.trim()).toBe('true')
      expect(result.exitCode).toBe(0)
    }
  })

  it('keeps a runtime throw body-free (prelude replaces the code frame)', async () => {
    const canary = 'CANARY-throw-line-do-not-log-1234567890'
    const source = 'const KEY = "' + canary + '"\nthrow new Error("boom")\n'
    const result = await runReal(source)
    expect(JSON.stringify(result)).not.toContain(canary)
    expect(renderSealedScriptResult(result)).not.toContain(canary)
    // The prelude turns the throw into a fixed, body-free diagnostic with exit 1.
    expect(result.ok).toBe(true)
    if (result.ok) {
      expect(result.exitCode).toBe(1)
      expect(result.stderr).toContain('diagnostics were withheld')
      expect(result.stderr).not.toContain('KEY')
      expect(result.stdout).toBe('')
    }
  })

  it('refuses a SYNTAX error whose code frame echoes a source line', async () => {
    const canary = 'CANARY-syntax-line-do-not-log-1234567890'
    const source = 'const x = 1\nconst ' + canary + ' = = 2\n'
    const result = await runReal(source)
    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.reason).toBe('output-redacted')
      expect(result.message).not.toContain(canary)
    }
    expect(JSON.stringify(result)).not.toContain(canary)
    expect(renderSealedScriptResult(result)).not.toContain(canary)
  })

  it('refuses a script that deliberately prints a >=32-char literal from its own source', async () => {
    const canary = 'CANARY-intentional-echo-1234567890ABCDEF'
    const source = 'process.stdout.write("' + canary + '\n")\n'
    const result = await runReal(source)
    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.reason).toBe('output-redacted')
    expect(JSON.stringify(result)).not.toContain(canary)
    expect(renderSealedScriptResult(result)).not.toContain(canary)
  })

  it('refuses a SHORT (<=15-char) syntax-error line via the structural code-frame rule', async () => {
    // The offending line here is only 12 chars trimmed: the >=16-char line rule and the 32-char
    // window rule both miss it, so only the structural [evalN] signal can catch Node's code frame.
    const canary = 'SECRET2'
    const result = await runReal('"' + canary + '" = 1\n')
    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.reason).toBe('output-redacted')
      expect(result.message).not.toContain(canary)
    }
    expect(JSON.stringify(result)).not.toContain(canary)
    expect(renderSealedScriptResult(result)).not.toContain(canary)
  })

  it('keeps a SHORT-line runtime ReferenceError body-free (prelude catches it first)', async () => {
    const canary = 'SECRET3'
    const result = await runReal(canary + '\n')
    expect(result.ok).toBe(true)
    if (result.ok) {
      expect(result.exitCode).toBe(1)
      expect(result.stderr).toContain('diagnostics were withheld')
      expect(result.stdout).toBe('')
    }
    expect(JSON.stringify(result)).not.toContain(canary)
    expect(renderSealedScriptResult(result)).not.toContain(canary)
  })

  it('conservatively refuses a NORMAL script that prints a literal [evalN]:<line> locator', async () => {
    // Documented conservative false positive: the structural rule cannot tell a real Node code-frame
    // locator from a script that prints one. Withholding output is the fail-closed choice.
    const result = await runReal('console.log("[eval1]:1")\n')
    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.reason).toBe('output-redacted')
    expect(JSON.stringify(result)).not.toContain('[eval1]:1')
    expect(renderSealedScriptResult(result)).not.toContain('[eval1]:1')
  })

  it('exits promptly when a throwing script holds a live handle (no timeout hang)', async () => {
    // Regression for I2: the prelude handlers must terminate, not merely set exitCode, or a live
    // handle (setInterval) keeps the loop alive until the tool timeout.
    const started = Date.now()
    const result = await runReal('setInterval(() => {}, 1000)\nthrow new Error("boom")\n')
    const elapsed = Date.now() - started
    expect(elapsed).toBeLessThan(2000)
    const timedOut = !result.ok && result.reason === 'timeout'
    expect(timedOut).toBe(false)
    expect(result.ok).toBe(true)
    if (result.ok) expect(result.exitCode).toBe(1)
  })
})

describe('dependency hygiene', () => {
  const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..', '..')

  it('keeps every @deepseek-ai peer optional and the lockfile free of deepseek-ai', () => {
    const pkg = JSON.parse(readFileSync(fileURLToPath(new URL('../package.json', import.meta.url)), 'utf8')) as {
      dependencies?: Record<string, string>
      peerDependencies?: Record<string, string>
      devDependencies?: Record<string, string>
      peerDependenciesMeta?: Record<string, { optional?: boolean }>
    }
    const dsh = Object.keys({ ...pkg.dependencies, ...pkg.peerDependencies, ...pkg.devDependencies })
      .filter((name) => name.startsWith('@deepseek-ai/'))
    expect(dsh.length).toBeGreaterThan(0)
    for (const name of dsh) expect(pkg.peerDependenciesMeta?.[name]?.optional).toBe(true)
    expect(readFileSync(join(REPO_ROOT, 'pnpm-lock.yaml'), 'utf8')).not.toMatch(/deepseek-ai/)
  })

  it('never statically imports a dsh module from the runtime source', () => {
    const source = readFileSync(fileURLToPath(new URL('../src/tool-runtime.ts', import.meta.url)), 'utf8')
    expect(source).not.toMatch(/^\s*import[^\n]*from\s+['"]@deepseek-ai/m)
  })
})

// --- Gated real-machine proof against the published dsh tool builder ---------------------------

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..', '..')
const LAB_TOOLS = join(REPO_ROOT, '.dsh-lab', 'node_modules', '@deepseek-ai', 'dsh-tools', 'lib', 'index.js')
const requested = process.env.SEALED_DSH_LAB === '1'
const labAvailable = requested && existsSync(LAB_TOOLS)
const labSkipReason = requested
  ? `the dsh lab is not installed at ${join(REPO_ROOT, '.dsh-lab')} (run: node scripts/dsh-lab.mjs --ensure)`
  : 'SEALED_DSH_LAB is not set to 1 (the dsh lab is opt-in)'

describe('sealed script tool on the real dsh tool builder (out-of-tree lab)', () => {
  if (!labAvailable) {
    // Loud, explicit skip: a missing lab is UNVERIFIED, never a pass.
    console.warn(`[dsh-tool-runtime] SKIPPED — ${labSkipReason}`)
    it.skip(`skips because ${labSkipReason}`, () => {})
    return
  }

  it('produces a definition the real defineTool accepts, validates, and executes', async () => {
    const mod = (await import(pathToFileURL(LAB_TOOLS).href)) as {
      defineTool: DefineToolLike
      ToolArgsError: new (...args: unknown[]) => Error
    }
    const tool = await buildSealedScriptTool({ ...SPEC, policy: { mode: 'read-only', workspaceRoot: process.cwd() } }, baseDeps(), mod.defineTool)
    expect(tool.name).toBe(SEALED_SCRIPT_TOOL_PREFIX + 'translate_run_mjs')

    const value = (await tool.execute({ input: 'hi' }, { signal: new AbortController().signal })) as { ok?: boolean; stdout?: string }
    expect(value.ok).toBe(true)
    expect(String(value.stdout)).toContain('42')

    await expect(tool.execute({ input: 5 }, { signal: new AbortController().signal })).rejects.toBeInstanceOf(mod.ToolArgsError)
  })
})
