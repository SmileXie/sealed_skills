import { readFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'
import { createPlaintextReveal } from '../src/log-mask.js'
import {
  createSealedPlaintextInvariant,
  findSealedPlaintext,
  installSealedInvariant,
  registerSealedInvariant,
  SEALED_PACKAGE_NAME,
  SEALED_PLAINTEXT_MIN_LENGTH,
  type InvariantFailure,
  type InvariantInstaller,
  type InvariantRegistry,
  type SealedInvariantContext,
} from '../src/invariant.js'
import {
  parsePlaceholder,
  renderPlaceholder,
  sealedRedactedData,
  SEALED_REDACTED,
} from '../src/session-events.js'

const ENTRY = 'skill:translate:body'
const CANARY = 'the quick brown fox jumps over the lazy dog'

class FakeInvariantError extends Error {
  readonly code = 'INVARIANT'
  readonly packageName: string
  constructor(packageName: string, message: string) {
    super(message)
    this.name = 'InvariantError'
    this.packageName = packageName
  }
}

function failFor(packageName: string = SEALED_PACKAGE_NAME): InvariantFailure {
  return (message: string): never => {
    throw new FakeInvariantError(packageName, message)
  }
}

function capturingContext(): {
  ctx: SealedInvariantContext
  listener: () => (session: unknown, event: unknown) => void
} {
  let listener: ((session: unknown, event: unknown) => void) | undefined
  const ctx: SealedInvariantContext = {
    on(name, l) {
      expect(name).toBe('session/event')
      listener = l
      return () => {}
    },
  }
  return { ctx, listener: () => listener! }
}

/** The real `isPlaintext` source: Task 5's reveal cache, read in place (no second copy). */
function canaryCache(): { isPlaintext: (text: string) => boolean } {
  const reveal = createPlaintextReveal()
  reveal.save(ENTRY, CANARY)
  return { isPlaintext: (text) => reveal.contains(text) }
}

function trackingRegistry(): { registry: InvariantRegistry; live: Map<string, InvariantInstaller>; calls: () => number } {
  const live = new Map<string, InvariantInstaller>()
  let calls = 0
  const registry: InvariantRegistry = {
    register(packageName, installer) {
      calls += 1
      if (live.has(packageName)) throw new Error('invariant "' + packageName + '" is already registered')
      live.set(packageName, installer)
      return () => {
        if (live.get(packageName) === installer) live.delete(packageName)
      }
    },
  }
  return { registry, live, calls: () => calls }
}

describe('Task 5 reveal cache as the isPlaintext source', () => {
  it('matches substrings of a cached body and zeroizes on dispose', () => {
    const reveal = createPlaintextReveal()
    reveal.save(ENTRY, CANARY)
    expect(reveal.contains(CANARY)).toBe(true)
    expect(reveal.contains(CANARY.slice(0, 30))).toBe(true)
    expect(reveal.contains('not present anywhere in the body')).toBe(false)
    expect(reveal.contains('')).toBe(false)
    reveal.dispose()
    expect(reveal.contains(CANARY)).toBe(false)
  })
})

describe('findSealedPlaintext', () => {
  it('stays silent on a normal committed tool/result carrying only the placeholder', () => {
    const { text } = renderPlaceholder(ENTRY)
    const { isPlaintext } = canaryCache()
    const event = { type: 'tool/result', seq: 12, data: { message: { id: 'm1', content: [{ type: 'text', text }] } } }
    expect(parsePlaceholder(text)).toHaveLength(1)
    expect(findSealedPlaintext(event, isPlaintext)).toBeUndefined()
  })

  it('stays silent on the sealed/redacted marker itself', () => {
    const { token } = renderPlaceholder(ENTRY)
    const { isPlaintext } = canaryCache()
    const event = { type: SEALED_REDACTED, seq: 13, data: sealedRedactedData(12, ENTRY, token) }
    expect(findSealedPlaintext(event, isPlaintext)).toBeUndefined()
  })

  it('excludes a placeholder even when isPlaintext would match anything', () => {
    const { text } = renderPlaceholder(ENTRY)
    const event = { type: 'tool/result', seq: 1, data: { message: { content: [{ type: 'text', text }] } } }
    expect(findSealedPlaintext(event, () => true)).toBeUndefined()
  })

  it('fires on a forged committed event and names only type/seq, never the body', () => {
    const { isPlaintext } = canaryCache()
    const event = { type: 'tool/result', seq: 42, data: { message: { id: 'm1', content: [{ type: 'text', text: CANARY }] } } }
    const message = findSealedPlaintext(event, isPlaintext)
    expect(message).toBeDefined()
    expect(message).toContain('"tool/result"')
    expect(message).toContain('42')
    expect(message).not.toContain(CANARY)
  })

  it('recurses into nested objects and arrays (positive and negative)', () => {
    const { isPlaintext } = canaryCache()
    const hit = { type: 'tool/result', seq: 7, data: { deep: [{ nested: { text: CANARY } }] } }
    expect(findSealedPlaintext(hit, isPlaintext)).toBeDefined()
    const miss = { type: 'tool/result', seq: 7, data: { deep: [{ nested: { text: 'a short ordinary string' } }] } }
    expect(findSealedPlaintext(miss, isPlaintext)).toBeUndefined()
  })

  it('ignores strings shorter than minLength, but catches them once the floor is cleared', () => {
    const { isPlaintext } = canaryCache()
    const short = CANARY.slice(0, SEALED_PLAINTEXT_MIN_LENGTH - 1)
    const event = { type: 'tool/result', seq: 3, data: { message: { content: [{ type: 'text', text: short }] } } }
    expect(findSealedPlaintext(event, isPlaintext)).toBeUndefined()
    expect(findSealedPlaintext(event, isPlaintext, short.length)).toBeDefined()
  })

  it('never throws and reports nothing on malformed or foreign events', () => {
    const { isPlaintext } = canaryCache()
    const bad: unknown[] = [
      null,
      undefined,
      42,
      'tool/result',
      {},
      { type: 'tool/result' },
      { type: 'tool/result', seq: -1, data: CANARY },
      { type: 'tool/result', seq: 1.5, data: CANARY },
      { seq: 1, data: CANARY },
      { type: 'tool/result', seq: 1, data: undefined },
    ]
    for (const event of bad) {
      expect(() => findSealedPlaintext(event, isPlaintext)).not.toThrow()
      expect(findSealedPlaintext(event, isPlaintext)).toBeUndefined()
    }
    expect(findSealedPlaintext({ type: 'tool/result', seq: 1, data: CANARY }, undefined as never)).toBeUndefined()
  })

  it('does not loop on cyclic data', () => {
    const { isPlaintext } = canaryCache()
    const data: Record<string, unknown> = {}
    data.self = data
    expect(findSealedPlaintext({ type: 'tool/result', seq: 1, data }, isPlaintext)).toBeUndefined()
  })

  it('swallows a throwing isPlaintext', () => {
    const event = { type: 'tool/result', seq: 1, data: { message: { content: [{ type: 'text', text: CANARY }] } } }
    const boom = (): boolean => {
      throw new Error('boom')
    }
    expect(() => findSealedPlaintext(event, boom)).not.toThrow()
    expect(findSealedPlaintext(event, boom)).toBeUndefined()
  })
})

describe('createSealedPlaintextInvariant', () => {
  it('injects the sessions service and subscribes to committed session events', () => {
    const installer = createSealedPlaintextInvariant({ isPlaintext: () => false })
    expect(installer.inject).toEqual(['sessions'])
  })

  it('calls fail with a body-free InvariantError on a forged event', () => {
    const { isPlaintext } = canaryCache()
    const installer = createSealedPlaintextInvariant({ isPlaintext })
    const { ctx, listener } = capturingContext()
    installer(ctx, failFor())
    const event = { type: 'user/message', seq: 9, data: { content: [{ type: 'text', text: CANARY }] } }
    let thrown: unknown
    try {
      listener()(undefined, event)
    } catch (error) {
      thrown = error
    }
    expect(thrown).toBeInstanceOf(FakeInvariantError)
    const invariantError = thrown as FakeInvariantError
    expect(invariantError.code).toBe('INVARIANT')
    expect(invariantError.packageName).toBe(SEALED_PACKAGE_NAME)
    expect(invariantError.message).not.toContain(CANARY)
    expect(invariantError.message).toContain('user/message')
    expect(invariantError.message).toContain('9')
  })

  it('does not throw on the normal placeholder flow', () => {
    const { text } = renderPlaceholder(ENTRY)
    const { isPlaintext } = canaryCache()
    const installer = createSealedPlaintextInvariant({ isPlaintext })
    const { ctx, listener } = capturingContext()
    installer(ctx, failFor())
    const event = { type: 'tool/result', seq: 4, data: { message: { content: [{ type: 'text', text }] } } }
    expect(() => listener()(undefined, event)).not.toThrow()
  })

  it('does not throw on a malformed event or a throwing isPlaintext', () => {
    const installer = createSealedPlaintextInvariant({
      isPlaintext: () => {
        throw new Error('boom')
      },
    })
    const { ctx, listener } = capturingContext()
    installer(ctx, failFor())
    expect(() => listener()(undefined, null)).not.toThrow()
    expect(() => listener()(undefined, { type: 'tool/result', seq: 1, data: { text: CANARY } })).not.toThrow()
  })

  it('is inert when the child context cannot observe events', () => {
    const installer = createSealedPlaintextInvariant({ isPlaintext: () => true })
    expect(() => installer({} as SealedInvariantContext, failFor())).not.toThrow()
  })
})

describe('registerSealedInvariant', () => {
  it('forwards to the registry under the sealed package name and returns the same disposer', () => {
    const calls: { packageName: string; installer: InvariantInstaller }[] = []
    const dispose = (): void => {}
    const registry: InvariantRegistry = {
      register(packageName, installer) {
        calls.push({ packageName, installer })
        return dispose
      },
    }
    const installer = createSealedPlaintextInvariant({ isPlaintext: () => false })
    expect(registerSealedInvariant(registry, installer)).toBe(dispose)
    expect(calls).toEqual([{ packageName: SEALED_PACKAGE_NAME, installer }])
  })
})

describe('installSealedInvariant', () => {
  it('registers exactly once and disposes on teardown', () => {
    const { registry, live } = trackingRegistry()
    const warnings: string[] = []
    const dispose = installSealedInvariant(
      registry,
      createSealedPlaintextInvariant({ isPlaintext: () => false }),
      (message) => warnings.push(message),
    )
    expect(live.size).toBe(1)
    expect(warnings).toEqual([])
    dispose()
    expect(live.size).toBe(0)
  })

  it('is idempotent across a reload: the stale registration is replaced, not duplicated', () => {
    const { registry, live, calls } = trackingRegistry()
    const warnings: string[] = []
    const first = installSealedInvariant(
      registry,
      createSealedPlaintextInvariant({ isPlaintext: () => false }),
      (message) => warnings.push(message),
    )
    const second = installSealedInvariant(
      registry,
      createSealedPlaintextInvariant({ isPlaintext: () => false }),
      (message) => warnings.push(message),
    )
    expect(live.size).toBe(1)
    // 1 successful register + 1 rejected duplicate + 1 successful retry.
    expect(calls()).toBe(3)
    expect(warnings).toEqual([])
    second()
    expect(live.size).toBe(0)
    first()
    expect(live.size).toBe(0)
  })

  it('degrades to a no-op with a redacted warning when the service is absent', () => {
    const warnings: string[] = []
    const dispose = installSealedInvariant(
      undefined,
      createSealedPlaintextInvariant({ isPlaintext: () => false }),
      (message) => warnings.push(message),
    )
    expect(typeof dispose).toBe('function')
    expect(() => dispose()).not.toThrow()
    expect(warnings).toHaveLength(1)
    expect(warnings[0]).not.toContain(CANARY)
  })

  it('never throws when the registry rejects registration outright', () => {
    const registry: InvariantRegistry = {
      register() {
        throw new Error('blocked by the invariants configuration')
      },
    }
    const warnings: string[] = []
    let dispose: (() => void) | undefined
    expect(() => {
      dispose = installSealedInvariant(
        registry,
        createSealedPlaintextInvariant({ isPlaintext: () => false }),
        (message) => warnings.push(message),
      )
    }).not.toThrow()
    expect(typeof dispose).toBe('function')
    expect(() => dispose!()).not.toThrow()
    expect(warnings).toHaveLength(1)
  })
})

describe('package metadata', () => {
  it('adds no @deepseek-ai/dsh* dependency to the package graph', () => {
    const packageJson = JSON.parse(
      readFileSync(resolve(dirname(fileURLToPath(import.meta.url)), '..', 'package.json'), 'utf8'),
    ) as {
      dependencies?: Record<string, string>
      devDependencies?: Record<string, string>
      peerDependencies?: Record<string, string>
      peerDependenciesMeta?: Record<string, { optional?: boolean }>
    }
    for (const section of [packageJson.dependencies ?? {}, packageJson.devDependencies ?? {}]) {
      expect(Object.keys(section).filter((name) => name.startsWith('@deepseek-ai/'))).toEqual([])
    }
    for (const [name, range] of Object.entries(packageJson.peerDependencies ?? {})) {
      if (!name.startsWith('@deepseek-ai/')) continue
      expect(packageJson.peerDependenciesMeta?.[name]?.optional).toBe(true)
      expect(range.length).toBeGreaterThan(0)
    }
  })
})
