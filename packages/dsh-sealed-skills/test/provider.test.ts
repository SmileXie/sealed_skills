import { describe, expect, it } from 'vitest'
import { PackRegistry } from '../src/registry.js'
import { createDshSkillProvider, createSkillProvider } from '../src/provider.js'
import type { SkillDefinition, SkillSummary } from '../src/core.js'

const summary: SkillSummary = { name: 'a', description: 'd', invocation: { modelInvocable: true, userInvocable: true } }
const definition: SkillDefinition = { ...summary, content: 'body' }

const core = {
  list: async () => [summary],
  readSkill: async (name: string) => {
    if (name !== 'a') throw new Error('no such skill')
    return definition
  },
}

describe('createSkillProvider', () => {
  it('reports its provider name', () => {
    expect(createSkillProvider(core).name).toBe('sealed')
  })

  it('lists summaries and loads bodies on demand', async () => {
    const provider = createSkillProvider(core)
    expect(await provider.list()).toEqual([summary])
    expect((await provider.get('a'))?.content).toBe('body')
  })

  it('returns undefined instead of throwing for an unknown skill', async () => {
    expect(await createSkillProvider(core).get('missing')).toBeUndefined()
  })

  it('returns undefined instead of leaking an error when the pack cannot be read', async () => {
    const broken = createSkillProvider({ list: async () => [], readSkill: async () => { throw new Error('LICENSE_EXPIRED') } })
    expect(await broken.get('a')).toBeUndefined()
  })
})

describe('createDshSkillProvider (dsh SkillProvider adapter)', () => {
  it('emits dsh-shaped candidates carrying source, provider, rank and an opaque locator', async () => {
    const provider = createDshSkillProvider(core, { rank: 600 })
    const candidates = await provider.list({})
    expect(Array.isArray(candidates)).toBe(true)
    expect(candidates).toEqual([{
      name: 'a', description: 'd', invocation: { modelInvocable: true, userInvocable: true },
      source: 'custom', provider: 'sealed', rank: 600, locator: { sealedSkill: 'a' },
    }])
  })

  it('loads the body through the locator it emitted and yields undefined for an unknown locator', async () => {
    const provider = createDshSkillProvider(core)
    const candidates = (await provider.list({})) as { locator: unknown }[]
    const loaded = await provider.get(candidates[0] as never, {})
    expect(loaded?.content).toBe('body')
    expect(loaded?.provider).toBe('sealed')
    expect(await provider.get({ name: 'x', locator: 42 } as never, {})).toBeUndefined()
  })

  it('collapses a read failure into undefined rather than leaking the reason', async () => {
    const broken = createDshSkillProvider({ list: async () => [summary], readSkill: async () => { throw new Error('NOT_GRANTED: skill:a:body') } })
    const candidates = (await broken.list({})) as { locator: unknown }[]
    expect(await broken.get(candidates[0] as never, {})).toBeUndefined()
  })

  it('returns no candidates once the caller signal is already aborted', async () => {
    const provider = createDshSkillProvider(core)
    expect(await provider.list({ signal: AbortSignal.abort() })).toEqual([])
  })
})

describe('PackRegistry', () => {
  it('returns an empty list for a missing directory', () => {
    expect(new PackRegistry({ dir: 'definitely-not-here' }).scan()).toEqual([])
  })
})
