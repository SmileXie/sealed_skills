import { describe, expect, it } from 'vitest'
import { PackRegistry } from '../src/registry.js'
import { createSkillProvider } from '../src/provider.js'
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

describe('PackRegistry', () => {
  it('returns an empty list for a missing directory', () => {
    expect(new PackRegistry({ dir: 'definitely-not-here' }).scan()).toEqual([])
  })
})
