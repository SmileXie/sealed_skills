import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { apply, inject, name, type SkillsContext } from '../src/plugin.js'
import type { DshSkillProvider, DshSkillProviderControl } from '../src/provider.js'

function fakeContext(): { ctx: SkillsContext; provider: () => DshSkillProvider } {
  let registered: DshSkillProvider | undefined
  const ctx: SkillsContext = {
    skills: {
      registerProvider(create: (control: DshSkillProviderControl) => DshSkillProvider) {
        registered = create({ signal: new AbortController().signal, invalidate: () => {} })
        return () => {}
      },
    },
  }
  return { ctx, provider: () => registered! }
}

function freshKeystoreDir(): string {
  return mkdtempSync(join(tmpdir(), 'sealed-plugin-'))
}

describe('sealed-skills plugin', () => {
  it('declares the dsh plugin metadata', () => {
    expect(name).toBe('sealed-skills')
    expect(inject).toContain('skills')
  })

  it('registers a sealed provider on ctx.skills synchronously during apply', () => {
    const { ctx, provider } = fakeContext()
    apply(ctx, { mounts: [], trustedLicenseKeysB64: [], keystoreDir: freshKeystoreDir() })
    expect(provider().name).toBe('sealed')
  })

  it('reports no candidates when nothing is mounted', async () => {
    const { ctx, provider } = fakeContext()
    apply(ctx, { mounts: [], trustedLicenseKeysB64: [], keystoreDir: freshKeystoreDir() })
    expect(await provider().list({})).toEqual([])
  })
})
