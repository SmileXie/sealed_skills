import { spawnSync } from 'node:child_process'
import { existsSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'

/**
 * Gated self-check for the optional out-of-tree dsh lab (`scripts/dsh-lab.mjs`).
 *
 * The lab installs @deepseek-ai/dsh into a git-ignored `.dsh-lab/`, so like M2's real-harness
 * integration it is opt-in: without SEALED_DSH_LAB=1 (or without an installed lab) this file
 * skips with an explicit reason and never fakes a pass. There is nothing to assert without dsh.
 */
const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..', '..')
const LAB_SCRIPT = join(REPO_ROOT, 'scripts', 'dsh-lab.mjs')
const DSH_BIN = join(REPO_ROOT, '.dsh-lab', 'node_modules', '@deepseek-ai', 'dsh', 'lib', 'bin.js')
const DSH_VERSION = '0.2.0-rc.2'

const requested = process.env.SEALED_DSH_LAB === '1'
const installed = existsSync(DSH_BIN)
const enabled = requested && installed

const skipReason = requested
  ? `the dsh lab is not installed at ${DSH_BIN} (run: node scripts/dsh-lab.mjs --ensure)`
  : 'SEALED_DSH_LAB is not set to 1 (the dsh lab is opt-in)'

function runLab(args: string[]) {
  return spawnSync(process.execPath, [LAB_SCRIPT, ...args], { cwd: REPO_ROOT, encoding: 'utf8' })
}

describe('optional dsh lab (out-of-tree harness)', () => {
  if (!enabled) {
    // Loud, explicit skip: a missing lab is UNVERIFIED, never a pass.
    console.warn(`[dsh-lab] SKIPPED — ${skipReason}`)
    it.skip(`skips because ${skipReason}`, () => {})
    return
  }

  it('reports the pinned dsh version', () => {
    const result = runLab(['--version'])
    expect(result.error).toBeUndefined()
    expect(result.status, result.stderr ?? '').toBe(0)
    expect(result.stdout).toContain(DSH_VERSION)
  })

  it('mounts the sealed plugin in a composed profile with no skipped bundle', () => {
    const result = runLab(['--dump-config'])
    expect(result.error).toBeUndefined()
    expect(result.status, result.stderr ?? '').toBe(0)
    expect(result.stdout).toContain('- id: sealed-skills')
    // The generated profile keeps the keystore inside the lab, never the user's real home.
    expect(result.stdout).toContain('.dsh-lab/sealed')
    expect(result.stderr ?? '').not.toContain('skipping profile bundle')
  })
})