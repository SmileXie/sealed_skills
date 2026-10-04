import { spawnSync } from 'node:child_process'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { zstdCompressSync } from 'node:zlib'
import { describe, expect, it } from 'vitest'

/**
 * Covers the M3 leak gate (`scripts/leak-gate.mjs`).
 *
 * Two claims are pinned here:
 *  1. The byte-wise scanner is NON-VACUOUS: it finds a canary both as raw bytes and inside a real
 *     zstd frame (the `session.jsonl.zstd` surface), and stays silent on a clean file.
 *  2. The whole gate prints exactly `leak-gate: clean` and exits 0 on the default path — i.e.
 *     WITHOUT the opt-in dsh lab. (The real-machine sub-check stays a loud skip/UNVERIFIED here.)
 */
const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..', '..')
const GATE = join(REPO_ROOT, 'scripts', 'leak-gate.mjs')

interface Needle {
  label: string
  needle: Buffer
}
interface GateModule {
  scanBufferForNeedles(buffer: Buffer, needles: Needle[]): { label: string; how: string }[]
  scanFilesForNeedles(files: string[], needles: Needle[]): { file: string; label: string; how: string }[]
  listFiles(root: string): string[]
}

async function loadGate(): Promise<GateModule> {
  return (await import(pathToFileURL(GATE).href)) as unknown as GateModule
}

describe('canary leak gate', () => {
  it('detects a raw and a zstd-compressed canary byte-wise (non-vacuous scanner)', async () => {
    const gate = await loadGate()
    const canary = 'CANARY-' + 'deadbeef'.repeat(4)
    const needles: Needle[] = [{ label: 'canary', needle: Buffer.from(canary, 'utf8') }]
    const dir = mkdtempSync(join(tmpdir(), 'leak-gate-test-'))
    try {
      const rawFile = join(dir, 'raw.bin')
      writeFileSync(rawFile, Buffer.concat([Buffer.from('x'), Buffer.from(canary), Buffer.from('y')]))
      const zstdFile = join(dir, 'session.jsonl.zstd')
      writeFileSync(zstdFile, zstdCompressSync(Buffer.from('{"t":"' + canary + '"}\n')))
      const cleanFile = join(dir, 'clean.txt')
      writeFileSync(cleanFile, 'nothing to see here')

      expect(gate.scanBufferForNeedles(Buffer.from('no canary here'), needles)).toHaveLength(0)
      expect(gate.scanFilesForNeedles([rawFile], needles).some((hit) => hit.how === 'raw')).toBe(true)
      expect(gate.scanFilesForNeedles([zstdFile], needles).some((hit) => hit.how === 'zstd')).toBe(true)
      expect(gate.scanFilesForNeedles([cleanFile], needles)).toHaveLength(0)
      expect(gate.listFiles(dir).length).toBe(3)
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })

  it('prints exactly `leak-gate: clean` and exits 0 without the dsh lab', () => {
    const run = spawnSync(process.execPath, [GATE], {
      cwd: REPO_ROOT,
      env: { ...process.env, SEALED_DSH_LAB: '' },
      encoding: 'utf8',
      timeout: 120_000,
    })
    expect(run.status, run.stderr).toBe(0)
    expect(run.stdout.trim()).toBe('leak-gate: clean')
  })
})