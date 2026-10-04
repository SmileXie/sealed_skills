import { createPublicKey, generateKeyPairSync } from 'node:crypto'
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { verifyLicense } from '@sealed/license-format'
import { CliError, encodeMasterFile, loadAuthorKey, main, parseArgs, parseMasterFile } from '../src/index.js'

function tmp(): string {
  return mkdtempSync(join(tmpdir(), 'cli-'))
}

function skillDir(): string {
  const dir = tmp()
  writeFileSync(join(dir, 'SKILL.md'), '---\nname: translate\ndescription: 翻译\n---\n正文\n')
  return dir
}

function capture(): { io: { stdout: (s: string) => void; stderr: (s: string) => void }; out: () => string; err: () => string } {
  let out = ''
  let err = ''
  return { io: { stdout: (s) => { out += s }, stderr: (s) => { err += s } }, out: () => out, err: () => err }
}

function rawPublicB64(key: ReturnType<typeof generateKeyPairSync>['publicKey']): string {
  return (key.export({ format: 'jwk' }) as { x: string }).x
}

describe('parseArgs', () => {
  it('parses keygen with an explicit output path', () => {
    expect(parseArgs(['keygen', '-o', 'author.key.json'])).toEqual({ kind: 'keygen', out: 'author.key.json' })
  })

  it('defaults the keygen output path', () => {
    expect(parseArgs(['keygen'])).toEqual({ kind: 'keygen', out: 'author.key.json' })
  })

  it('parses pack with required options and a trial list', () => {
    expect(parseArgs(['pack', 'dir', '-o', 'x.sealedpack', '--pack-id', 'com.example.x', '--version', '1.0.0', '--label', 'x', '--key', 'k.json', '--trial', 'meta,skill:x:body']))
      .toEqual({ kind: 'pack', dir: 'dir', out: 'x.sealedpack', packId: 'com.example.x', version: '1.0.0', label: 'x', key: 'k.json', trial: ['meta', 'skill:x:body'] })
  })

  it('parses inspect with and without an author key', () => {
    expect(parseArgs(['inspect', 'x.sealedpack'])).toEqual({ kind: 'inspect', pack: 'x.sealedpack' })
    expect(parseArgs(['inspect', 'x.sealedpack', '--author-pub', 'ABC'])).toEqual({ kind: 'inspect', pack: 'x.sealedpack', authorPub: 'ABC' })
  })

  it('parses trial with a day count', () => {
    expect(parseArgs(['trial', 'x.sealedpack', '--master', 'x.master.json', '--device-pub', 'DEV', '--days', '7', '--key', 'k.json']))
      .toEqual({ kind: 'trial', pack: 'x.sealedpack', master: 'x.master.json', devicePub: 'DEV', days: 7, key: 'k.json' })
  })

  it('rejects an unknown command', () => {
    expect(() => parseArgs(['nope'])).toThrow(CliError)
  })

  it('rejects pack without --pack-id', () => {
    expect(() => parseArgs(['pack', 'dir', '-o', 'x.sealedpack', '--version', '1', '--label', 'x', '--key', 'k.json'])).toThrow(/--pack-id/)
  })

  it('rejects a non-integer --days', () => {
    expect(() => parseArgs(['trial', 'x.sealedpack', '--master', 'm', '--device-pub', 'DEV', '--days', 'seven', '--key', 'k.json'])).toThrow(/--days/)
  })
})

describe('master.json', () => {
  it('round-trips the pack master key', () => {
    const text = encodeMasterFile({ pack_id: 'com.example.p', version: '1.0.0' }, Buffer.alloc(32, 7))
    const parsed = parseMasterFile(text)
    expect(parsed.packId).toBe('com.example.p')
    expect(parsed.version).toBe('1.0.0')
    expect(parsed.master.equals(Buffer.alloc(32, 7))).toBe(true)
  })

  it('rejects a master key that is not 32 bytes', () => {
    expect(() => parseMasterFile(JSON.stringify({ v: 1, pack_id: 'p', version: '1', master: 'AAAA' }))).toThrow()
  })
})

describe('seal cli in-process', () => {
  it('runs keygen -> pack -> inspect -> trial end to end', async () => {
    const home = tmp()
    const keyPath = join(home, 'author.key.json')
    const packPath = join(home, 'translate.sealedpack')
    const masterPath = packPath + '.master.json'
    const licensePath = join(home, 'translate.license')
    const devicePub = rawPublicB64(generateKeyPairSync('x25519').publicKey)

    expect(await main(['keygen', '-o', keyPath], capture().io)).toBe(0)
    expect(await main(['pack', skillDir(), '-o', packPath, '--pack-id', 'com.example.translate', '--version', '1.0.0', '--label', '翻译', '--key', keyPath, '--trial', 'meta,skill:translate:body'], capture().io)).toBe(0)
    expect(existsSync(packPath)).toBe(true)
    expect(existsSync(masterPath)).toBe(true)

    const key = loadAuthorKey(keyPath)
    const inspect = capture()
    expect(await main(['inspect', packPath, '--author-pub', key.publicKeyB64], inspect.io)).toBe(0)
    expect(inspect.out()).toContain('"signatureValid": true')
    expect(inspect.out()).toContain('"pack_id": "com.example.translate"')

    expect(await main(['trial', packPath, '--master', masterPath, '--device-pub', devicePub, '--days', '7', '--key', keyPath, '-o', licensePath], capture().io)).toBe(0)
    const payload = verifyLicense(readFileSync(licensePath, 'utf8'), [createPublicKey(key.privateKey)])
    expect(payload.dev).toBe(devicePub)
    expect(payload.keys.map((k) => k.eid).sort()).toEqual(['meta', 'skill:translate:body'])
  })

  it('prints an actionable error and writes nothing when SKILL.md has no frontmatter', async () => {
    const home = tmp()
    const keyPath = join(home, 'author.key.json')
    const badDir = tmp()
    writeFileSync(join(badDir, 'SKILL.md'), 'no frontmatter here')
    const packPath = join(home, 'bad.sealedpack')

    expect(await main(['keygen', '-o', keyPath], capture().io)).toBe(0)
    const failed = capture()
    expect(await main(['pack', badDir, '-o', packPath, '--pack-id', 'p', '--version', '1', '--label', 'l', '--key', keyPath], failed.io)).toBe(1)
    expect(failed.err()).toMatch(/frontmatter/i)
    expect(existsSync(packPath)).toBe(false)
  })
})