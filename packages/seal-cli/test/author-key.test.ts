import { createPublicKey, sign as edSign, verify as edVerify } from 'node:crypto'
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { AuthorKeyError, generateAuthorKey, loadAuthorKey, saveAuthorKey } from '../src/index.js'

function freshPath(): string {
  return join(mkdtempSync(join(tmpdir(), 'author-')), 'author.key.json')
}

describe('author key file', () => {
  it('round-trips a generated key through disk and signs/verifies', () => {
    const path = freshPath()
    const key = generateAuthorKey()
    saveAuthorKey(path, key)
    const loaded = loadAuthorKey(path)
    expect(loaded.publicKeyB64).toBe(key.publicKeyB64)
    const message = Buffer.from('sealed', 'utf8')
    const signature = edSign(null, message, loaded.privateKey)
    expect(edVerify(null, message, createPublicKey(loaded.privateKey), signature)).toBe(true)
  })

  it('writes BOM-free JSON with base64url raw Ed25519 keys', () => {
    const path = freshPath()
    saveAuthorKey(path, generateAuthorKey())
    const bytes = readFileSync(path)
    expect(bytes[0]).not.toBe(0xef)
    const parsed = JSON.parse(bytes.toString('utf8')) as Record<string, unknown>
    expect(parsed.v).toBe(1)
    expect(parsed.alg).toBe('ed25519')
    expect(parsed.pub).toMatch(/^[A-Za-z0-9_-]{43}$/)
    expect(parsed.priv).toMatch(/^[A-Za-z0-9_-]{43}$/)
  })

  it('rejects a key file whose private and public halves disagree', () => {
    const path = freshPath()
    saveAuthorKey(path, generateAuthorKey())
    const doc = JSON.parse(readFileSync(path, 'utf8')) as Record<string, unknown>
    doc.pub = generateAuthorKey().publicKeyB64
    writeFileSync(path, JSON.stringify(doc))
    expect(() => loadAuthorKey(path)).toThrow(AuthorKeyError)
  })

  it('rejects a malformed key file', () => {
    const path = freshPath()
    writeFileSync(path, 'not json')
    expect(() => loadAuthorKey(path)).toThrow(AuthorKeyError)
  })
})