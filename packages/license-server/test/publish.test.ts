import { generateKeyPairSync } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import { b64u, rawPrivateBytes } from '@sealed/license-format'
import { handlePublishPack, loadServerKeys, openStore } from '../src/index.js'

function fixture() {
  const proof = generateKeyPairSync('x25519')
  const keys = loadServerKeys({
    SEALED_SERVER_LICENSE_KEY: (generateKeyPairSync('ed25519').privateKey.export({ format: 'jwk' }) as { d: string }).d,
    SEALED_SERVER_PROOF_KEY: rawPrivateBytes(proof.privateKey).toString('base64url'),
    SEALED_SERVER_MASTER_KEY: b64u(Buffer.alloc(32, 1)),
  } as NodeJS.ProcessEnv)
  return { keys, store: openStore(':memory:') }
}

const body = {
  pack: { id: 'com.example.p', version: '1.0.0' },
  author_pub: 'A'.repeat(43),
  label: '翻译',
  master_b64: Buffer.alloc(32, 3).toString('base64url'),
  trial_entries: ['meta'],
  entries: [{ id: 'meta', type: 'meta', size: 10 }, { id: 'skill:translate:body', type: 'text', size: 20 }],
}

describe('handlePublishPack', () => {
  it('stores the pack and returns a summary', () => {
    const f = fixture()
    const result = handlePublishPack(f.store, f.keys, body, 1000)
    expect(result.status).toBe(200)
    expect(f.store.getPack('com.example.p', '1.0.0')?.trialEntries).toEqual(['meta'])
    expect(f.store.getPack('com.example.p', '1.0.0')?.masterWrapped.startsWith('v1.')).toBe(true)
  })

  it('is idempotent: a repeated publish returns the cached response without a second audit row', () => {
    const f = fixture()
    const first = handlePublishPack(f.store, f.keys, body, 1000)
    const second = handlePublishPack(f.store, f.keys, body, 1001)
    expect(second).toEqual(first)
    expect(f.store.listAudit().filter((a) => a.action === 'publish').length).toBe(1)
  })

  it('rejects a malformed request and a bad master key with a structured 4xx', () => {
    const f = fixture()
    expect(() => handlePublishPack(f.store, f.keys, { ...body, author_pub: 'short' }, 1))
      .toThrowError(expect.objectContaining({ status: 400, code: 'BAD_REQUEST' }))
    expect(() => handlePublishPack(f.store, f.keys, { ...body, master_b64: 'AAAA' }, 1))
      .toThrowError(expect.objectContaining({ status: 400, code: 'BAD_REQUEST' }))
  })
})
