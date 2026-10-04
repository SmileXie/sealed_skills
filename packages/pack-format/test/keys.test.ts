import { describe, expect, it } from 'vitest'
import { deriveEntryKey, entryAad } from '../src/index.js'

const master = Buffer.alloc(32, 7)

describe('deriveEntryKey', () => {
  it('is deterministic and 32 bytes', () => {
    const a = deriveEntryKey(master, 'com.x.p', '1.0.0', 'meta')
    expect(a.length).toBe(32)
    expect(a.equals(deriveEntryKey(master, 'com.x.p', '1.0.0', 'meta'))).toBe(true)
  })

  it('separates entries, versions and packs', () => {
    const base = deriveEntryKey(master, 'com.x.p', '1.0.0', 'a')
    expect(base.equals(deriveEntryKey(master, 'com.x.p', '1.0.0', 'b'))).toBe(false)
    expect(base.equals(deriveEntryKey(master, 'com.x.p', '1.0.1', 'a'))).toBe(false)
    expect(base.equals(deriveEntryKey(master, 'com.x.q', '1.0.0', 'a'))).toBe(false)
  })
})

describe('entryAad', () => {
  it('is unambiguous across the separator', () => {
    expect(entryAad('p', '1', 'a:b').equals(entryAad('p:1', '', 'a:b'))).toBe(false)
  })
})
