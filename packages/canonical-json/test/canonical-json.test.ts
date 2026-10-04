import { describe, expect, it } from 'vitest'
import { canonicalJson, CanonicalJsonError } from '../src/index.js'

describe('canonicalJson', () => {
  it('sorts object keys by UTF-16 code units', () => {
    expect(canonicalJson({ b: 1, a: 2, A: 3 })).toBe('{"A":3,"a":2,"b":1}')
  })

  it('serializes nested structures without whitespace', () => {
    expect(canonicalJson({ z: [1, true, null], a: { y: 'x' } })).toBe('{"a":{"y":"x"},"z":[1,true,null]}')
  })

  it('drops undefined properties but rejects undefined inside arrays', () => {
    expect(canonicalJson({ a: undefined, b: 1 })).toBe('{"b":1}')
    expect(() => canonicalJson([undefined])).toThrow(CanonicalJsonError)
  })

  it('rejects non-integer numbers', () => {
    expect(() => canonicalJson(1.5)).toThrow(CanonicalJsonError)
    expect(() => canonicalJson(2 ** 53)).toThrow(CanonicalJsonError)
  })

  it('keeps unicode literal and escapes control characters', () => {
    expect(canonicalJson({ s: '译\n' })).toBe('{"s":"译\\n"}')
  })
})