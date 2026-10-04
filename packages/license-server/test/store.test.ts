import { describe, expect, it } from 'vitest'
import { openStore, ServerError } from '../src/index.js'

function store() { return openStore(':memory:') }

describe('Store', () => {
  it('round-trips a pack record', () => {
    const s = store()
    s.putPack({ packId: 'com.example.p', version: '1.0.0', label: '翻译', authorPub: 'A'.repeat(43), masterWrapped: 'wrapped', trialEntries: ['meta'], entries: [{ id: 'meta', type: 'meta', size: 10 }] })
    expect(s.getPack('com.example.p', '1.0.0')?.label).toBe('翻译')
    expect(s.getPack('com.example.p', '1.0.0')?.trialEntries).toEqual(['meta'])
    expect(s.getPack('com.example.p', '2.0.0')).toBeUndefined()
    s.close()
  })

  it('treats a repeated trial as a conflict', () => {
    const s = store()
    s.putTrial('dev1', 'p', '1', 'lic_t1')
    expect(() => s.putTrial('dev1', 'p', '1', 'lic_t2')).toThrow(ServerError)
    expect(s.getTrial('dev1', 'p', '1')?.licenseId).toBe('lic_t1')
    s.close()
  })

  it('reports a replayed nonce as a conflict', () => {
    const s = store()
    expect(s.insertNonce('lic_1', 'n1', 1000)).toBe(true)
    expect(s.insertNonce('lic_1', 'n1', 1001)).toBe(false)
    expect(s.insertNonce('lic_1', 'n2', 1002)).toBe(true)
    s.close()
  })

  it('counts seats per subject+pack and releases them', () => {
    const s = store()
    s.putSeat({ sub: 'cust', packId: 'p', version: '1', devicePub: 'd1', licenseId: 'l1' })
    s.putSeat({ sub: 'cust', packId: 'p', version: '1', devicePub: 'd2', licenseId: 'l2' })
    s.putSeat({ sub: 'other', packId: 'p', version: '1', devicePub: 'd3', licenseId: 'l3' })
    expect(s.countSeats('cust', 'p', '1')).toBe(2)
    s.deleteSeat('cust', 'p', '1', 'd1')
    expect(s.countSeats('cust', 'p', '1')).toBe(1)
    s.deleteSeatsForSubject('cust')
    expect(s.countSeats('cust', 'p', '1')).toBe(0)
    s.close()
  })

  it('stores licenses and flips the revoked flag', () => {
    const s = store()
    s.putLicense({ licenseId: 'l1', sub: 'cust', packId: 'p', version: '1', devicePub: 'd1', caps: ['full'], plan: 'pro', seatLimit: 2, iat: 1, exp: 2, graceUntil: 3, revoked: false })
    expect(s.getLicenseForDevice('p', '1', 'd1')?.licenseId).toBe('l1')
    s.markRevoked('l1')
    expect(s.getLicense('l1')?.revoked).toBe(true)
    expect(s.getLicenseForDevice('p', '1', 'd1')).toBeUndefined()
    s.close()
  })

  it('appends audit entries and expires nonces', () => {
    const s = store()
    s.appendAudit({ at: 5, action: 'activate', actor: 'server', subject: 'l1', detail: 'ok' })
    s.insertNonce('l1', 'old', 1)
    s.pruneNonces(0, 999)
    expect(s.listAudit().length).toBe(1)
    expect(s.insertNonce('l1', 'old', 1000)).toBe(true)
    s.close()
  })
})
