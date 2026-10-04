import { generateKeyPairSync } from 'node:crypto'
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { deriveEntryKey, readContainer } from '@sealed/pack-format'
import { unwrapEntryKey, verifyLicense } from '@sealed/license-format'
import { makeTrialLicense, packSkillDir } from '../src/index.js'

const author = generateKeyPairSync('ed25519')
const device = generateKeyPairSync('x25519')
const master = Buffer.alloc(32, 9)

const dir = mkdtempSync(join(tmpdir(), 'skill-'))
mkdirSync(join(dir, 'scripts'), { recursive: true })
writeFileSync(join(dir, 'SKILL.md'), '---\nname: translate\ndescription: 翻译\n---\n正文\n')
writeFileSync(join(dir, 'scripts/run.py'), 'print(1)\n')

describe('makeTrialLicense', () => {
  it('grants only the trial entries and nothing else', () => {
    const { file, manifest } = packSkillDir(dir, {
      packId: 'com.example.t', version: '1.0.0', label: 't', master, authorPrivateKey: author.privateKey,
      trialEntryIds: ['meta', 'skill:translate:body'],
    })
    const license = makeTrialLicense({ manifest, master, devicePublicKey: device.publicKey, trialEntryIds: ['meta', 'skill:translate:body'], days: 7, signingKey: author.privateKey })
    const payload = verifyLicense(license, [author.publicKey])
    expect(payload.caps).toEqual(['trial'])
    expect(payload.keys.map((k) => k.eid).sort()).toEqual(['meta', 'skill:translate:body'])

    const ck = deriveEntryKey(master, 'com.example.t', '1.0.0', 'meta')
    expect(unwrapEntryKey(payload, 'meta', device.privateKey).equals(ck)).toBe(true)
    expect(() => unwrapEntryKey(payload, 'script:translate:scripts/run.py', device.privateKey)).toThrow('LICENSE_NO_GRANT')
    expect(readContainer(file).manifest.entries.length).toBe(3)
  })

  it('sets exp to days and grace to three more days', () => {
    const { manifest } = packSkillDir(dir, { packId: 'com.example.t2', version: '1.0.0', label: 't', master, authorPrivateKey: author.privateKey, trialEntryIds: ['meta'] })
    const payload = verifyLicense(makeTrialLicense({ manifest, master, devicePublicKey: device.publicKey, trialEntryIds: ['meta'], days: 7, signingKey: author.privateKey, now: 1_000_000 }), [author.publicKey])
    expect(payload.exp - payload.iat).toBe(7 * 86400)
    expect(payload.grace_until - payload.exp).toBe(3 * 86400)
  })
})
