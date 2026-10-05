// Golden-vector generator for the public Sealed Skills formats.
//
// TEST-ONLY. The fixed keys/nonces below exist solely to make the vectors reproducible and
// MUST NOT be used in production. Run with:  node test-vectors/generate.mjs
// Requires the workspace to be built first:  corepack pnpm -r build
import { writeFileSync } from 'node:fs'
import { createPrivateKey, createPublicKey } from 'node:crypto'
import { deriveEntryKey } from '../packages/pack-format/dist/keys.js'
import { entryAad } from '../packages/pack-format/dist/aad.js'
import { sealEntry, openEntry } from '../packages/pack-format/dist/aead.js'
import { wrapEntryKey, unwrapEntryKey } from '../packages/license-format/dist/wrap.js'
import { signLicense, verifyLicense } from '../packages/license-format/dist/token.js'
import { x25519PrivateFromRaw, x25519PublicFromRaw, rawPublicBytes } from '../packages/license-format/dist/x25519.js'

const hex = (b) => Buffer.from(b).toString('hex')
const b64u = (b) => Buffer.from(b).toString('base64url')

// ---- pack-format vectors -------------------------------------------------------
const master = Buffer.from('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f', 'hex')
const packId = 'com.example.translate'
const version = '1.0.0'
const mkNonce = (n) => Buffer.from(Array.from({ length: 12 }, (_, i) => (n + i) & 0xff))

const packCases = [
  { name: 'meta-ascii', entry_id: 'meta', nonce: mkNonce(0x10), plaintext_utf8: '{"name":"translate","version":"1.0.0"}' },
  { name: 'text-unicode', entry_id: 'skill:translate:body', nonce: mkNonce(0x20), plaintext_utf8: '把用户输入翻译成自然、地道的英文。' },
  { name: 'script-multiline', entry_id: 'script:translate:run.mjs', nonce: mkNonce(0x30), plaintext_utf8: 'export function run(input) {\n  return String(input).trim()\n}\n' },
  { name: 'data-empty', entry_id: 'data:params', nonce: mkNonce(0x40), plaintext_utf8: '' },
  { name: 'boundary-1024', entry_id: 'skill:big:body', nonce: mkNonce(0x50), plaintext_utf8: 'A'.repeat(1024) },
]

const packVectors = packCases.map((c) => {
  const ck = deriveEntryKey(master, packId, version, c.entry_id)
  const aad = entryAad(packId, version, c.entry_id)
  const sealed = sealEntry(ck, aad, Buffer.from(c.plaintext_utf8, 'utf8'), c.nonce)
  const roundTrip = openEntry(ck, aad, sealed.nonce, sealed.ct).toString('utf8')
  if (roundTrip !== c.plaintext_utf8) throw new Error('pack vector round-trip failed: ' + c.name)
  return {
    name: c.name,
    pack_id: packId,
    version,
    entry_id: c.entry_id,
    master_hex: hex(master),
    nonce_hex: hex(c.nonce),
    plaintext_utf8: c.plaintext_utf8,
    ck_hex: hex(ck),
    aad_hex: hex(aad),
    ct_hex: hex(sealed.ct),
  }
})

writeFileSync(
  new URL('./pack-format.json', import.meta.url),
  JSON.stringify(
    {
      format: 'sealed-skills/pack-format',
      format_version: 1,
      note: 'TEST-ONLY golden vectors. Fixed keys/nonces; DO NOT USE IN PRODUCTION.',
      vectors: packVectors,
    },
    null,
    2,
  ) + '\n',
  'utf8',
)

// ---- license-format vectors ---------------------------------------------------
const ED25519_PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex')
const signingSeed = Buffer.from('a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf', 'hex')
const signingKey = createPrivateKey({ key: Buffer.concat([ED25519_PKCS8_PREFIX, signingSeed]), format: 'der', type: 'pkcs8' })
const signingPubRaw = (createPublicKey(signingKey).export({ format: 'der', type: 'spki' })).subarray(-32)

const devicePrivRaw = Buffer.from('1111111111111111111111111111111111111111111111111111111111111111', 'hex')
const ephemeralPrivRaw = Buffer.from('2222222222222222222222222222222222222222222222222222222222222222', 'hex')
const devicePriv = x25519PrivateFromRaw(devicePrivRaw)
const devicePubRaw = rawPublicBytes(createPublicKey(devicePriv))
const devicePub = x25519PublicFromRaw(devicePubRaw)
const ephemeralPriv = x25519PrivateFromRaw(ephemeralPrivRaw)

const lid = 'lic_test_0001'
const eid = 'skill:translate:body'
const contentKey = Buffer.from('c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf', 'hex')
const wrapNonce = Buffer.from('f0f1f2f3f4f5f6f7f8f9fafb', 'hex')

const payload = {
  v: 1,
  lid,
  sub: 'trial:11111111',
  pack: { id: packId, version, author_pub: b64u(signingPubRaw) },
  dev: b64u(devicePubRaw),
  iat: 1700000000,
  exp: 1700604800,
  grace_until: 1700864000,
  caps: ['trial'],
  groups: ['trial'],
  keys: [],
  seats: { plan: 'trial', limit: 1 },
}
const grant = wrapEntryKey(payload, eid, contentKey, devicePub, { ephemeralPrivateKey: ephemeralPriv, nonce: wrapNonce })
payload.keys = [grant]
const token = signLicense(payload, signingKey)

// sanity checks before writing
const round = unwrapEntryKey(payload, eid, devicePriv)
if (!round.equals(contentKey)) throw new Error('license vector unwrap failed')
verifyLicense(token, [createPublicKey(signingKey)])

writeFileSync(
  new URL('./license-format.json', import.meta.url),
  JSON.stringify(
    {
      format: 'sealed-skills/license-format',
      format_version: 1,
      note: 'TEST-ONLY golden vectors. Fixed keys/nonces; DO NOT USE IN PRODUCTION.',
      signing_seed_hex: hex(signingSeed),
      signing_public_b64u: b64u(signingPubRaw),
      device_private_hex: hex(devicePrivRaw),
      device_public_b64u: b64u(devicePubRaw),
      ephemeral_private_hex: hex(ephemeralPrivRaw),
      lid,
      eid,
      content_key_hex: hex(contentKey),
      wrap_nonce_hex: hex(wrapNonce),
      payload,
      expected_grant: grant,
      expected_token: token,
    },
    null,
    2,
  ) + '\n',
  'utf8',
)

console.log('wrote pack-format.json vectors=' + packVectors.length)
console.log('wrote license-format.json expected_token_len=' + token.length)