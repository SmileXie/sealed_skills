// m2-smoke: end-to-end licensing smoke test.
//
// Runs the real license server in-process (127.0.0.1:0), publishes the demo pack, activates it
// on a fresh device key, decrypts the body from the on-disk ciphertext pack, renews with device
// proof, revokes, and proves the next renewal is refused. Then proves a server trial unlocks only
// the trial entries. Finally asserts the plaintext body never lands in any on-disk artifact.
//
// Preconditions: `corepack pnpm -r build` has produced every package's dist/ output.
import { createPublicKey, generateKeyPairSync, randomBytes } from 'node:crypto'
import { mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { packSkillDir } from '../packages/seal-cli/dist/pack.js'
import { parseSkillMarkdown } from '../packages/seal-cli/dist/frontmatter.js'
import { b64u, rawPrivateBytes } from '../packages/license-format/dist/index.js'
import { createApp, loadServerKeys, openStore, serverLicensePublicB64 } from '../packages/license-server/dist/index.js'
import { FileKeystore, LicenseClient, SealedCore } from '../packages/dsh-sealed-skills/dist/index.js'

const root = new URL('../', import.meta.url)
const home = fileURLToPath(new URL('.sealed-home/m2/', root))
mkdirSync(home, { recursive: true })

const packId = 'com.example.translate'
const version = '1.0.0'
const adminToken = 'smoke-admin-token'
const packRef = { id: packId, version }
const master = randomBytes(32)
const author = generateKeyPairSync('ed25519')
const authorPub = author.publicKey.export({ format: 'jwk' }).x

// 1. Pack the demo skill. The body entry is intentionally NOT part of the trial set.
const { file: pack, manifest } = packSkillDir(fileURLToPath(new URL('demo/translate', root)), {
  packId, version, label: '翻译', master, trialEntryIds: ['meta'], authorPrivateKey: author.privateKey,
})
const packPath = join(home, 'translate.sealedpack')
writeFileSync(packPath, pack)

// 2. Start the license server in-process, on an ephemeral port.
const proofKey = generateKeyPairSync('x25519')
const keys = loadServerKeys({
  SEALED_SERVER_LICENSE_KEY: generateKeyPairSync('ed25519').privateKey.export({ format: 'jwk' }).d,
  SEALED_SERVER_PROOF_KEY: rawPrivateBytes(proofKey.privateKey).toString('base64url'),
  SEALED_SERVER_MASTER_KEY: b64u(Buffer.alloc(32, 7)),
})
const store = openStore(':memory:')
const server = createApp({ store, keys, adminToken })
await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
const url = 'http://127.0.0.1:' + server.address().port
const licensePublic = serverLicensePublicB64(keys)
const trustedLicenseKeys = [createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: licensePublic }, format: 'jwk' })]
const adminHeaders = { 'content-type': 'application/json', authorization: 'Bearer ' + adminToken }

// 3. Publish the pack (admin only) and mint a purchase token.
const published = await fetch(url + '/v1/admin/packs', {
  method: 'POST',
  headers: adminHeaders,
  body: JSON.stringify({
    pack: packRef, author_pub: authorPub, label: '翻译',
    master_b64: master.toString('base64url'),
    trial_entries: manifest.entries.filter((entry) => entry.trial).map((entry) => entry.id),
    entries: manifest.entries.map((entry) => ({ id: entry.id, type: entry.type, size: entry.size })),
  }),
})
if (published.status !== 200) throw new Error('m2-smoke: publish failed with status ' + published.status)
store.putPurchase({ token: 'purchase-smoke', sub: 'smoke-customer', packId, version, plan: 'pro', seats: 1 })

// 4. Activate on this device, decrypt, and read the body back from the on-disk ciphertext pack.
const keystore = new FileKeystore({ dir: home })
await keystore.createDeviceKey()
const client = new LicenseClient({ serverUrl: url, serverProofPubB64: keys.proofPublicB64, keystore, homeDir: home, trustedLicenseKeys })
const entitlement = await client.activate(packRef, 'purchase-smoke')
const core = new SealedCore({ pack: readFileSync(packPath), license: entitlement.license, trustedLicenseKeys, keystore })
if ((await core.readSkill('translate')).content.trim().length === 0) throw new Error('m2-smoke: decrypted an empty skill body')

// 5. Renew (device proof), revoke, then prove the next renewal is refused.
const renewed = await client.renew(packRef, entitlement.license)
if (renewed.source !== 'network') throw new Error('m2-smoke: renew did not use the network')
const revoked = await fetch(url + '/v1/revoke', {
  method: 'POST', headers: adminHeaders, body: JSON.stringify({ license_id: entitlement.payload.lid }),
})
if (revoked.status !== 200 || (await revoked.json()).revoked !== 1) throw new Error('m2-smoke: revoke failed')
let renewalDenied = false
try { await client.renew(packRef, renewed.license) } catch (error) { renewalDenied = error?.code === 'LICENSE_REVOKED' }
if (!renewalDenied) throw new Error('m2-smoke: renewal after revoke was not denied')
console.log('m2-smoke: publish → activate → decrypt → renew → revoke → renew-denied OK')

// 6. A server trial on a second device unlocks only the trial entries.
const trialHome = join(home, 'trial')
const trialKeystore = new FileKeystore({ dir: trialHome })
await trialKeystore.createDeviceKey()
const trialClient = new LicenseClient({ serverUrl: url, serverProofPubB64: keys.proofPublicB64, keystore: trialKeystore, homeDir: trialHome, trustedLicenseKeys })
const trial = await trialClient.activateTrial(packRef)
const trialCore = new SealedCore({ pack: readFileSync(packPath), license: trial.license, trustedLicenseKeys, keystore: trialKeystore })
let nonTrialDenied = false
try { await trialCore.readSkill('translate') } catch (error) { nonTrialDenied = error?.code === 'NOT_GRANTED' }
if (!nonTrialDenied) throw new Error('m2-smoke: trial unlocked a non-trial entry')
console.log('m2-smoke: trial grants only trial entries OK')

server.close()

// 7. Leak check: the plaintext body must not appear in any artifact under .sealed-home.
const sourceBody = parseSkillMarkdown(readFileSync(fileURLToPath(new URL('demo/translate/SKILL.md', root)), 'utf8')).body
const needle = Buffer.from(sourceBody.trim(), 'utf8')
if (needle.length === 0) throw new Error('m2-smoke: derived an empty leak-check needle')
const leaked = collectFiles(home).filter((path) => readFileSync(path).includes(needle))
if (leaked.length > 0) {
  console.error('disk-leak-check: FAILED, plaintext body found in', leaked)
  process.exitCode = 1
} else {
  console.log('disk-leak-check: clean (no plaintext body in .sealed-home/ artifacts)')
}

function collectFiles(dir) {
  const out = []
  for (const name of readdirSync(dir)) {
    const abs = join(dir, name)
    if (statSync(abs).isDirectory()) out.push(...collectFiles(abs))
    else out.push(abs)
  }
  return out
}
