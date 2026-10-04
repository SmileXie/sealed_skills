import { generateKeyPairSync, randomBytes } from 'node:crypto'
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { packSkillDir } from '../packages/seal-cli/dist/pack.js'
import { parseSkillMarkdown } from '../packages/seal-cli/dist/frontmatter.js'
import { makeTrialLicense } from '../packages/seal-cli/dist/trial.js'
import { FileKeystore, x25519PublicFromRaw } from '../packages/dsh-sealed-skills/dist/keystore.js'
import { SealedCore } from '../packages/dsh-sealed-skills/dist/core.js'

const root = new URL('../', import.meta.url)
const home = fileURLToPath(new URL('.sealed-home/', root))
mkdirSync(home, { recursive: true })

const author = generateKeyPairSync('ed25519')
const master = randomBytes(32)
const trialEntryIds = ['meta', 'skill:translate:body']

const { file, manifest } = packSkillDir(fileURLToPath(new URL('demo/translate', root)), {
  packId: 'com.example.translate', version: '1.0.0', label: '翻译', master, trialEntryIds,
  authorPrivateKey: author.privateKey,
})

const keystore = new FileKeystore({ dir: home })
await keystore.createDeviceKey()
const devicePublicKey = x25519PublicFromRaw(await keystore.loadDevicePublicKey())
const license = makeTrialLicense({
  manifest, master, devicePublicKey, trialEntryIds, days: 7, signingKey: author.privateKey,
})

// Persist only the ciphertext pack and the device-bound license, then load both back from disk.
const packPath = join(home, 'translate.sealedpack')
const licensePath = join(home, 'translate.license')
writeFileSync(packPath, file)
writeFileSync(licensePath, license, 'utf8')

const core = new SealedCore({
  pack: readFileSync(packPath),
  authorPublicKeyB64: author.publicKey.export({ format: 'jwk' }).x,
  license: readFileSync(licensePath, 'utf8'),
  trustedLicenseKeys: [author.publicKey],
  keystore,
})

console.log('skills:', await core.list())
console.log('content:', (await core.readSkill('translate')).content)

// Leak check: derive the plaintext body from the author's source dir, then assert it never
// appears in the on-disk runtime artifacts. Deriving it here keeps this script free of any
// second plaintext copy of the packed body.
const sourceBody = parseSkillMarkdown(
  readFileSync(fileURLToPath(new URL('demo/translate/SKILL.md', root)), 'utf8'),
).body
const needle = Buffer.from(sourceBody.trim(), 'utf8')
if (needle.length === 0) throw new Error('smoke: derived an empty leak-check needle')
const artifacts = [packPath, licensePath, join(home, 'device.json')]
const leaked = artifacts.filter((path) => readFileSync(path).includes(needle))
if (leaked.length > 0) {
  console.error('disk-leak-check: FAILED, plaintext body found in', leaked)
  process.exitCode = 1
} else {
  console.log('disk-leak-check: clean (no plaintext body in .sealed-home/ artifacts)')
}
