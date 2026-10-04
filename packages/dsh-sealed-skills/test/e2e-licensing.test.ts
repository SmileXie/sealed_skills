import { createPublicKey, generateKeyPairSync, randomBytes } from 'node:crypto'
import { mkdtempSync } from 'node:fs'
import type { AddressInfo } from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'
import {
  deriveEntryKey, encodeManifest, entryAad, sealEntry, signManifest, writeContainer,
  type PackEntryMeta, type PackManifest,
} from '@sealed/pack-format'
import { b64u, rawPrivateBytes } from '@sealed/license-format'
import { createApp, loadServerKeys, openStore, serverLicensePublicB64 } from '@sealed/license-server'
import { SealedCore } from '../src/core.js'
import { LicenseClient } from '../src/license-client.js'
import { FileKeystore } from '../src/keystore.js'

const packId = 'com.example.translate'
const version = '1.0.0'
const ADMIN = 'admin-token'
const packRef = { id: packId, version }
const master = randomBytes(32)
const author = generateKeyPairSync('ed25519')
const authorPub = (author.publicKey.export({ format: 'jwk' }) as { x: string }).x

// A minimal sealed pack whose body entry is withheld from the trial set.
function buildPack(): { file: Buffer; manifest: PackManifest } {
  const entries: { id: string; type: PackEntryMeta['type']; body: string }[] = [
    {
      id: 'meta',
      type: 'meta',
      body: JSON.stringify({
        skills: [{
          name: 'translate', description: '翻译',
          invocation: { modelInvocable: true, userInvocable: true },
          entries: ['skill:translate:body'],
        }],
        resources: {},
      }),
    },
    { id: 'skill:translate:body', type: 'text', body: '把用户输入翻译成英文。\n' },
  ]
  const manifest: PackManifest = { pack_id: packId, version, label: '翻译', entry_count: entries.length, entries: [] }
  const chunks = entries.map((entry) => {
    const key = deriveEntryKey(master, packId, version, entry.id)
    const sealed = sealEntry(key, entryAad(packId, version, entry.id), Buffer.from(entry.body, 'utf8'))
    manifest.entries.push({ id: entry.id, type: entry.type, size: sealed.ct.length, trial: entry.id !== 'skill:translate:body' })
    return { id: entry.id, nonce: sealed.nonce, ct: sealed.ct }
  })
  const signature = signManifest(encodeManifest(manifest), author.privateKey)
  return { file: writeContainer({ manifest, chunks, signature }), manifest }
}

function publishBody(manifest: PackManifest) {
  return {
    pack: packRef,
    author_pub: authorPub,
    label: '翻译',
    master_b64: master.toString('base64url'),
    trial_entries: manifest.entries.filter((entry) => entry.trial).map((entry) => entry.id),
    entries: manifest.entries.map((entry) => ({ id: entry.id, type: entry.type, size: entry.size })),
  }
}

let current: { close: () => void } | undefined
afterEach(() => { current?.close(); current = undefined })

async function startServer() {
  const proofKey = generateKeyPairSync('x25519')
  const keys = loadServerKeys({
    SEALED_SERVER_LICENSE_KEY: (generateKeyPairSync('ed25519').privateKey.export({ format: 'jwk' }) as { d: string }).d,
    SEALED_SERVER_PROOF_KEY: rawPrivateBytes(proofKey.privateKey).toString('base64url'),
    SEALED_SERVER_MASTER_KEY: b64u(Buffer.alloc(32, 4)),
  } as NodeJS.ProcessEnv)
  const store = openStore(':memory:')
  const server = createApp({ store, keys, adminToken: ADMIN })
  server.listen(0)
  current = server
  await new Promise<void>((resolve) => server.once('listening', () => resolve()))
  const url = 'http://127.0.0.1:' + (server.address() as AddressInfo).port
  return { url, store, keys, licensePublic: serverLicensePublicB64(keys) }
}

async function publish(url: string, manifest: PackManifest): Promise<void> {
  const response = await fetch(url + '/v1/admin/packs', {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: 'Bearer ' + ADMIN },
    body: JSON.stringify(publishBody(manifest)),
  })
  expect(response.status).toBe(200)
}

async function newClient(url: string, serverProofPubB64: string, licensePubB64: string, homeDir: string): Promise<LicenseClient> {
  const keystore = new FileKeystore({ dir: homeDir })
  await keystore.createDeviceKey()
  const trustedLicenseKeys = [createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: licensePubB64 }, format: 'jwk' })]
  return new LicenseClient({
    serverUrl: url, serverProofPubB64, keystore, homeDir, trustedLicenseKeys,
    retry: { attempts: 2, baseMs: 1, maxMs: 2 },
  })
}

function trustedKeys(licensePubB64: string) {
  return [createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: licensePubB64 }, format: 'jwk' })]
}

describe('M2 licensing end to end', () => {
  it('publishes, activates, decrypts, renews and then fails to renew after a revoke', async () => {
    const { url, store, keys, licensePublic } = await startServer()
    const { file: pack, manifest } = buildPack()
    await publish(url, manifest)
    store.putPurchase({ token: 'purchase-1', sub: 'cust', packId, version, plan: 'pro', seats: 1 })

    const home = mkdtempSync(join(tmpdir(), 'sealed-home-'))
    const client = await newClient(url, keys.proofPublicB64, licensePublic, home)
    const entitlement = await client.activate(packRef, 'purchase-1')
    expect(entitlement.state).toBe('active')
    expect(entitlement.payload.caps).toEqual(['full'])

    const core = new SealedCore({
      pack, license: entitlement.license, keystore: new FileKeystore({ dir: home }),
      trustedLicenseKeys: trustedKeys(licensePublic),
    })
    expect((await core.list()).map((skill) => skill.name)).toEqual(['translate'])
    expect((await core.readSkill('translate')).content).toBe('把用户输入翻译成英文。\n')

    const renewed = await client.renew(packRef, entitlement.license)
    expect(renewed.source).toBe('network')

    const revoked = await fetch(url + '/v1/revoke', {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: 'Bearer ' + ADMIN },
      body: JSON.stringify({ license_id: entitlement.payload.lid }),
    })
    expect((await revoked.json() as { revoked: number }).revoked).toBe(1)
    await expect(client.renew(packRef, renewed.license)).rejects.toMatchObject({ code: 'LICENSE_REVOKED' })
  })

  it('grants a server trial only the trial entries and refuses the rest', async () => {
    const { url, store, keys, licensePublic } = await startServer()
    const { file: pack, manifest } = buildPack()
    await publish(url, manifest)

    const home = mkdtempSync(join(tmpdir(), 'sealed-home-'))
    const client = await newClient(url, keys.proofPublicB64, licensePublic, home)
    const trial = await client.activateTrial(packRef)
    expect(trial.payload.caps).toEqual(['trial'])

    const core = new SealedCore({
      pack, license: trial.license, keystore: new FileKeystore({ dir: home }),
      trustedLicenseKeys: trustedKeys(licensePublic),
    })
    await expect(core.readSkill('translate')).rejects.toMatchObject({ code: 'NOT_GRANTED' })

    const devicePub = (await new FileKeystore({ dir: home }).loadDevicePublicKey())!.toString('base64url')
    expect(store.getTrial(devicePub, packId, version)).toBeDefined()
  })
})
