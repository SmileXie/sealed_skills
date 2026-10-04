import { readFileSync } from 'node:fs'
import { createPublicKey } from 'node:crypto'
import { join } from 'node:path'
import { readContainer } from '@sealed/pack-format'
import { SealedCore } from './core.js'
import { FileKeystore } from './keystore.js'
import { LicenseClient, LicenseDenied, type Entitlement } from './license-client.js'
import { createDshSkillProvider, type DshSkillProvider, type DshSkillProviderControl } from './provider.js'

/**
 * dsh entrypoint for the `dsh-sealed-skills` bundle.
 *
 * VERIFICATION: the `SkillProvider` / `SkillProviderControl` /
 * `ctx.skills.registerProvider()` shapes this file targets were verified against the
 * published `@deepseek-ai/dsh-skill@0.0.1-rc.1` type declarations (see provider.ts for
 * the exact file + line map). The git clone of the harness repository failed in this
 * environment, so the *plugin loader* details below are UNVERIFIED — see
 * `docs/sealed-skills/notes/dsh-skill-provider.md`.
 */

/**
 * One installed pack.
 *
 * Provide `licensePath` for an offline, pre-issued license, or `purchaseToken` / `trial`
 * for online activation against the license server. The pack author key is never supplied
 * here: it is read from the signed license (`pack.author_pub`).
 */
export interface SealedPackMount {
  /** Absolute path to a `.sealedpack` container. */
  readonly packPath: string
  /** Absolute path to a signed license binding this pack to this device (offline import). */
  readonly licensePath?: string
  /** Purchase token used to activate online when no cached/offline license exists. */
  readonly purchaseToken?: string
  /** Request a server-issued trial when no cached/offline license exists. */
  readonly trial?: boolean
}

export interface SealedSkillsConfig {
  /** Packs to expose. Each mount is licensed lazily on first use. */
  readonly mounts?: SealedPackMount[]
  /** base64url raw Ed25519 public keys trusted to sign licenses (the license server keys). */
  readonly trustedLicenseKeysB64?: string[]
  /** License server base URL; falls back to `SEALED_SERVER_URL`. */
  readonly serverUrl?: string
  /** base64url raw X25519 public key used for device-proof on renew; falls back to `SEALED_SERVER_PROOF_PUB`. */
  readonly serverProofPubB64?: string
  /** Directory for the file-backed device keystore. Defaults to `$SEALED_HOME` or `<cwd>/.sealed-home`. */
  readonly keystoreDir?: string
  /** Candidate precedence rank. Defaults to 600, the published `BUNDLED_SKILL_RANK`. */
  readonly rank?: number
}

/** The only part of the dsh context surface this plugin depends on. */
export interface SkillsContext {
  readonly skills: {
    registerProvider(create: (control: DshSkillProviderControl) => DshSkillProvider): () => void
  }
}

export const name = 'sealed-skills'
export const inject = ['skills']

/**
 * Register the sealed provider on `ctx.skills` during plugin apply and return the dsh
 * effect disposer so the loader can order teardown.
 *
 * Cores are built lazily on first use (online activation or offline import) and cached per
 * pack path. A mount whose pack is missing/corrupt, whose license cannot be obtained or
 * imported, or that is bound to another device is skipped (fail-closed per mount): neither
 * core construction nor `list()` rejects, and the provider reports only the healthy packs.
 */
export function apply(ctx: SkillsContext, config: SealedSkillsConfig = {}): () => void {
  const mounts = config.mounts ?? []
  const homeDir = config.keystoreDir ?? process.env.SEALED_HOME ?? join(process.cwd(), '.sealed-home')
  const keystore = new FileKeystore({ dir: homeDir })
  const trustedLicenseKeys = (config.trustedLicenseKeysB64 ?? []).map((key) =>
    createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: key }, format: 'jwk' }))
  const client = new LicenseClient({
    serverUrl: config.serverUrl ?? process.env.SEALED_SERVER_URL,
    serverProofPubB64: config.serverProofPubB64 ?? process.env.SEALED_SERVER_PROOF_PUB,
    keystore, homeDir, trustedLicenseKeys,
  })

  const cores = new Map<string, Promise<SealedCore>>()
  const coreFor = (mount: SealedPackMount): Promise<SealedCore> => {
    let pending = cores.get(mount.packPath)
    if (!pending) {
      // Cache the in-flight promise so concurrent callers share one activation, and drop it on
      // failure so a later call can retry (e.g. after the network or a license file is fixed).
      pending = buildCore(mount).catch((error: unknown) => { cores.delete(mount.packPath); throw error })
      cores.set(mount.packPath, pending)
    }
    return pending
  }

  async function buildCore(mount: SealedPackMount): Promise<SealedCore> {
    const pack = readFileSync(mount.packPath)
    const manifest = readContainer(pack).manifest
    const packRef = { id: manifest.pack_id, version: manifest.version }
    let entitlement: Entitlement
    if (mount.licensePath) {
      entitlement = await client.importLicense(readFileSync(mount.licensePath, 'utf8'), packRef)
    } else {
      try {
        entitlement = await client.ensureLicense(packRef)
      } catch (error) {
        if (!(error instanceof LicenseDenied) || error.code !== 'NO_LICENSE') throw error
        if (mount.purchaseToken) entitlement = await client.activate(packRef, mount.purchaseToken)
        else if (mount.trial) entitlement = await client.activateTrial(packRef)
        else throw error
      }
    }
    return new SealedCore({ pack, license: entitlement.license, trustedLicenseKeys, keystore })
  }

  // Aggregate the mounted packs behind the single `Pick<SealedCore, 'list' | 'readSkill'>` seam.
  const aggregate = {
    async list() {
      const summaries = []
      for (const mount of mounts) {
        try {
          summaries.push(...await (await coreFor(mount)).list())
        } catch {
          // Fail closed for THIS mount only: a missing/corrupt pack, an unobtainable license or an
          // unavailable keystore must never take down list() for the healthy mounts.
        }
      }
      return summaries
    },
    async readSkill(skillName: string) {
      for (const mount of mounts) {
        try {
          const core = await coreFor(mount)
          if (!(await core.list()).some((skill) => skill.name === skillName)) continue
          return await core.readSkill(skillName)
        } catch {
          continue
        }
      }
      throw new Error('no such sealed skill')
    },
  }

  // The dsh contract returns the exact Cordis effect disposer; hand it back so the
  // plugin loader can order teardown (unregister provider -> abort signal -> cache drop).
  return ctx.skills.registerProvider((control) =>
    createDshSkillProvider(aggregate, { rank: config.rank, signal: control.signal }))
}

export const plugin = { name, inject, apply }
export default plugin
