import { readFileSync } from 'node:fs'
import { createPublicKey } from 'node:crypto'
import { join } from 'node:path'
import { SealedCore } from './core.js'
import { FileKeystore } from './keystore.js'
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

/** One installed pack: the ciphertext container plus the device-bound license that grants entries. */
export interface SealedPackMount {
  /** Absolute path to a `.sealedpack` container. */
  readonly packPath: string
  /** Absolute path to the Ed25519-signed license binding this pack to this device. */
  readonly licensePath: string
  /** base64url raw Ed25519 public key the pack manifest was signed with. */
  readonly authorPublicKeyB64: string
}

export interface SealedSkillsConfig {
  /** Packs to expose. M1 mounts are explicit; M2 adds server-driven activation. */
  readonly mounts?: SealedPackMount[]
  /** base64url raw Ed25519 public keys trusted to sign licenses (the author key in M1; server keys in M2+). */
  readonly trustedLicenseKeysB64?: string[]
  /** Directory for the M1 file-backed device keystore. Defaults to `$SEALED_HOME` or `<cwd>/.sealed-home`. */
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
 * Cores are built lazily on first use and cached per pack path. A mount whose pack or license
 * is missing, corrupt, or bound to another device is skipped (fail-closed per mount): neither
 * core construction nor `list()` rejects, and the provider reports only the healthy packs.
 * M1 keeps a single process-wide keystore.
 */
export function apply(ctx: SkillsContext, config: SealedSkillsConfig = {}): () => void {
  const mounts = config.mounts ?? []
  const keystore = new FileKeystore({
    dir: config.keystoreDir ?? process.env.SEALED_HOME ?? join(process.cwd(), '.sealed-home'),
  })
  const trustedLicenseKeys = (config.trustedLicenseKeysB64 ?? []).map((key) =>
    createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: key }, format: 'jwk' }))

  const cores = new Map<string, SealedCore>()
  const coreFor = (mount: SealedPackMount): SealedCore => {
    let core = cores.get(mount.packPath)
    if (!core) {
      core = new SealedCore({
        pack: readFileSync(mount.packPath),
        authorPublicKeyB64: mount.authorPublicKeyB64,
        license: readFileSync(mount.licensePath, 'utf8'),
        trustedLicenseKeys,
        keystore,
      })
      cores.set(mount.packPath, core)
    }
    return core
  }

  // Aggregate the mounted packs behind the single `Pick<SealedCore, 'list' | 'readSkill'>` seam.
  const aggregate = {
    async list() {
      const summaries = []
      for (const mount of mounts) {
        try {
          summaries.push(...await coreFor(mount).list())
        } catch {
          // Fail closed for THIS mount only: a missing/corrupt pack, a bad license or an
          // unavailable keystore must never take down list() for the healthy mounts.
        }
      }
      return summaries
    },
    async readSkill(skillName: string) {
      for (const mount of mounts) {
        let core: SealedCore
        try {
          core = coreFor(mount)
          if (!(await core.list()).some((skill) => skill.name === skillName)) continue
        } catch {
          continue
        }
        return core.readSkill(skillName)
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
