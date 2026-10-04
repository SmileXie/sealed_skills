import type { SealedCore, SkillDefinition, SkillSummary } from './core.js'

/**
 * M1 core-facing seam: the minimal provider surface the smoke path and tests consume.
 * `get()` collapses "not granted / expired / failed to decrypt" into `undefined` so a
 * caller cannot distinguish (and therefore cannot probe) why a skill is unavailable.
 */
export interface SkillProviderLike {
  readonly name: string
  list(): Promise<SkillSummary[]>
  get(name: string): Promise<SkillDefinition | undefined>
}

export function createSkillProvider(core: Pick<SealedCore, 'list' | 'readSkill'>): SkillProviderLike {
  return {
    name: 'sealed',
    // Spec §7.3: the provider degrades instead of throwing. In M1 the skill NAMES live only in
    // the encrypted `meta` entry, so an unauthorized/expired license cannot honestly surface any
    // name — an empty list is the truthful degradation. (M2 can show the cleartext manifest label.)
    async list() {
      try {
        return await core.list()
      } catch {
        return []
      }
    },
    async get(name: string) {
      try {
        return await core.readSkill(name)
      } catch {
        return undefined
      }
    },
  }
}

// --- dsh `SkillProvider` adapter -------------------------------------------------
//
// The types below mirror the REAL published dsh service contract. They were verified
// from the npm tarball `@deepseek-ai/dsh-skill@0.0.1-rc.1` (fetched from registry.npmjs.org),
// inside `package/lib/types/index.d.ts`:
//
//   L44-59   SkillSummary            { name, description, whenToUse?, invocation, source, provider, resourceBase? }
//   L61-70   SkillCandidate          extends SkillSummary { rank, locator, path?, metadata? }
//   L72-79   SkillDefinition         extends SkillSummary { content, path?, metadata? }
//   L88-104  SkillLookupOptions      { cwd?, signal? } / SkillViewOptions { scope? }
//   L154-159 SkillCatalogSnapshot    { skills, complete }
//   L161-166 SkillProviderObservation{ candidates, complete }
//   L168-188 SkillProvider           { name; list(options); get(candidate, options) }
//   L190-195 SkillProviderControl    { signal, invalidate }
//   L249     SkillService.registerProvider(create: (control) => SkillProvider): () => void
//
// They are re-declared structurally instead of importing `@deepseek-ai/dsh-skill`, so this
// package keeps no dependency on dsh and the adapter stays unit-testable in isolation.
// The git clone of the harness repository failed in this environment (network reset), so
// the surface is verified against the published artifact rather than the source checkout.

export interface DshSkillInvocationPolicy {
  readonly modelInvocable: boolean
  readonly userInvocable: boolean
}

export interface DshSkillSummary {
  readonly name: string
  readonly description: string
  readonly whenToUse?: string
  readonly invocation: DshSkillInvocationPolicy
  readonly source: string
  readonly provider: string
}

export interface DshSkillCandidate extends DshSkillSummary {
  readonly rank: number
  readonly locator: unknown
}

export interface DshSkillDefinition extends DshSkillSummary {
  readonly content: string
}

export interface DshSkillLookupOptions {
  readonly cwd?: string
  readonly signal?: AbortSignal
}

export interface DshSkillProviderObservation {
  readonly candidates: readonly DshSkillCandidate[]
  readonly complete: boolean
}

export interface DshSkillProvider {
  readonly name: string
  readonly list: (options: DshSkillLookupOptions) => Promise<readonly DshSkillCandidate[] | DshSkillProviderObservation>
  readonly get: (candidate: DshSkillCandidate, options: DshSkillLookupOptions) => Promise<DshSkillDefinition | undefined>
}

export interface DshSkillProviderControl {
  readonly signal: AbortSignal
  readonly invalidate: () => void
}

/** Marker stored in `SkillCandidate.locator`; dsh hands the opaque value back to `get()`. */
interface SealedLocator {
  readonly sealedSkill: string
}

function locatorName(locator: unknown): string | undefined {
  if (locator === null || typeof locator !== 'object') return undefined
  const name = (locator as SealedLocator).sealedSkill
  return typeof name === 'string' ? name : undefined
}

/**
 * Adapt a `SealedCore` to the dsh `SkillProvider` contract.
 *
 * - Candidates never carry a `path` (and therefore no `resourceBase`): sealed skills are
 *   virtual and only exist decrypted in memory.
 * - `get()` accepts the opaque locator it emitted and re-reads through the core, folding
 *   authorization and decryption failures into `undefined` instead of leaking a reason.
 */
export function createDshSkillProvider(core: Pick<SealedCore, 'list' | 'readSkill'>, opts: {
  rank?: number
  source?: string
  signal?: AbortSignal
} = {}): DshSkillProvider {
  const rank = opts.rank ?? 600
  const source = opts.source ?? 'custom'
  const aborted = (options: DshSkillLookupOptions) => Boolean(opts.signal?.aborted || options.signal?.aborted)
  return {
    name: 'sealed',
    async list(options: DshSkillLookupOptions) {
      if (aborted(options)) return []
      let summaries: SkillSummary[]
      try {
        summaries = await core.list()
      } catch {
        // Same §7.3 degradation as `createSkillProvider`: never reject the dsh list() call.
        return []
      }
      return summaries.map((skill): DshSkillCandidate => ({
        name: skill.name,
        description: skill.description,
        ...(skill.whenToUse === undefined ? {} : { whenToUse: skill.whenToUse }),
        invocation: skill.invocation,
        source,
        provider: 'sealed',
        rank,
        locator: { sealedSkill: skill.name } satisfies SealedLocator,
      }))
    },
    async get(candidate: DshSkillCandidate, options: DshSkillLookupOptions) {
      if (aborted(options)) return undefined
      const skillName = locatorName(candidate.locator)
      if (skillName === undefined) return undefined
      try {
        const skill = await core.readSkill(skillName)
        return {
          name: skill.name,
          description: skill.description,
          ...(skill.whenToUse === undefined ? {} : { whenToUse: skill.whenToUse }),
          invocation: skill.invocation,
          source,
          provider: 'sealed',
          content: skill.content,
        }
      } catch {
        return undefined
      }
    },
  }
}
