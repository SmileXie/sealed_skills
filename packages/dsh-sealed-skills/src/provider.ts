import type { SealedCore, SkillDefinition, SkillSummary } from './core.js'

export interface SkillProviderLike {
  readonly name: string
  list(): Promise<SkillSummary[]>
  get(name: string): Promise<SkillDefinition | undefined>
}

/**
 * dsh `SkillProvider` 的适配层。M1 只暴露 `list()` / `get()`：
 * `get()` 把「未授权 / 已过期 / 解密失败」统一折叠为 undefined，避免把包内信息或错误细节泄露给调用方。
 */
export function createSkillProvider(core: Pick<SealedCore, 'list' | 'readSkill'>): SkillProviderLike {
  return {
    name: 'sealed',
    list: () => core.list(),
    async get(name: string) {
      try {
        return await core.readSkill(name)
      } catch {
        return undefined
      }
    },
  }
}
