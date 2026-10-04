> **SUPERSEDED (M3 recon):** the seam facts here were verified against `@deepseek-ai/dsh-skill@0.0.1-rc.1`. See `docs/sealed-skills/notes/dsh-0.2-seams.md` for the current 0.2.x contract. Kept for history.
>
> **M3 Task 1 measured addendum:** re-verified against an installed `@deepseek-ai/dsh@0.2.0-rc.2` on this machine — the cordis session service is `sessions`, the projection API is `sessions.registerMessageProjection(...)`, and the `SessionEventMap` augmentation specifier is `@deepseek-ai/dsh-session/types`. See §9 of the superseding note for file:line evidence. The skill seam drifted only in `SkillService`→`SkillRegistry` and `SkillSummary.path?`; neither breaks our adapter.

# 真实 dsh `SkillProvider` 契约与我们的适配

- 状态：**接口签名 = 已验证（verified）**；**插件加载/接线 = 已验证（M3 Task 3，见 §6）**；**完整 headless profile 启动 = 未验证（需模型凭证）**
- 日期：2026-10-04
- 验证对象：`@deepseek-ai/dsh-skill@0.0.1-rc.1`（npm 发布产物）
- 相关实现：`packages/dsh-sealed-skills/src/provider.ts`（适配层）、`packages/dsh-sealed-skills/src/plugin.ts`（插件入口）

## 1. 验证方式（以及为什么不是 clone）

任务要求先 `git clone --depth 1 https://github.com/deepseek-ai/deepseek-harness .dsh-checkout`，再打开
`packages/skill/skill/src/index.ts` 核对签名。**本机该 clone 失败**：

```text
fatal: unable to access 'https://github.com/deepseek-ai/deepseek-harness/': Recv failure: Connection was reset
```

对 `https://github.com/...` 的直接 HTTP 访问亦超时，docs 站点 `deepseek-harness.github.io` 同样不可达。
因此**未能核对源码仓库**（即 `packages/skill/skill/src/index.ts` 本身）。

但 **npm registry（`registry.npmjs.org`）可达**，而 dsh 的 skill 服务是已发布到 npm 的正式产物。
我们下载了 tarball 并解包，直接读取其 TypeScript 声明文件：

```text
包：@deepseek-ai/dsh-skill@0.0.1-rc.1
文件：package/lib/types/index.d.ts        （tarball 内路径，源仓库对应 packages/skill/skill/src/index.ts 的 .d.ts 产物）
另参阅：@deepseek-ai/cordis@4.0.4 / package/lib/types/registry.d.ts
```

> 结论：**接口签名是「已验证」的（来源为官方 npm 发布产物）**，但**不是**通过源码仓库核对，且
> **插件如何被 dsh 加载、配置如何注入，仍未验证**。下文所有行号均指上述 tarball 内的
> `package/lib/types/index.d.ts`。

## 2. 实测签名（逐条，含文件路径 + 行号）

来源：`@deepseek-ai/dsh-skill@0.0.1-rc.1` → `package/lib/types/index.d.ts`

- L16 `export declare const BUNDLED_SKILL_RANK = 600;`
- L44-59 `interface SkillSummary { name: string; description: string; whenToUse?: string; invocation: SkillInvocationPolicy; source: SkillSource; provider: string; resourceBase?: SkillResourceBase }`
- L61-70 `interface SkillCandidate extends SkillSummary { rank: number; locator: unknown; path?: string; metadata?: Readonly<Record<string, unknown>> }`
- L72-79 `interface SkillDefinition extends SkillSummary { content: string; path?: string; metadata?: Readonly<Record<string, unknown>> }`
- L81-86 `type SkillRegistration = Omit<SkillDefinition, 'invocation' | 'provider'> & { invocation?: SkillInvocationPolicy; provider?: string }`
- L88-95 `interface SkillLookupOptions { cwd?: string | undefined; signal?: AbortSignal | undefined }`
- L100-104 `interface SkillViewOptions extends SkillLookupOptions { scope?: ScopeKey | undefined }`
- L154-159 `interface SkillCatalogSnapshot { skills: SkillSummary[]; complete: boolean }`
- L161-166 `interface SkillProviderObservation { candidates: readonly SkillCandidate[]; complete: boolean }`
- L168-188
  ```ts
  interface SkillProvider {
    readonly name: string
    readonly list: (options: SkillLookupOptions) => Promise<readonly SkillCandidate[] | SkillProviderObservation>
    readonly get: (candidate: SkillCandidate, options: SkillLookupOptions) => Promise<SkillDefinition | undefined>
  }
  ```
- L190-195 `interface SkillProviderControl { readonly signal: AbortSignal; readonly invalidate: () => void }`
- L201-204 `declare module '@deepseek-ai/cordis' { interface Context { skills: SkillService } }`
- L249 `registerProvider(create: (control: SkillProviderControl) => SkillProvider): () => void`（`SkillService` 方法）
- L259 `register(skill: SkillRegistration): () => void`
- L276 `snapshot(options?: SkillViewOptions): Promise<SkillCatalogSnapshot>`
- L268 `list(options?: SkillViewOptions): Promise<SkillSummary[]>`（按 name 排序）
- L286 `get(name: string, options?: SkillViewOptions): Promise<SkillDefinition | undefined>`

来源：`@deepseek-ai/cordis@4.0.4` → `package/lib/types/registry.d.ts`

- `Plugin.Base { name?: string; Config?: StandardSchemaV1; inject?: Inject; provide?: string | string[]; intercept?: Dict<boolean> }`
- `Plugin.Function = (ctx: Context, config: T) => any`
- `Plugin.Object = { apply(ctx: Context, config: T): any }`
- `Context.inject(deps, callback)` / `Context.plugin(plugin, ...args)`

重要行为（同文件 L84-104、README）：

- `registerProvider` 的工厂**同步执行**；远端初始化/鉴权应放进 `list()`。
- `list()` 返回数组 = 「本次发现是完整的」简写；返回 `{ candidates, complete: false }` 表示候选可用但发现不完整。
- 重复 `provider.name`（同一 layer 内）会抛错；`runtime` 是保留名。
- `get()` 收到的是**本 provider 自己返回的同一个 `locator`**（原样回传，不克隆）。
- `SkillSummary.source` / `provider` 为**必填**；`rank` 只在同一 layer 内解决重名。
- README 提到 shipped local provider 为 `@deepseek-ai/dsh-skill-local`，但该包**未发布到 npm**
  （`registry.npmjs.org` 返回 `Not found`），因此没有官方 provider 实现样例可供对照。

## 3. 我们的适配（`provider.ts` / `plugin.ts`）

`createDshSkillProvider(core, { rank, source, signal })` 把 `SealedCore`（`list()` + `readSkill(name)`）
适配成上面的 `SkillProvider`：

| dsh 契约 | 我们的实现 |
|---|---|
| `name: string` | 固定 `'sealed'` |
| `list(options)` | 调 `core.list()`，映射为 `SkillCandidate[]`；`options.signal` 已中止时返回 `[]` |
| `get(candidate, options)` | 从 `candidate.locator` 取回 skill 名，再 `core.readSkill(name)`；任何失败折叠为 `undefined` |
| `SkillCandidate.rank` | 默认 `600`（= `BUNDLED_SKILL_RANK`），可由 `plugin.ts` 配置覆盖 |
| `SkillCandidate.locator` | `{ sealedSkill: <name> }`（不透明；不暴露 pack 路径） |
| `SkillSummary.source` | 默认 `'custom'`（可配置） |
| `SkillSummary.provider` | 固定 `'sealed'` |
| `SkillSummary.resourceBase` / `.path` | **一律不提供** —— sealed 技能是虚拟技能，磁盘上无路径，明文只在内存 |

`plugin.ts` 导出 `name = 'sealed-skills'`、`inject = ['skills']`、`apply(ctx, config)`，并在 `apply` 内
调用 `ctx.skills.registerProvider((control) => createDshSkillProvider(...))`，把返回的 Cordis disposer
原样回传以保留 teardown 顺序。`config` 形如：

```ts
{
  mounts: [{ packPath, licensePath?, purchaseToken?, trial? }],   // 作者公钥不再由调用方给出
  trustedLicenseKeysB64: string[],   // 服务器 license 签名公钥（base64url raw Ed25519）
  serverUrl?: string,                // 默认 $SEALED_SERVER_URL
  serverProofPubB64?: string,        // 默认 $SEALED_SERVER_PROOF_PUB
  keystoreDir?: string,              // 默认 $SEALED_HOME 或 <cwd>/.sealed-home
  rank?: number,
}
```

每个 mount 或者给 `licensePath`（离线导入的预置 license），或者给 `purchaseToken` / `trial`
（在线激活）。pack 的作者公钥只从已签名 license 的 `pack.author_pub` 读取，调用方无法覆盖。

我们**刻意不 import** `@deepseek-ai/dsh-skill` / `@deepseek-ai/cordis`，而是在 `provider.ts` 里做**结构化
重声明**（duck typing），使该包不依赖 dsh、且适配层可独立单测。这是与 dsh 官方类型的**有意差异**：
若未来 dsh 类型变更，我们需要手动同步，编译器不会替我们检查。

## 4. 未验证项与待确认问题（numbered）

以下均**未经验证**，实现按现有证据做保守选择；接入真实 dsh 前必须逐条确认：

1. **`packages/skill/skill/src/index.ts` 源码签名**是否与 npm 发布产物 `0.0.1-rc.1` 完全一致（我们只核对了发布产物，未 clone 源码）。
2. **`ctx.skills.registerProvider` 的实际调用时机**：是否必须在插件 `apply()` 内**同步**调用（README 说工厂同步执行），以及注册失败时的错误形状。
3. **`inject = ['skills']` 的模块级导出形式**是否被 dsh 的插件加载器识别；dsh 是否要求 `{ name, inject, apply, Config }` 对象插件，或读取 ESM 命名导出（我们两种都导出了，但未实测）。
4. **`SkillProviderControl.signal` 的语义**：注册被 dispose 时是否必定 abort；我们用它短路 `list()`/`get()`，未验证其真实行为。
5. **`locator` 的序列化约束**：dsh 明确说 locator 是「opaque provider-owned handle」原样回传；我们返回普通对象，未验证缓存/比较是否要求可结构化克隆或可 `===`。
6. **`SkillSummary.invocation` 是否必须是新对象**、是否可以复用同一引用（我们每次映射都新建对象）。
7. **`rank` 的重名解决语义**：`600` 是否合适由产品决定；README 只说明「同 layer 内小者胜」，未说明与 `BUNDLED_SKILL_RANK` 的相对关系在我们的场景下是否恰当。
8. **`Config` schema 校验**：dsh 插件常用 `@deepseek-ai/schemastery` 定义 `Config`；我们未定义 schema，`plugin.ts` 的配置是普通对象，未验证是否被接受。
9. **`demo/cordis.yml` 的挂载语法**：`- insert: [{ id, name }]` 是否为当前 dsh 的插件树写法（该文件来自任务简报，未对照真实 dsh 文档验证）；`name` 指向 `.ts` 源码还是 `.js` 产物也未验证。
10. **多个 pack 的处理**：我们用一个 `sealed` provider 聚合所有 mount；dsh 是否更希望每个 pack 一个 provider（影响 `provider` 字段与重名解决）。
11. **密钥库路径与并发**：`plugin.ts` 默认共享一个 `FileKeystore`；未验证 dsh 是否会在同一进程加载多个我们的插件实例、以及并发 `mkdir` 的行为。
12. **授权失败的错误可见性**：`get()` 折叠为 `undefined` 是否符合 dsh 消费者（如 `dsh-tool-skill`）的期望——它拿不到「未授权/已过期」的区分，只会看到技能不可加载。

## 5. 如何补验证

网络可用时：

```bash
git clone --depth 1 https://github.com/deepseek-ai/deepseek-harness .dsh-checkout
cd .dsh-checkout && corepack pnpm install
# 打开 packages/skill/skill/src/index.ts 核对 §2 的每条签名，并找一个真实 provider 样例
```

然后在测试 profile 里 `ctx.plugin(sealedPlugin, config)`，断言：虚拟技能无 `path`、`list()` 摘要正确、
`get()` 正文正确、dispose 后 provider 被注销。

## 6. M3 Task 3 实测：真实 dsh 0.2.x 运行时集成（2026-10-04）

目标运行时：`@deepseek-ai/dsh@0.2.0-rc.2`（cordis `~4.0.4`），装在 git-ignored 的 `.dsh-lab/`；
测试文件 `packages/dsh-sealed-skills/test/dsh-integration.test.ts`（门控 `SEALED_DSH_LAB=1`）。

**驱动的层（务必区分，勿过度声明）：**

| 层 | 怎么驱动 | 证明了什么 |
| --- | --- | --- |
| 真实 profile 加载器 | app-boot 的 `loadProfile` + `evaluatePluginCompatibility` + `composeEntries`，对象为 lab profile `m3-lab` | 真实包身份 `@sealed/dsh-sealed-skills` 经 `dsh.bundle` 被解析，`skippedBundles` 为空，peer 兼容门通过 |
| 真实 cordis 内核 + 真实 `SkillRegistry` | `app-boot.boot('sealed-verify', <最小 cordis.yml>, [], prepare, bareModuleBaseUrl)`；条目 `@deepseek-ai/dsh-skill` 与 `@sealed/dsh-sealed-skills` 均按**真实包名**解析 | `apply(ctx, config)` 真的执行、`registerProvider()` 真的调用、`skills/change` 被触发、`list()`/`get()` 返回技能 |
| 未驱动 | 完整 shipped profile（`dsh-base` + `dsh-headless`） | **未验证**：headless 应用需要模型凭证（`MISSING_CREDENTIAL`），本环境无法启动 |

**授权链：** 真实 Ed25519 签名的 pack（`@sealed/pack-format`）+ 进程内真实 `@sealed/license-server`
（`createApp` 监听 `127.0.0.1:0`）+ 真实 `LicenseClient` 在线激活（`purchaseToken`）。

**实测命令与观察（lab 已装）：**

```text
$ $env:SEALED_DSH_LAB='1'; corepack pnpm --filter @sealed/dsh-sealed-skills test
 ✓ test/dsh-integration.test.ts (2 tests)
 Test Files  8 passed (8)
      Tests  57 passed (57)          # 门控关闭时全仓为 173 passed + 1 skipped

$ node scripts/dsh-lab.mjs --ensure --dump-config
 # == @sealed/dsh-sealed-skills, patched by .../m3-lab/cordis.patch.yml
 - id: sealed-skills
   name: '@sealed/dsh-sealed-skills'
   config:
     keystoreDir: .../.dsh-lab/sealed
     mounts: [...]
 dsh-lab: self-check: plugin sealed-skills is mounted
 dsh-lab: self-check: no profile bundle was skipped
```

**反向对照（证明断言不是空转）：** 同一条真实管线把 `purchaseToken` 换成伪造值、并用全新
`keystoreDir`（无缓存 license）→ `ctx.skills.list()` 返回 `[]`；正确 token → 返回 `[translate]`
且正文为真实明文。授权链是真正 load-bearing 的。

**§4 未验证项的收敛：**

- 已关闭：#2（apply 内同步注册）、#3（ESM 导出与加载）、#4（`signal`/invalidate 语义——注册时
  及 dispose 后均触发 `skills/change`）、#5（locator 仅被原样回传）、#6（`invocation` 每次新建）、
  #9（挂载语法——改为发布真实 `dsh.bundle` + profile 用户层 patch）、#11（单实例/单 keystore 路径）、
  #12（`get()` 折叠为 `undefined` 符合 `SkillRegistry` 语义）。
- 仍开放：#1（未 clone 源码仓库，仅核对 npm 产物）、#7（`rank` 相对 `BUNDLED_SKILL_RANK` 的产品取舍）、
  #8（仍未声明 `Config` schema——dsh 接受普通对象配置，但没有 schema 校验）、
  #10（单 provider 聚合 vs 每 pack 一个 provider 的设计选择），
  以及**完整 headless profile 的端到端启动**（需模型凭证）。
