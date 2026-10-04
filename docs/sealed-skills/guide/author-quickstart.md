# 作者快速上手（M1）

目标：用本仓库的 M1 工具，把 `demo/translate/` 这样一个技能目录打成加密包，并为它签发一份
**绑定到本机设备**的 7 天试用 license，最后在无 dsh 依赖的情况下验证它能被解密。

> 本文所有命令都在仓库根目录执行，且都经过实测。M1 没有授权服务器：试用 license 由作者本机
> 私钥签发，仅用于开发与演示；生产签发属于 M2。

## 0. 前置

- Node ≥ 20（本机 24.x），`corepack` 可用。
- 包管理器统一写 `corepack pnpm`，不要用裸 `pnpm`。
- 加密只用 Node 内置 `crypto`，无需安装任何密码学依赖。

```bash
corepack pnpm install
corepack pnpm -r build
```

`-r build` 会依次编译五个包；成功时每个包打印 `Done`。

## 1. 认识技能目录

`demo/translate/SKILL.md`：

```markdown
---
name: translate
description: 把用户输入翻译成英文
whenToUse: 当用户要求翻译文本时
---

把用户输入翻译成自然、地道的英文，保留原有语气与格式。
```

打包规则（M1）：

- `SKILL.md` 的 `---` frontmatter 必须有 `name` 与 `description`；`whenToUse` 可选。
- 正文（frontmatter 之后的 Markdown）成为条目 `skill:<name>:body`。
- `resources/` 下的文件 → `skill:<name>:res:<相对路径>`。
- `scripts/` 下的文件 → `script:<name>:<相对路径>`。
- `data/` 下的文件 → `data:<name>`。
- 另有自动生成的加密元数据条目 `meta`。
- 条目 id 派生是确定的；含 `:`、空格、unicode 的资源相对路径同样支持，但禁止 `..` 或绝对路径（防穿越）。
- 空目录或缺 frontmatter 会报可执行错误，绝不产出空包。

## 2. 打包（一次加密，全客户共用）

```bash
node -e "import('./packages/seal-cli/dist/pack.js').then(async (m) => { const a = (await import('node:crypto')).generateKeyPairSync('ed25519'); const r = m.packSkillDir('./demo/translate', { packId: 'com.example.translate', version: '1.0.0', label: '翻译', master: Buffer.alloc(32, 1), trialEntryIds: ['meta','skill:translate:body'], authorPrivateKey: a.privateKey }); console.log(r.manifest.entries.map((e) => e.id)) })"
```

预期输出：

```text
[ 'meta', 'skill:translate:body' ]
```

`packSkillDir(dir, opts)` 返回 `{ file, manifest, master }`：

- `file` 是 `.sealedpack` 容器的 `Buffer`（可直接 `writeFileSync` 落盘）。
- `manifest` 是**明文**不透明清单：只含 id / 类型 / 密文长度 / 试用标记，不含技能名、描述或正文哈希。
- `master` 是 32 字节 pack master key；**只应留在作者/服务端**，不要随包分发。

opts 说明：

| 字段 | 含义 |
|---|---|
| `packId` / `version` | 参与条目密钥派生与 AAD；发布后不可复用旧 id 解新内容 |
| `label` | 非敏感公开名，用于未授权时展示 |
| `master` | 32 字节 pack master key |
| `trialEntryIds` | 试用 license 需要解锁的条目 id 列表 |
| `authorPrivateKey` | Ed25519 私钥，用于给 manifest 签名 |

> 本示例用 `Buffer.alloc(32, 1)` 作为 master 只为可复制；真实使用请用 `randomBytes(32)` 并妥善保管。
> 示例作者私钥是进程内临时生成的，因此**该包没有可长期验证的作者身份**——真实发布须持久化作者密钥。

## 3. 签一份绑定本机的试用 license

`makeTrialLicense` 的输入是上一步的 `manifest`、`master`、本机设备公钥和试用条目 id：

- 设备密钥：`FileKeystore` 在 `.sealed-home/device.json` 生成 X25519 密钥对（M1 为明文退路，M2 换 OS 密钥库）。
- license 载荷用 Ed25519 签名；每个被授权条目一把 `CK_i`，用设备公钥经 X25519 ECDH 封装。
- 缺设备私钥 → 换机不可用；缺条目封装 → 该条目解不开。

**最省事的验证方式**是直接跑端到端冒烟，它把「打包 → 设备密钥 → 签 license → 落盘 → 读回解密」串起来：

```bash
node scripts/m1-smoke.mjs
```

实测输出：

```text
skills: [
  {
    name: 'translate',
    description: '把用户输入翻译成英文',
    invocation: { modelInvocable: true, userInvocable: true },
    whenToUse: '当用户要求翻译文本时'
  }
]
content: 把用户输入翻译成自然、地道的英文，保留原有语气与格式。

disk-leak-check: clean (no plaintext body in .sealed-home/ artifacts)
```

`disk-leak-check` 会读取 `.sealed-home/translate.sealedpack`、`.sealed-home/translate.license` 与
`.sealed-home/device.json`，断言正文字节串**不出现**在任何落盘产物中。

## 4. 检查一个已有的包

`inspectPack(file, authorPublicKey?)` 只读地解析容器并（可选）验 manifest 签名：

```bash
node -e "import('node:fs').then(async (fs) => { const a = (await import('node:crypto')).generateKeyPairSync('ed25519'); const m = await import('./packages/seal-cli/dist/pack.js'); const r = m.packSkillDir('./demo/translate', { packId: 'com.example.translate', version: '1.0.0', label: '翻译', master: Buffer.alloc(32, 1), trialEntryIds: ['meta','skill:translate:body'], authorPrivateKey: a.privateKey }); console.log(JSON.stringify(m.inspectPack(r.file, a.publicKey), null, 2)) })"
```

预期输出的关键字段：`manifest.pack_id` 为 `com.example.translate`、`chunks` 为 2、
`signatureValid` 为 `true`，且 `manifest.entries` 里每个条目只有 `id` / `type` / `size` / `trial`。

## 5. 跑测试

```bash
corepack pnpm -r test
```

M1 基线：五个包共 **84 个测试全绿**（`canonical-json` 5、`pack-format` 19、`license-format` 13、
`seal-cli` 16、`dsh-sealed-skills` 31）。

## 6. 常见问题

- **`SKILL_MD_NO_FRONTMATTER`**：`SKILL.md` 未以 `---` frontmatter 开头，或缺 `name` / `description`。
- **`ENTRY_PATH_INVALID`**：`resources/` / `scripts/` / `data/` 下的相对路径含 `..`、反斜杠或空段。
- **`TOO_LARGE`**：单条目超过 32 MiB（`33554432` 字节）上限。
- **解密时 `NOT_GRANTED`**：license 里没有该条目的封装密钥——试用 license 只会解锁 `trialEntryIds`。
- **解密时 `LICENSE_EXPIRED`**：已过 `exp` 且超过 `grace_until` 宽限期。
- **`DECRYPT_FAILED`**：密文被篡改，或条目身份（pack id / version / entry id）不匹配。

## 7. 下一步（尚未实现）

M2 起，签发将改由授权服务器完成，作者只需持有作者签名私钥；试用/席位/续期/吊销与 OS 密钥库
后端都在 M2。脚本执行（`scripts/` 条目的运行）在 M3，日志掩码同样在 M3。详见
`docs/sealed-skills/README.md` 的路线图。
