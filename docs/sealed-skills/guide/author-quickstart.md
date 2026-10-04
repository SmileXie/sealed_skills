# 作者快速上手（M1 + M2）

目标：用本仓库的 M1 工具，把 `demo/translate/` 这样一个技能目录打成加密包，并为它签发一份
**绑定到本机设备**的 7 天试用 license，最后在无 dsh 依赖的情况下验证它能被解密。

> 本文所有命令都在仓库根目录执行，且都经过实测。第 3 节的本机试用 license 仍由作者私钥签发，
> 仅用于开发与演示；生产签发走授权服务器，见第 4.5 节与
> `docs/sealed-skills/guide/publish-and-license.md`。

## 0. 前置

- Node ≥ 20（本机 24.x），`corepack` 可用。
- 包管理器统一写 `corepack pnpm`，不要用裸 `pnpm`。
- 加密只用 Node 内置 `crypto`，无需安装任何密码学依赖。

```bash
corepack pnpm install
corepack pnpm -r build
```

`-r build` 会依次编译五个包；成功时每个包打印 `Done`。下文的 `seal` 统一写作
`node packages/seal-cli/dist/cli.js`（`seal-cli` 也声明了 `bin.seal`，安装后可直接用 `seal`）。

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

## 2. 生成作者密钥并打包（一次加密，全客户共用）

作者私钥是**长期身份**：pack manifest 与 license 都由它签名，客户端用对应公钥验签。
先生成并持久化（POSIX 下 0600，BOM-free）：

```bash
node packages/seal-cli/dist/cli.js keygen -o author.key.json
```

输出：

```text
author key written: author.key.json
public key (b64url): <43 字符的 base64url 公钥>
```

`author.key.json` 的文档化格式（明文 JSON；`pub` / `priv` 为 base64url raw 32 字节）：

```json
{ "v": 1, "alg": "ed25519", "pub": "<base64url>", "priv": "<base64url>" }
```

> 该文件等价于作者身份：不要提交进仓库、不要随包分发。`--author-pub` 用的就是其中的 `pub`。

打包（`--trial` 列出试用 license 需要解锁的条目 id）：

```bash
node packages/seal-cli/dist/cli.js pack ./demo/translate -o translate.sealedpack \
  --pack-id com.example.translate --version 1.0.0 --label 翻译 \
  --key author.key.json --trial meta,skill:translate:body
```

输出：

```text
pack written: translate.sealedpack
master key written (server-only): translate.sealedpack.master.json
entries: meta, skill:translate:body
```

- `translate.sealedpack` 是密文包，可给所有客户。
- `translate.sealedpack.master.json` 保存 pack master key（`{ v, pack_id, version, master, created_at }`），
  **只应留在作者/服务端**，用于为各设备封装 `CK_i`；不要随包分发。
- 重复打包同一目录：除各条目随机 nonce 外，manifest 是确定的。

`packSkillDir(dir, opts)` 是 CLI 底层的可复用函数，返回 `{ file, manifest, master }`：
`file` 是容器 `Buffer`；`manifest` 是明文不透明清单（只含 id / 类型 / 密文长度 / 试用标记，
不含技能名、描述或正文哈希）；`master` 是 32 字节 pack master key。opts：`packId` / `version`
参与密钥派生与 AAD；`label` 是非敏感公开名（未授权时展示）；`trialEntryIds` 见上；`authorPrivateKey`
是 Ed25519 私钥。

## 3. 签一份绑定本机的试用 license

试用 license 绑定**本机设备公钥**；设备密钥由客户端 `FileKeystore` 生成于 `.sealed-home/device.json`。
签名时为每个被授权条目解出一把 `CK_i`，用设备公钥经 X25519 ECDH 封装：

```bash
node packages/seal-cli/dist/cli.js trial translate.sealedpack \
  --master translate.sealedpack.master.json \
  --device-pub <本机设备公钥 base64url> \
  --days 7 --key author.key.json -o translate.license
```

输出：

```text
trial license written: translate.license
trial entries: meta, skill:translate:body
```

`--device-pub` 从客户端设备密钥库读取；本地可取一份：

```bash
node -e "import('./packages/dsh-sealed-skills/dist/keystore.js').then(async ({ FileKeystore }) => { const ks = new FileKeystore({ dir: '.sealed-home' }); await ks.createDeviceKey(); console.log((await ks.loadDevicePublicKey()).toString('base64url')) })"
```

缺设备私钥 → 换机不可用；缺条目封装 → 该条目解不开。

**最省事的验证方式**是端到端冒烟（打包 → 设备密钥 → 签 license → 落盘 → 读回解密），
它自带一份临时作者密钥，无需先运行 `keygen`：

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
`.sealed-home/device.json`，断言 demo 正文字节**不出现**在这三个落盘产物中（脚本条目与日志/临时文件不在自动断言范围内）。

## 4. 检查一个已有的包

```bash
node packages/seal-cli/dist/cli.js inspect translate.sealedpack --author-pub <author.key.json 的 pub>
```

输出（摘要，绝不解密）：

```json
{
  "pack_id": "com.example.translate",
  "version": "1.0.0",
  "label": "翻译",
  "entry_count": 2,
  "entries": [
    { "id": "meta", "size": 249, "trial": true, "type": "meta" },
    { "id": "skill:translate:body", "size": 98, "trial": true, "type": "text" }
  ],
  "chunks": 2,
  "signatureValid": true
}
```

`inspectPack(file, authorPublicKey?)` 是底层函数，只读解析容器并（可选）验 manifest 签名。

## 4.5 登记到授权服务器并签发 purchase token（M2）

本机试用 license 只能自己用；对外售卖时，把 pack 的 **master key 登记到你自己托管的授权服务器**，
由服务器为每台设备签发 license。完整部署与运营见 `docs/sealed-skills/guide/publish-and-license.md`，
最短路径：

1. 起服务器（环境变量含义见 `publish-and-license.md` 第 2 节）：

   ```bash
   SEALED_SERVER_ADMIN_TOKEN=dev-token \
   SEALED_SERVER_LICENSE_KEY=... SEALED_SERVER_PROOF_KEY=... SEALED_SERVER_MASTER_KEY=... \
   node packages/license-server/dist/bin.js
   ```

2. 只上传 master 登记 pack（**绝不上传 `.sealedpack` 或明文**）：

   ```bash
   SEALED_SERVER_URL=http://127.0.0.1:8787 SEALED_SERVER_ADMIN_TOKEN=dev-token node --input-type=module -e "
   import { readFileSync } from 'node:fs'
   import { inspectPack } from './packages/seal-cli/dist/pack.js'
   import { parseMasterFile } from './packages/seal-cli/dist/master.js'
   const manifest = inspectPack(readFileSync('translate.sealedpack')).manifest
   const master = parseMasterFile(readFileSync('translate.sealedpack.master.json', 'utf8'))
   const authorPub = JSON.parse(readFileSync('author.key.json', 'utf8')).pub
   const res = await fetch(process.env.SEALED_SERVER_URL + '/v1/admin/packs', {
     method: 'POST',
     headers: { 'content-type': 'application/json', authorization: 'Bearer ' + process.env.SEALED_SERVER_ADMIN_TOKEN },
     body: JSON.stringify({
       pack: { id: manifest.pack_id, version: manifest.version }, author_pub: authorPub, label: manifest.label,
       master_b64: master.master.toString('base64url'),
       trial_entries: manifest.entries.filter((e) => e.trial).map((e) => e.id),
       entries: manifest.entries.map((e) => ({ id: e.id, type: e.type, size: e.size })),
     }),
   })
   console.log(res.status, await res.text())
   "
   ```

3. 买家付款后，由你的计费系统写入一张 `purchase_token`：
   `Store.putPurchase({ token, sub, packId, version, plan, seats })`（未知 token 会被拒绝，
   `seats` 控制设备数）。

4. 交付：`.sealedpack` + `purchase_token`；**绝不交付** `master.json` 与 `author.key.json`。

用户侧只需配置 `serverUrl` / `serverProofPubB64` / `trustedLicenseKeysB64`，再给 mount 一个
`purchaseToken`（或 `trial: true`，或离线 `licensePath`）即可；作者公钥随 license 传递，无需单独配置。

## 5. 跑测试

```bash
corepack pnpm -r test
```

当前基线：六个包共 **170 个测试全绿**（`canonical-json` 5、`pack-format` 36、`license-format` 19、
`seal-cli` 32、`license-server` 28、`dsh-sealed-skills` 50）。

## 6. 常见问题

- **`NO_SKILL_MD`**：目录里没有 `SKILL.md`。
- **`SKILL_MD_NO_FRONTMATTER`**：`SKILL.md` 未以 `---` frontmatter 开头，或缺 `name` / `description`。
- **`ENTRY_PATH_INVALID`**：`resources/` / `scripts/` / `data/` 下的相对路径含 `..`、反斜杠或空段。
- **`TOO_LARGE`**：单条目超过 32 MiB（`33554432` 字节）上限。
- **解密时 `NOT_GRANTED`**：license 里没有该条目的封装密钥——试用 license 只会解锁 `trialEntryIds`。
- **解密时 `LICENSE_INVALID`**：license 的 `dev` 与本机设备公钥不符（此授权不适用于本机）。
- **解密时 `LICENSE_EXPIRED`**：已过 `exp` 且超过 `grace_until` 宽限期。
- **`DECRYPT_FAILED`**：密文被篡改，或条目身份（pack id / version / entry id）不匹配。

## 7. 下一步

- **发布与授权（M2，已实现）**：把 master 登记到授权服务器、签发 `purchase_token`、激活 /
  续期 / 席位 / 吊销，见 `docs/sealed-skills/guide/publish-and-license.md`。
- **生态与参与方式（M2，已实现）**：为什么收费、怎么选商业模式、如何适配别的 runtime，见
  `docs/sealed-skills/guide/for-skill-developers.md`。
- **协议参考（M2，已实现）**：端点、错误码、设备证明公式，见 `docs/sealed-skills/spec/protocol.md`。
- **尚未实现**：OS 密钥库后端（DPAPI / Keychain / libsecret，Plan 2B，当前为
  `$SEALED_HOME/device.json` 文件）；脚本执行沙箱与日志掩码（M3）。
