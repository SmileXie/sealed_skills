# Sealed Skills — M4「生态与交付」实现计划

- 计划文件：`docs/superpowers/plans/2026-10-04-sealed-skills-m4-ecosystem.md`（未跟踪，按仓库惯例不入库）
- 规格来源：`docs/superpowers/specs/2026-10-04-sealed-skills-design.md` §6.1 / §6.2 / §7 / §9 / §10.2
- 前置：M1（`c7cc700`）、M2（`5f39ef2`）、M3（`1fb6b10`）已并入 `master`；基线 **275 passed + 5 loud skips**；`pnpm leak-gate` = `leak-gate: clean`。

## 0. 目标与非目标

**M4 目标**：把「能用的框架」升级为「可被第三方采纳的生态」——公开且可互操作的**线格式规范 + golden vectors**、面向技能作者 / loader 作者 / 市场的**详尽文档**、以及发布级 CI。

**交付物**
1. `docs/sealed-skills/spec/pack-format.md` + `test-vectors/pack-format.*`（`.sealedpack` v1 公开规范 + 黄金向量）。
2. `docs/sealed-skills/spec/license-format.md` + `test-vectors/license-format.*`（license v1 公开规范 + 黄金向量）。
3. `docs/sealed-skills/guide/threat-model.md`（威胁模型与保证边界）。
4. `docs/sealed-skills/guide/build-your-own-loader.md`（第三方 loader 指南）。
5. `docs/sealed-skills/guide/trial-and-marketplace.md` + 刷新 `guide/for-skill-developers.md`（试用/市场/生态邀请）。
6. CI（`test` workflow + `release` dry-run）+ 文档索引刷新 + 最终整分支评审与合并。

**非目标**（属 M5 / Plan 2B，不在 M4）：原生/WASM `DecryptBackend`；DPAPI/Keychain/libsecret；真实市场后端；多语言 SDK 实现（仅规范 + 向量 + 指南使其可行）。

## 1. Global Constraints（每个任务都受约束）

- **线格式冻结**：不得破坏性修改 v1 线格式；如需扩展一律**附加可选字段**并遵守「未知字段忽略」（spec §5.3）。黄金向量必须与 M1-M3 产物字节一致。
- **黄金向量确定性**：当前 `sealEntry` 内部用 `randomBytes` 生成 nonce。为产出**可复现**向量，给 AEAD 增加一个 **nonce 注入 seam**（如 `sealEntry(key, aad, plaintext, nonce?)` 或 `sealEntryWithNonce`），**生产路径仍用随机 nonce**；规范中写明「测试向量以固定 nonce 构造」。
- **测试向量密钥仅用于向量**：文档与向量文件必须显著标注「TEST-ONLY, DO NOT USE IN PRODUCTION」。
- 文档以**中文**为主（与 README/guide 现状一致）；格式规范允许中英混排，但字段名、十六进制、代码标识符用英文。示例中**不得**出现可用于生产的真实私钥。
- 零明文承诺不变；不新增第三方运行时依赖；pnpm 经 `corepack`；CI 用 Node 24。
- 不 stage `docs/superpowers/plans/*`；不 `git add -A`。提交用 `git -c commit.gpgsign=false -c user.name="Codex" -c user.email="codex@local" commit --no-verify -m "..."`。

## 2. 任务

### Task 1：`pack-format` 公开规范 + 黄金向量

**Files**：`docs/sealed-skills/spec/pack-format.md`、`test-vectors/pack-format.json`、`packages/pack-format/test/vectors.test.ts`、`packages/pack-format/src/aead.ts`（nonce seam）

- 规范内容：容器字节布局（magic `SLDSK1` / version / manifest 长度 / manifest / entry table / chunk area）、manifest 的 JCS 规范化与 Ed25519 签名、条目 id 约定（`meta` / `skill:<name>:body` / `skill:<name>:res:<path>` / `script:<name>:<path>` / `data:<name>`）、CK_i 派生（`HKDF-SHA256(master, salt=packId||0x00||version, info="entry:"||entryId, 32)`）、AAD（`packId||0x00||version||0x00||entryId`）、AEAD（AES-256-GCM，12B nonce，16B tag 追加）、大小上限（`MAX_ENTRY_BYTES` 32 MiB）、错误码、版本兼容规则。
- 黄金向量：固定 `master`/`packId`/`version`/`entryId`/`nonce`/`plaintext` → 期望 `CK_i`、`aad`、`nonce`、`ct`（十六进制）。至少 3 组（`meta`/`text`/`script`），含空 plaintext、Unicode、边界长度。
- 测试：从 JSON 读向量重算并断言；再用固定签名密钥做完整容器 `writeContainer → readContainer` 往返。
- **验收**：向量文件可被独立第三方实现复现；测试全绿；线格式零破坏（M1-M3 测试零回归）。

### Task 2：`license-format` 公开规范 + 黄金向量

**Files**：`docs/sealed-skills/spec/license-format.md`、`test-vectors/license-format.json`、`packages/license-format/test/vectors.test.ts`

- 规范内容：令牌形状（`<payloadB64>.<sigB64>`）、payload 字段（`v`/`lid`/`pack`/`dev`/`exp`/`grace_until`/`caps`/`groups`/`keys[{eid,eph,n,c}]`/`seats`）、JCS、Ed25519 验签、CK 封装（`ss = ECDH(eph_priv, dev_pub)`；`kek = HKDF-SHA256(ss, salt=lid, info="wrap:"||eid, 32)`；`c = AES-256-GCM(kek, n, aad=lid||0x00||eid, CK)`）、设备绑定、状态机 `active`/`grace`/`expired`、时钟回拨。
- 黄金向量：固定签名密钥（固定 seed）、固定设备 X25519、固定 `lid`/`eid`/`CK`/`eph`/`n` → 期望 `c` 与**完整令牌验签通过**；另附**篡改检测**向量（改 1 字节则验签/解封失败）。
- **验收**：第三方可仅凭规范 + 向量复现；测试全绿。

### Task 3：`guide/threat-model.md`

**Files**：`docs/sealed-skills/guide/threat-model.md`
- 等级 B 威胁模型、信任边界（可信：作者私钥、master、授权服务器；不可信：用户机器一切）、S1-S7 属性、**保证 vs 非保证**、M3 实测残余（缺插件 harness 整条拒绝会话 §9.7；`invariants` 哨兵 detect-only；子串匹配漏编码/拆分；Windows 沙箱后端未知；模型提供方可见明文；有调试权限用户最终可提取）、M5/Plan 2B 的定位与「不要指望」清单。

### Task 4：`guide/build-your-own-loader.md`

**Files**：`docs/sealed-skills/guide/build-your-own-loader.md`
- 面向**第三方 runtime**：如何只用公开格式实现 loader（open pack → 验 manifest 签名 → 验 license（作者公钥来自 license 的 `pack.author_pub`）→ 解封 CK → 解密条目 → 交给 runtime）；生命周期与 fail-closed 顺序（log-mask/脱敏必须先于解密）、零化、错误脱敏；用 golden vectors 自测的互操作检查清单；示例伪代码（语言无关）。明确「不要依赖我们的 loader 源码，依赖规范与向量」。

### Task 5：`guide/trial-and-marketplace.md` + 刷新 `for-skill-developers.md`

**Files**：`docs/sealed-skills/guide/trial-and-marketplace.md`、`docs/sealed-skills/guide/for-skill-developers.md`
- 试用（`trial_entries`、试用去重 409）、席位、续期、吊销延迟（≤1 TTL）、定价与分发建议、市场集成模式（作者 `keygen/pack/publish` + license-server 部署 + 分发 `.sealedpack`）、对技能开发者的号召、贡献路径（提交技能、规范反馈、实现 loader）。
- 刷新 `for-skill-developers.md`：与新规范/指南交叉链接，确保「详尽且鼓励加入生态」。

### Task 6：CI + 文档索引 + 最终评审 + 合并

**Files**：`.github/workflows/test.yml`、`.github/workflows/release-dry-run.yml`（或等价）、`docs/sealed-skills/README.md`（文档索引/仓库布局）
- CI：`test` workflow 跑 `pnpm install --frozen-lockfile` + `pnpm -r build` + `pnpm -r test` + `pnpm leak-gate`；`release` dry-run 跑 `pnpm -r publish --dry-run`（或 `npm pack`）**不发布**。
- 文档索引更新为「七篇 + 向量」并修正仓库布局。
- **最终整分支评审（最有力模型）** + 一次修复波 + 定向复审；随后合并 `master`。

## 3. M4 Exit Criteria（合并前必须成立）

1. 六个包 `build` + `test` 全绿零回归；`pnpm leak-gate` = `leak-gate: clean`。
2. `spec/pack-format.md` 与 `spec/license-format.md` 均附**可复现** golden vectors，且向量测试在**无 dsh** 环境通过。
3. 五篇新文档齐备，README 索引准确、仓库布局同步。
4. CI 含 `test`（含 275+ 测试）与 `leak-gate`，并有 release dry-run（不发布）。
5. 文档/示例不含真实密钥或受保护明文；未验证项如实标注（不得把 UNVERIFIED 写成已通过）。
6. 最终评审无 Critical/Important。

## 4. Self-Review

- **规格覆盖**：§6.1 契约层公开规范 → Task 1/2；§10.2 golden vectors → Task 1/2；生态文档 → Task 3/4/5；发布流程与 CI → Task 6。
- **类型/线格式一致性**：向量必须与 `deriveEntryKey`/`entryAad`/`sealEntry`/`wrapEntryKey` 的实际实现一致；nonce seam 仅测试用，不影响生产随机性。
- **风险与残余**：真机完整模型回合仍需 `DEEPSEEK_API_KEY`（UNVERIFIED）；多语言 loader 仅规范级可行（未提供实现）；Plan 2B/M5 仍未实现。