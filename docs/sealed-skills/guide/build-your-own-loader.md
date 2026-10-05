# 写给 runtime / loader 作者：只用公开格式实现一个 Sealed Skills loader

这份文档面向**要给一个（新的）LLM harness / runtime 接入 Sealed Skills 的人**。
目标：**只依赖公开规范与 golden vectors**，就能读 `.sealedpack`、验 license、解密并交给你的 runtime，
**不需要**阅读或移植本仓库的 loader 源码。

> 参考实现（Node.js）在 `packages/dsh-sealed-skills`，但本指南刻意不假设任何一门语言或框架。
> 线格式见 `spec/pack-format.md` 与 `spec/license-format.md`；黄金向量见
> `test-vectors/pack-format.json`、`test-vectors/license-format.json`。

## 1. 你需要什么

| 输入 | 来源 |
|---|---|
| `.sealedpack` 字节 | 用户安装的技能包 |
| license 文本 | 用户的在线激活结果，或离线导入的 license 文件 |
| **受信服务器 license 公钥**（1 把或多把） | 你信任的授权服务器；必须内置在你的 loader 里 |
| 设备 X25519 私钥 | 用户的设备密钥库（Plan 2B 是 OS 密钥库；当前是文件） |
| runtime 的「技能」接口 | 你要对接的目标 harness |

**不要**从调用方传入作者公钥——作者公钥必须来自**已验签的 license**（`payload.pack.author_pub`），
否则会引入「调用方伪造作者」的漏洞。

## 2. 核心算法（顺序即安全边界）

```
load(packBytes, licenseText, trustedServerKeys, devicePrivateKey):
  1. parsed = readContainer(packBytes)              # spec/pack-format.md
  2. payload = verifyLicense(licenseText, trustedServerKeys)
         - 解析 + JCS 规范化断言 + Ed25519 验签；失败即拒绝
  3. 断言 payload.pack.id == parsed.manifest.pack_id
            payload.pack.version == parsed.manifest.version      # license 与包必须匹配
  4. authorKey = Ed25519PublicFromRaw(payload.pack.author_pub)
     断言 manifest 签名有效            # 否则 → PACK_SIGNATURE
  5. 断言 licenseStatus(payload, now) != expired
  6. 断言 devicePublic(devicePrivateKey) == payload.dev          # 设备绑定
  7. 解密入口：
        eid  = 请求的条目 id
        ck   = unwrapEntryKey(payload, eid, devicePrivateKey)     # spec/license-format.md §5
        aad  = pack_id || 0x00 || version || 0x00 || eid
        pt   = AES-256-GCM-open(ck, nonce, aad, ct)               # spec/pack-format.md §5
        zero(ck); zero(pt) 用后
```

要点：

- **先验签，再解密**：任何一步失败都**拒绝**，绝不回退到「跳过授权/跳过完整性」。
- **license 是唯一授权载体**：`keys[]` 里没有 `eid` 就是未授权（`NOT_GRANTED`），不要用 `caps`/`groups`
  自行放宽——它们只是标签。
- **虚拟技能**：交给 runtime 的技能定义**不要带磁盘路径**（没有 `path` / `resourceBase`），
  正文只在内存字符串里存在。
- **零化**：解出的 `ck` 与明文缓冲用后清零；不要写临时文件。

## 3. 对接 DeepSeek Harness（dsh 0.2.x）：两条落盘路径

dsh 的技能接口与客户端逻辑是解耦的，但要**正确**接入需要处理两条独立通道：

**A. 技能提供者**：把 `list()` / `readSkill(name)` 适配到 dsh 的技能注册接口
（`ctx.skills.registerProvider`）。这是技能正文进入模型的通道。

**B. 会话事件类型注册（必做，否则明文会漏）**：dsh 的会话日志是**消息派生视图**的来源。
如果你只是把正文交给 dsh，正文会随 `skill` 工具的 `tool/result`、以及 `/name` 的 `user/message`
**落盘进会话日志**。dsh 的 `SessionEventMap` 是 merge-extensible 的，正确做法是：

1. 声明一个自定义事件类型（如 `sealed/redacted`）；
2. 注册一个 **message projection**，让落盘时正文被替换成占位符（如 `⟦sealed:pack:entry⟧`），
   并从派生视图读取时还原明文；
3. **在 apply 时把该类型注册进 dsh 导出的 `KNOWN_SESSION_EVENT_TYPES`**。

### 3.1 上游缺口（务必阅读）

dsh 0.2.x 的 `session.append`**无法**为事件设置 `ignorable: true`，而读取器对「未知类型且无
`ignorable`」的会话是**整条拒绝**的。这带来一个必须知情的取舍：

- 插件在 apply 时把 `sealed/redacted` 注册进运行时的 `KNOWN_SESSION_EVENT_TYPES`，因此
  **装了插件的 harness 能正常读取**用过 sealed 技能的会话；
- 但**没装插件**的 harness 打开同一份会话日志时，会**整条拒绝**（而不是优雅回退成占位符）。

这是 **dsh 上游缺口**，不是本协议能修的。建议上游提供 append-with-ignorable 或
session 级 redaction API。细节见 `docs/sealed-skills/notes/dsh-0.2-seams.md` §9.7。

### 3.2 fail-closed 顺序

明文一旦被交给 dsh，就可能落盘。因此：

```
先确保 log-mask（事件类型注册 + projection）就绪
    │  未就绪 → 技能提供者「拒绝服务」，而不是「先给明文再说」
    ▼
再注册技能提供者
```

参考实现里，log-mask 未就绪时 `readSkill` 直接抛「service unavailable」。**宁可不可用，
也不产生明文日志。**

## 4. 脚本条目（`scripts/`）的执行规则

包内脚本条目（`script:<name>:<path>`）是**技能内容的一部分**，同样不能落盘：

- **只经子进程 stdin 传入源码**——不进 `argv`、不写临时文件、不经环境变量；
- 用后**零化**内存中的源码；
- 若目标平台的沙箱不可用或**非 fully-enforcing**，**拒绝注册脚本工具**（fail-closed），
  但**纯提示词技能仍可用**；
- 子进程输出若回显了源码，应标记/脱敏（参考实现：`output-redacted`）。

## 5. 错误处理原则

对用户暴露的错误要**脱敏**：不带明文、不带来密钥、不带内部堆栈。建议把错误归类为：
包完整性（`PACK_SIGNATURE` / 格式错）、授权（`LICENSE_INVALID` / `LICENSE_EXPIRED` / `NOT_GRANTED`）、
解密认证（`DECRYPT_FAILED`）、元数据（`META_INVALID`）。区分「未授权」（可提示购买）
与「解密失败」（可能被篡改）。

## 6. 用 golden vectors 自测互操作性

在接入你的 runtime 之前，先用向量做**离线**验证（不需要网络、不需要我们的代码）：

1. `test-vectors/pack-format.json`：固定 `master`/`pack_id`/`version`/`entry_id`/`nonce`/`plaintext_utf8`，
   断言你算出的 `ck`、`aad`、`ct` 与文件里的十六进制**逐字节相等**；再 `open` 回来等于明文。
2. `test-vectors/license-format.json`：固定签名种子 / 设备私钥 / 临时私钥 / nonce，
   断言你的 `unwrapEntryKey` 能得到 `content_key_hex`；断言你的 `verifyLicense` 接受
   `expected_token`；再把签名**翻转一个字节**，断言必须**拒绝**。
   （复现封装需要固定临时私钥与 nonce，这是**测试专用** seam，见 license 规范 §8。）
3. 负例清单：
   - 改一个签名字节 → 验签失败；
   - 换一把未受信服务器公钥 → 验签失败；
   - 改 `dev` 或换设备私钥 → 解封失败（GCM tag 不过）；
   - 改一个密文字节 → `open` 失败；
   - 改 `v` → 拒绝；缺字段 → `MALFORMED`。

## 7. 检查清单（提交前自查）

- [ ] 作者公钥只来自已验签 license，绝不来自调用方。
- [ ] 先验签 / 验设备绑定 / 验有效期，**再**解密；失败一律拒绝。
- [ ] 技能定义**无磁盘路径**；明文只在内存。
- [ ] 交出明文**之前**，会话日志掩码（dsh 下即 projection + 事件类型注册）已就绪，否则拒服务。
- [ ] 已在 apply 时把自定义事件类型注册进 `KNOWN_SESSION_EVENT_TYPES`（dsh 0.2.x）。
- [ ] 脚本源码只经 stdin；用后零化；沙箱非 enforcing 时拒绝脚本工具。
- [ ] `ck` 与明文缓冲用后清零；不写临时文件、不进日志。
- [ ] 错误信息脱敏；不含密钥、正文或堆栈。
- [ ] 通过 §6 的全部正例与负例向量。
- [ ] 如果改了线格式：那是**新版本**，必须走 `format_version` / `v` 升版，不得就地破坏 v1。

## 8. 相关文档

- `spec/pack-format.md`、`spec/license-format.md` —— 你真正要依赖的规范。
- `guide/threat-model.md` —— 保证边界与未验证项（别过度承诺）。
- `notes/dsh-0.2-seams.md` —— dsh 0.2.x 接缝与上游缺口 §9.7。
- `guide/for-skill-developers.md` §8 —— 运行时接入的组件总览。