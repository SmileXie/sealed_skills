# `.sealedpack` v1 —— 公开线格式规范

本文件是 Sealed Skills 加密包容器 **v1** 的**公开规范**。任何第三方 loader 都可以只依据本文
（加上 `test-vectors/pack-format.json`）实现读取与校验，**不需要**阅读本仓库的 loader 源码。

> **TEST-ONLY**：`test-vectors/` 中的密钥与 nonce 仅用于复现向量，**绝不可用于生产**。
> 参考实现：`packages/pack-format`（Node.js，仅依赖 `node:crypto` 与 JCS）。

## 1. 约定

- 所有多字节整数为**大端**（big-endian）：`u32` = 4 字节无符号，`u64` = 8 字节无符号。
- 所有字符串（id、version 等）以 **UTF-8** 编码。
- JSON 规范化使用 **RFC 8785 (JCS)**；签名与派生都以规范化后的**精确字节**为准。
- `master` 是 32 字节的 pack 主密钥（只在作者/服务端持有）。

## 2. 容器字节布局

```
offset  field
0       magic            : 6 字节 ASCII "SLDSK1"
6       version(1) + 0   : 2 字节 [format_version=1, 0x00]
8       manifest_len     : u32
12      manifest         : manifest_len 字节 = JCS(manifest) 的 UTF-8
...     sig_len          : u32
...     signature        : sig_len 字节（Ed25519(manifest)，64 字节）
...     entry_count      : u32（= manifest.entry_count）
...     entry table      : entry_count 条记录，顺序与 chunk area 一致
...     chunk area       : entry_count 条记录，顺序与 entry table 一致
```

**entry table 每条记录**

```
id_len   : u32
id       : id_len 字节 UTF-8（条目 id）
offset   : u64（该条目 nonce 在**整个文件**中的绝对偏移）
ct_len   : u32（密文长度，含 16 字节 GCM tag）
```

**chunk area 每条记录**

```
nonce    : 12 字节（AES-GCM nonce）
ct       : ct_len 字节（= AES-GCM 密文 || 16 字节 tag）
```

读取器必须校验：magic、`format_version == 1`、各段不越界、table 的 `ct_len` 与 manifest 的
`size` 一致、`entry_count` 与 manifest 一致。错误码见 §6。

## 3. Manifest（JCS）

规范化后形如（字段按 JCS 排序，示例非规范顺序）：

```json
{
  "pack_id": "com.example.translate",
  "version": "1.0.0",
  "label": "翻译",
  "entry_count": 2,
  "entries": [
    { "id": "meta", "type": "meta", "size": 128, "trial": false },
    { "id": "skill:translate:body", "type": "text", "size": 96, "trial": true }
  ]
}
```

- `type` ∈ `meta` | `text` | `script` | `data`。**前向兼容**：读取器必须**忽略**未知 `type` 的条目，
  而不是整体失败。
- `size` = 该条目密文长度（含 tag），即 `ct_len`。
- `trial`：该条目是否属于试用集合（供发布服务记录；读取不影响解密）。
- `signature` 是对 `JCS(manifest)` 精确字节的 **Ed25519** 签名，使用**作者**私钥；验证需要
  `pack.author_pub`（来自 license，见 `spec/license-format.md`）。

## 4. 条目 id 约定

| 形态 | 含义 |
|---|---|
| `meta` | 技能元数据（名称、描述、`whenToUse`、`entries` 列表） |
| `skill:<name>:body` | 技能正文（Markdown） |
| `skill:<name>:res:<path>` | 技能资源文件 |
| `script:<name>:<path>` | 可执行脚本条目 |
| `data:<name>` | 私有数据块 |

`<path>` 使用包内相对路径；`<name>` 为技能名。读取器按此约定分发，但格式本身不限制 id 集合。

## 5. 逐条目密钥与 AEAD

对每个条目 `id`：

```
CK_i  = HKDF-SHA256(key = master, salt = pack_id || 0x00 || version,
                    info = "entry:" || id, L = 32)
AAD   = pack_id || 0x00 || version || 0x00 || id        (UTF-8)
nonce = 12 字节随机（每个条目一次）
ct    = AES-256-GCM(key = CK_i, iv = nonce, aad = AAD, plaintext) 的结果 || 16 字节 tag
```

`0x00` 是单字节分隔符，避免拼接歧义。解密用同一 `AAD` 与 `tag` 验证完整性。

**大小上限**：单条目密文 `MAX_ENTRY_BYTES = 33,554,432`（32 MiB）。超限 → `TOO_LARGE`。

## 6. 错误码（`PackErrorCode`）

| 码 | 触发 |
|---|---|
| `BAD_MAGIC` | 前 6 字节不是 `SLDSK1` |
| `BAD_VERSION` | `format_version != 1`（更高版本要求升级 loader） |
| `TRUNCATED` | 任意段越界 / 文件不足 |
| `BAD_MANIFEST` | manifest 非 JSON / 结构非法 |
| `TOO_LARGE` | 条目超过 32 MiB |
| `TABLE_MISMATCH` | table 与 manifest 不一致（数量 / id / size） |

## 7. 版本与兼容

- `format_version` 当前为 `1`。遇到**更高**版本 → 拒绝并提示升级 loader。
- **未知字段必须忽略**（manifest 顶层未知键、entry 记录未知键）。
- 未知条目 `type` → 忽略该条目，不整体失败。

## 8. Golden vectors

`test-vectors/pack-format.json` 为固定 `master`/`nonce`/明文 → 期望 `CK_i`、`AAD`、`nonce`、`ct` 的
十六进制向量；`packages/pack-format/test/vectors.test.ts` 用参考实现逐字节复算。第三方实现可用它
自测互操作性。生成脚本：`test-vectors/generate.mjs`（TEST-ONLY）。