import { generateKeyPairSync } from 'node:crypto'
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { deriveEntryKey, entryAad, openEntry, readContainer, verifyManifestSignature } from '@sealed/pack-format'
import { assertSafeRelPath, inspectPack, packSkillDir, parseSkillMarkdown } from '../src/index.js'

function skillDir(files: Record<string, Buffer | string>): string {
  const dir = mkdtempSync(join(tmpdir(), 'skill-'))
  for (const [rel, content] of Object.entries(files)) {
    const full = join(dir, rel)
    mkdirSync(join(full, '..'), { recursive: true })
    writeFileSync(full, content)
  }
  return dir
}

const author = generateKeyPairSync('ed25519')
const master = Buffer.alloc(32, 5)
const base = { packId: 'com.example.translate', version: '1.0.0', label: '翻译', master, authorPrivateKey: author.privateKey, trialEntryIds: [] as string[] }

const goodDir = () => skillDir({
  'SKILL.md': '---\nname: translate\ndescription: 翻译文本\nwhenToUse: 需要翻译时\n---\n\n把用户输入翻译成英文。\n',
  'scripts/run.py': 'print("hi")\n',
  'resources/logo.png': Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x00, 0xff, 0xfe]),
  'data/glossary.json': JSON.stringify({ a: '甲' }),
})

describe('parseSkillMarkdown', () => {
  it('splits frontmatter from the body', () => {
    const parsed = parseSkillMarkdown('---\nname: x\ndescription: y\n---\nbody text\n')
    expect(parsed.frontmatter).toEqual({ name: 'x', description: 'y' })
    expect(parsed.body).toBe('body text\n')
  })

  it('rejects a file without frontmatter', () => {
    expect(() => parseSkillMarkdown('no frontmatter')).toThrow('SKILL_MD_NO_FRONTMATTER')
  })

  it('parses CRLF-authored frontmatter', () => {
    const parsed = parseSkillMarkdown('---\r\nname: x\r\ndescription: y\r\n---\r\nbody\r\n')
    expect(parsed.frontmatter).toEqual({ name: 'x', description: 'y' })
    expect(parsed.body).toBe('body\n')
  })

  it('parses a UTF-8 BOM-prefixed file with LF endings', () => {
    const parsed = parseSkillMarkdown('\uFEFF---\nname: x\ndescription: y\n---\nbody\n')
    expect(parsed.frontmatter).toEqual({ name: 'x', description: 'y' })
    expect(parsed.body).toBe('body\n')
  })
})

describe('assertSafeRelPath', () => {
  it('accepts ordinary relative paths including unicode and colons', () => {
    expect(assertSafeRelPath('图 片:v1.png')).toBe('图 片:v1.png')
  })

  it('rejects traversal and absolute-ish segments', () => {
    expect(() => assertSafeRelPath('a/../b')).toThrow('ENTRY_PATH_INVALID')
    expect(() => assertSafeRelPath('/etc/passwd')).toThrow('ENTRY_PATH_INVALID')
    expect(() => assertSafeRelPath('a//b')).toThrow('ENTRY_PATH_INVALID')
    expect(() => assertSafeRelPath('a/./b')).toThrow('ENTRY_PATH_INVALID')
  })
})

describe('packSkillDir', () => {
  it('produces a verifiable pack whose body entry decrypts with the derived key', () => {
    const { file, manifest } = packSkillDir(goodDir(), base)
    const parsed = readContainer(file)
    expect(parsed.manifest.pack_id).toBe(base.packId)
    expect(parsed.manifest.entries.map((e) => e.id).sort()).toEqual([
      'data:glossary.json', 'meta', 'script:translate:run.py',
      'skill:translate:body', 'skill:translate:res:logo.png',
    ])
    expect(verifyManifestSignature(parsed.manifestBytes, parsed.signature, author.publicKey)).toBe(true)
    expect(manifest.entry_count).toBe(parsed.chunks.length)

    const id = 'skill:translate:body'
    const chunk = parsed.chunks.find((c) => c.id === id)!
    const key = deriveEntryKey(master, base.packId, base.version, id)
    expect(openEntry(key, entryAad(base.packId, base.version, id), chunk.nonce, chunk.ct).toString('utf8'))
      .toBe('把用户输入翻译成英文。\n')
  })

  it('keeps binary resources byte-exact and records type as a role, not an encoding', () => {
    const parsed = readContainer(packSkillDir(goodDir(), base).file)
    const id = 'skill:translate:res:logo.png'
    const chunk = parsed.chunks.find((c) => c.id === id)!
    const plain = openEntry(deriveEntryKey(master, base.packId, base.version, id), entryAad(base.packId, base.version, id), chunk.nonce, chunk.ct)
    expect(plain.equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x00, 0xff, 0xfe]))).toBe(true)
  })

  it('rejects a directory without SKILL.md', () => {
    expect(() => packSkillDir(skillDir({ 'scripts/a.py': 'x' }), base)).toThrow('NO_SKILL_MD')
  })

  it('is deterministic apart from nonces', () => {
    const first = readContainer(packSkillDir(goodDir(), base).file).manifest
    const second = readContainer(packSkillDir(goodDir(), base).file).manifest
    expect(second).toEqual(first)
  })

  it('accepts unicode and colon-bearing file names deterministically', () => {
    // NTFS cannot store ':' in a file name (it separates an alternate data stream), so on
    // Windows the colon case is exercised through assertSafeRelPath instead of on disk.
    const fileName = process.platform === 'win32' ? '图 片 v1.png' : '图 片:v1.png'
    const dir = skillDir({ 'SKILL.md': '---\nname: t\ndescription: d\n---\nb\n', ['resources/' + fileName]: Buffer.from([1, 2, 3]) })
    const ids = readContainer(packSkillDir(dir, { ...base, packId: 'com.example.u' }).file).manifest.entries.map((e) => e.id)
    expect(ids).toContain('skill:t:res:' + fileName)
    expect(assertSafeRelPath('图 片:v1.png')).toBe('图 片:v1.png')
  })

  it('refuses an entry above the 32 MiB cap', () => {
    const dir = skillDir({ 'SKILL.md': '---\nname: big\ndescription: d\n---\nb\n', 'data/huge.bin': Buffer.alloc(33 * 1024 * 1024, 1) })
    expect(() => packSkillDir(dir, { ...base, packId: 'com.example.big' })).toThrow('TOO_LARGE')
  })

  it('inspects without any key able to decrypt', () => {
    const info = inspectPack(packSkillDir(goodDir(), base).file, author.publicKey)
    expect(info.signatureValid).toBe(true)
    expect(info.chunks).toBe(5)
  })

  it('encrypts a meta entry describing the skill for the runtime', () => {
    const parsed = readContainer(packSkillDir(goodDir(), base).file)
    const chunk = parsed.chunks.find((c) => c.id === 'meta')!
    const ck = deriveEntryKey(master, base.packId, base.version, 'meta')
    let metaText: string
    try {
      metaText = openEntry(ck, entryAad(base.packId, base.version, 'meta'), chunk.nonce, chunk.ct).toString('utf8')
    } finally {
      ck.fill(0)
    }
    const meta = JSON.parse(metaText)
    expect(meta.skills[0].name).toBe('translate')
    expect(meta.skills[0].description).toBe('翻译文本')
    expect(meta.skills[0].whenToUse).toBe('需要翻译时')
    expect(meta.skills[0].invocation).toEqual({ modelInvocable: true, userInvocable: true })
    expect(meta.resources).toEqual({ 'skill:translate:res:logo.png': 'logo.png' })
    expect(meta.skills[0].entries).toContain('skill:translate:body')
    expect(meta.skills[0].entries).toContain('script:translate:run.py')
  })
})
