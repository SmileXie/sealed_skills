import type { KeyObject } from 'node:crypto'
import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join, relative, sep } from 'node:path'
import {
  MAX_ENTRY_BYTES, deriveEntryKey, entryAad, readContainer, sealEntry, signManifest, verifyManifestSignature, writeContainer,
  type PackEntryMeta, type PackManifest,
} from '@sealed/pack-format'
import { parseSkillMarkdown } from './frontmatter.js'
import { assertSafeRelPath } from './paths.js'

export function packSkillDir(dir: string, opts: {
  packId: string
  version: string
  label: string
  master: Buffer
  trialEntryIds: string[]
  authorPrivateKey: KeyObject
}): { file: Buffer; manifest: PackManifest; master: Buffer } {
  let skillText: string
  try {
    skillText = readFileSync(join(dir, 'SKILL.md'), 'utf8')
  } catch {
    throw new Error('NO_SKILL_MD')
  }
  const { frontmatter, body } = parseSkillMarkdown(skillText)
  const name = frontmatter.name as string

  const entries: { id: string; type: PackEntryMeta['type']; bytes: Buffer }[] = [
    { id: 'meta', type: 'meta', bytes: Buffer.alloc(0) },
    { id: 'skill:' + name + ':body', type: 'text', bytes: Buffer.from(body, 'utf8') },
  ]
  const resources: Record<string, string> = {}
  const roots: [string, string, PackEntryMeta['type']][] = [
    ['resources', 'skill:' + name + ':res:', 'text'],
    ['scripts', 'script:' + name + ':', 'script'],
    ['data', 'data:', 'data'],
  ]
  for (const [subdir, prefix, type] of roots) {
    const root = join(dir, subdir)
    let files: string[] = []
    try { if (statSync(root).isDirectory()) files = walk(root) } catch { continue }
    for (const abs of files) {
      const rel = assertSafeRelPath(relative(root, abs).split(sep).join('/'))
      const id = prefix + rel
      entries.push({ id, type, bytes: readFileSync(abs) })
      if (subdir === 'resources') resources[id] = rel
    }
  }

  const meta = {
    skills: [{
      name,
      description: frontmatter.description as string,
      ...(typeof frontmatter.whenToUse === 'string' ? { whenToUse: frontmatter.whenToUse } : {}),
      invocation: {
        modelInvocable: frontmatter['disable-model-invocation'] !== true,
        userInvocable: frontmatter['user-invocable'] !== false,
      },
      entries: entries
        .filter((e) => e.id.startsWith('skill:' + name + ':') || e.id.startsWith('script:' + name + ':'))
        .map((e) => e.id),
    }],
    resources,
  }
  entries[0] = { id: 'meta', type: 'meta', bytes: Buffer.from(JSON.stringify(meta), 'utf8') }
  entries.sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0))

  const manifest: PackManifest = { pack_id: opts.packId, version: opts.version, label: opts.label, entry_count: entries.length, entries: [] }
  const chunks: { id: string; nonce: Buffer; ct: Buffer }[] = []
  for (const entry of entries) {
    if (entry.bytes.length > MAX_ENTRY_BYTES) throw new Error('TOO_LARGE: ' + entry.id)
    const sealed = sealEntry(deriveEntryKey(opts.master, opts.packId, opts.version, entry.id), entryAad(opts.packId, opts.version, entry.id), entry.bytes)
    manifest.entries.push({ id: entry.id, type: entry.type, size: sealed.ct.length, trial: opts.trialEntryIds.includes(entry.id) })
    chunks.push({ id: entry.id, nonce: sealed.nonce, ct: sealed.ct })
  }
  const signature = signManifest(Buffer.from(JSON.stringify(manifest), 'utf8'), opts.authorPrivateKey)
  return { file: writeContainer({ manifest, chunks, signature }), manifest, master: opts.master }
}

export function inspectPack(file: Buffer, authorPublicKey?: KeyObject): { manifest: PackManifest; signatureValid: boolean | undefined; chunks: number } {
  const parsed = readContainer(file)
  return {
    manifest: parsed.manifest,
    signatureValid: authorPublicKey ? verifyManifestSignature(parsed.manifestBytes, parsed.signature, authorPublicKey) : undefined,
    chunks: parsed.chunks.length,
  }
}

function walk(root: string): string[] {
  const out: string[] = []
  for (const name of readdirSync(root)) {
    const abs = join(root, name)
    if (statSync(abs).isDirectory()) out.push(...walk(abs))
    else out.push(abs)
  }
  return out
}
