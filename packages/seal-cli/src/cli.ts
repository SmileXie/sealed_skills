#!/usr/bin/env node
import { createPublicKey, randomBytes } from 'node:crypto'
import { existsSync, readFileSync, writeFileSync } from 'node:fs'
import { pathToFileURL } from 'node:url'
import { readContainer } from '@sealed/pack-format'
import { x25519PublicFromRaw } from '@sealed/license-format'
import { AUTHOR_KEY_FILE, generateAuthorKey, loadAuthorKey, saveAuthorKey } from './author-key.js'
import { encodeMasterFile, parseMasterFile } from './master.js'
import { inspectPack, packSkillDir } from './pack.js'
import { makeTrialLicense } from './trial.js'

/** Thrown for invalid command-line input. */
export class CliError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'CliError'
  }
}

export type SealCommand =
  | { kind: 'keygen'; out: string }
  | { kind: 'pack'; dir: string; out: string; packId: string; version: string; label: string; key: string; trial: string[] }
  | { kind: 'inspect'; pack: string; authorPub?: string }
  | { kind: 'trial'; pack: string; master: string; devicePub: string; days: number; key: string; out?: string }

export const USAGE = [
  'usage: seal <command> [options]',
  '',
  '  seal keygen [-o author.key.json]',
  '  seal pack <dir> -o <out.sealedpack> --pack-id <id> --version <v> --label <l> --key <author.key.json> [--trial <id,id>]',
  '  seal inspect <pack> [--author-pub <b64url>]',
  '  seal trial <pack> --master <x.master.json> --device-pub <b64url> --days <n> --key <author.key.json> [-o <out.license>]   # local trial; the author key is the license signer',
  '',
].join('\n')

interface Tokens {
  positionals: string[]
  options: Map<string, string>
}

function parseTokens(args: string[]): Tokens {
  const positionals: string[] = []
  const options = new Map<string, string>()
  for (let i = 0; i < args.length; i++) {
    const token = args[i]
    if (token === '--help' || token === '-h') {
      options.set('--help', '')
      continue
    }
    if (token.startsWith('-')) {
      const next = args[i + 1]
      if (next === undefined || next.startsWith('-')) throw new CliError('missing value for ' + token)
      options.set(token, next)
      i++
    } else {
      positionals.push(token)
    }
  }
  return { positionals, options }
}

function opt(tokens: Tokens, names: string[]): string | undefined {
  for (const name of names) {
    const value = tokens.options.get(name)
    if (value !== undefined) return value
  }
  return undefined
}

function required(tokens: Tokens, names: string[], label: string): string {
  const value = opt(tokens, names)
  if (value === undefined || value === '') throw new CliError('missing required ' + label)
  return value
}

/** Parse argv (without `node` / script) into a validated command. Pure; throws CliError. */
export function parseArgs(argv: string[]): SealCommand {
  const [command, ...rest] = argv
  const tokens = parseTokens(rest)
  switch (command) {
    case 'keygen': {
      const out = opt(tokens, ['-o', '--out']) ?? tokens.positionals[0] ?? AUTHOR_KEY_FILE
      return { kind: 'keygen', out }
    }
    case 'pack': {
      const dir = tokens.positionals[0]
      if (!dir) throw new CliError('missing required <dir>')
      const out = required(tokens, ['-o', '--out'], '<out.sealedpack> (-o)')
      const trial = (opt(tokens, ['--trial']) ?? '').split(',').map((id) => id.trim()).filter((id) => id.length > 0)
      return {
        kind: 'pack',
        dir,
        out,
        packId: required(tokens, ['--pack-id'], '--pack-id'),
        version: required(tokens, ['--version'], '--version'),
        label: required(tokens, ['--label'], '--label'),
        key: required(tokens, ['--key'], '--key'),
        trial,
      }
    }
    case 'inspect': {
      const pack = tokens.positionals[0]
      if (!pack) throw new CliError('missing required <pack>')
      const authorPub = opt(tokens, ['--author-pub'])
      return authorPub === undefined ? { kind: 'inspect', pack } : { kind: 'inspect', pack, authorPub }
    }
    case 'trial': {
      const pack = tokens.positionals[0]
      if (!pack) throw new CliError('missing required <pack>')
      const daysRaw = required(tokens, ['--days'], '--days')
      const days = Number(daysRaw)
      if (!Number.isInteger(days) || days <= 0) throw new CliError('--days must be a positive integer (got ' + daysRaw + ')')
      const out = opt(tokens, ['-o', '--out'])
      return {
        kind: 'trial',
        pack,
        master: required(tokens, ['--master'], '--master'),
        devicePub: required(tokens, ['--device-pub'], '--device-pub'),
        days,
        key: required(tokens, ['--key'], '--key'),
        ...(out === undefined ? {} : { out }),
      }
    }
    default:
      throw new CliError('unknown command: ' + (command ?? '(none)'))
  }
}

/** Map low-level packer errors to actionable, non-secret messages. */
function actionable(error: unknown): string {
  const message = error instanceof Error ? error.message : String(error)
  if (message === 'NO_SKILL_MD') return 'no SKILL.md found in the skill directory (expected <dir>/SKILL.md)'
  if (message === 'SKILL_MD_NO_FRONTMATTER') return 'SKILL.md has no --- frontmatter block (name and description are required)'
  if (message === 'SKILL_MD_BAD_FRONTMATTER') return 'SKILL.md frontmatter must define name and description'
  return message
}

export interface CliIo {
  stdout: (chunk: string) => void
  stderr: (chunk: string) => void
}

/** Run one CLI command. Returns a process exit code; never throws. */
export async function main(argv: string[], io: CliIo): Promise<number> {
  let cmd: SealCommand
  try {
    cmd = parseArgs(argv)
  } catch (error) {
    io.stderr('seal: ' + actionable(error) + '\n')
    io.stderr(USAGE)
    return 2
  }
  try {
    switch (cmd.kind) {
      case 'keygen': {
        if (existsSync(cmd.out)) throw new CliError('refusing to overwrite existing author key: ' + cmd.out)
        const key = generateAuthorKey()
        saveAuthorKey(cmd.out, key)
        io.stdout('author key written: ' + cmd.out + '\npublic key (b64url): ' + key.publicKeyB64 + '\n')
        return 0
      }
      case 'pack': {
        const key = loadAuthorKey(cmd.key)
        const master = randomBytes(32)
        const { file, manifest } = packSkillDir(cmd.dir, {
          packId: cmd.packId, version: cmd.version, label: cmd.label, master,
          trialEntryIds: cmd.trial, authorPrivateKey: key.privateKey,
        })
        writeFileSync(cmd.out, file)
        const masterPath = cmd.out + '.master.json'
        writeFileSync(masterPath, encodeMasterFile(manifest, master), { encoding: 'utf8', mode: 0o600 })
        io.stdout('pack written: ' + cmd.out + '\nmaster key written (server-only): ' + masterPath + '\nentries: ' + manifest.entries.map((e) => e.id).join(', ') + '\n')
        return 0
      }
      case 'inspect': {
        const authorKey = cmd.authorPub === undefined
          ? undefined
          : createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: cmd.authorPub }, format: 'jwk' })
        const info = inspectPack(readFileSync(cmd.pack), authorKey)
        const summary = {
          pack_id: info.manifest.pack_id,
          version: info.manifest.version,
          label: info.manifest.label,
          entry_count: info.manifest.entry_count,
          entries: info.manifest.entries,
          chunks: info.chunks,
          signatureValid: info.signatureValid ?? null,
        }
        io.stdout(JSON.stringify(summary, null, 2) + '\n')
        return 0
      }
      case 'trial': {
        const manifest = readContainer(readFileSync(cmd.pack)).manifest
        const masterFile = parseMasterFile(readFileSync(cmd.master, 'utf8'))
        if (masterFile.packId !== manifest.pack_id || masterFile.version !== manifest.version) {
          throw new CliError('master file is for ' + masterFile.packId + '@' + masterFile.version + ', but the pack is ' + manifest.pack_id + '@' + manifest.version)
        }
        const key = loadAuthorKey(cmd.key)
        const devicePublicKey = x25519PublicFromRaw(Buffer.from(cmd.devicePub, 'base64url'))
        const trialEntryIds = manifest.entries.filter((entry) => entry.trial).map((entry) => entry.id)
        const license = makeTrialLicense({
          manifest, master: masterFile.master, devicePublicKey, trialEntryIds, days: cmd.days, signingKey: key.privateKey,
        })
        const outPath = cmd.out ?? cmd.pack.replace(/\.sealedpack$/, '') + '.license'
        writeFileSync(outPath, license, 'utf8')
        io.stdout('trial license written: ' + outPath + '\ntrial entries: ' + trialEntryIds.join(', ') + '\n')
        return 0
      }
    }
    return 0
  } catch (error) {
    io.stderr('seal: ' + actionable(error) + '\n')
    return 1
  }
}

const invoked = process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href
if (invoked) {
  void main(process.argv.slice(2), {
    stdout: (chunk) => process.stdout.write(chunk),
    stderr: (chunk) => process.stderr.write(chunk),
  }).then((code) => { process.exitCode = code })
}