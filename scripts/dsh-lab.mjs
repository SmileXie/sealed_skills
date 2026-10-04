#!/usr/bin/env node
// Sealed Skills — optional out-of-tree dsh lab.
//
// Why this exists: real-harness integration needs @deepseek-ai/dsh (~462 MB), which must
// NOT enter the repo dependency graph. This script installs the harness into a git-ignored
// `.dsh-lab/` directory, generates a dsh profile that mounts our *built* plugin bundle, and
// exposes objective self-checks (`--dump-config`, `--headless`).
//
// Everything is idempotent and offline-cacheable. Nothing here writes skill plaintext or key
// material. The lab is opt-in: tests that need it skip loudly unless SEALED_DSH_LAB=1.
//
// Usage:
//   node scripts/dsh-lab.mjs --ensure [--force]     install + (re)generate the profile
//   node scripts/dsh-lab.mjs --dump-config          compose and print the profile tree
//   node scripts/dsh-lab.mjs --version              print the pinned dsh version
//   node scripts/dsh-lab.mjs --headless "<task>"    run a one-shot headless task
//   node scripts/dsh-lab.mjs --clean                remove .dsh-lab/ (path-checked)
//   node scripts/dsh-lab.mjs --help

import { spawnSync } from 'node:child_process'
import { existsSync, lstatSync, mkdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
import { basename, dirname, join, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

/** Pinned harness version. Kept in one place; bump alongside the peer declarations. */
export const DSH_VERSION = '0.2.0-rc.2'

const HERE = dirname(fileURLToPath(import.meta.url))
/** Repository root (this script lives in `scripts/`). */
export const REPO_ROOT = resolve(HERE, '..')
/** Git-ignored lab root. Nothing outside this directory is ever written. */
export const LAB_DIR = join(REPO_ROOT, '.dsh-lab')
/** DSH_HOME for the lab, so profiles/sessions stay inside `.dsh-lab/`. */
export const DSH_HOME = join(LAB_DIR, 'home')
/** SEALED_HOME for the mounted plugin, so its keystore stays inside `.dsh-lab/`. */
export const SEALED_HOME = join(LAB_DIR, 'sealed')
export const PROFILE_NAME = 'm3-lab'
export const PROFILE_DIR = join(DSH_HOME, 'profiles', PROFILE_NAME)
/** Bundle shim name (a generated wrapper; our real package does not ship `dsh.bundle` yet). */
export const BUNDLE_NAME = '@sealed-lab/dsh-sealed-skills-lab'
export const BUNDLE_DIR = join(PROFILE_DIR, 'node_modules', '@sealed-lab', 'dsh-sealed-skills-lab')
export const DSH_BIN = join(LAB_DIR, 'node_modules', '@deepseek-ai', 'dsh', 'lib', 'bin.js')
const NPM_CACHE = join(LAB_DIR, 'npm-cache')
const PLUGIN_PKG_DIR = join(REPO_ROOT, 'packages', 'dsh-sealed-skills')
const PLUGIN_DIST = join(PLUGIN_PKG_DIR, 'dist', 'index.js')
const PLUGIN_ID = 'sealed-skills'

function log(message) {
  process.stderr.write(`dsh-lab: ${message}\n`)
}

function fail(message, code = 1) {
  process.stderr.write(`dsh-lab: ${message}\n`)
  process.exit(code)
}

function writeFile(file, text) {
  mkdirSync(dirname(file), { recursive: true })
  writeFileSync(file, text)
}

function readJson(file) {
  return JSON.parse(readFileSync(file, 'utf8'))
}

function installedDshVersion() {
  const manifest = join(LAB_DIR, 'node_modules', '@deepseek-ai', 'dsh', 'package.json')
  if (!existsSync(manifest)) return undefined
  try {
    return readJson(manifest).version
  } catch {
    return undefined
  }
}

function toPosix(value) {
  return value.replace(/\\/g, '/')
}

/** Read the plugin's own peer declarations so the shim exercises the real compat gate. */
function pluginPeerDependencies() {
  const manifest = join(PLUGIN_PKG_DIR, 'package.json')
  if (!existsSync(manifest)) fail(`plugin package not found at ${manifest}`)
  return readJson(manifest).peerDependencies ?? {}
}

/**
 * Optional mounts, so later tasks can point the profile at a real pack/license without
 * hand-editing generated files. Set SEALED_DSH_LAB_MOUNTS_FILE to a JSON file holding the
 * `SealedPackMount[]` array. The lab only reads that file; keep it out of version control.
 */
function loadMounts() {
  const file = process.env.SEALED_DSH_LAB_MOUNTS_FILE
  if (!file) return []
  if (!existsSync(file)) fail(`SEALED_DSH_LAB_MOUNTS_FILE points at a missing file: ${file}`)
  const parsed = JSON.parse(readFileSync(file, 'utf8'))
  if (!Array.isArray(parsed)) fail(`${file} must contain a JSON array of mounts`)
  return parsed
}

/**
 * Our real package's dsh bundle declaration, when it ships one. With it the lab mounts the
 * genuine `@sealed/dsh-sealed-skills` bundle (junctioned into the profile node_modules);
 * without it the lab falls back to a generated shim that copies our peer declarations.
 */
function pluginBundle() {
  const manifest = join(PLUGIN_PKG_DIR, 'package.json')
  if (!existsSync(manifest)) fail(`plugin package not found at ${manifest}`)
  const pkg = readJson(manifest)
  const patch = pkg.dsh?.bundle?.patch
  if (typeof pkg.name !== 'string' || typeof patch !== 'string') return undefined
  return { name: pkg.name, patch }
}

/**
 * Optional extra plugin config so tests can supply license-server settings without
 * hand-editing generated files. Set SEALED_DSH_LAB_PLUGIN_CONFIG_FILE to a JSON object;
 * `keystoreDir` and `mounts` are always overwritten with this lab's values.
 */
function loadPluginConfig() {
  const file = process.env.SEALED_DSH_LAB_PLUGIN_CONFIG_FILE
  if (!file) return {}
  if (!existsSync(file)) fail(`SEALED_DSH_LAB_PLUGIN_CONFIG_FILE points at a missing file: ${file}`)
  const parsed = JSON.parse(readFileSync(file, 'utf8'))
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    fail(`${file} must contain a JSON object of plugin config`)
  }
  return parsed
}

/** Junction our real package into the profile node_modules (link-only; safe to remove). */
function linkRealBundle(profileDir) {
  const scope = join(profileDir, 'node_modules', '@sealed')
  const link = join(scope, 'dsh-sealed-skills')
  mkdirSync(scope, { recursive: true })
  if (existsSync(link)) {
    if (!lstatSync(link).isSymbolicLink()) {
      fail(`refusing to replace ${toPosix(link)}: it exists and is not a link`)
    }
    rmSync(link, { recursive: true, force: true })
  }
  symlinkSync(PLUGIN_PKG_DIR, link, 'junction')
  return link
}

/**
 * Run npm inside the lab. Prefers npm's JavaScript entrypoint beside the running node binary
 * (no shell, no DEP0190), and falls back to the platform shim only if that file is absent.
 */
function runNpm(args) {
  const env = { ...process.env, npm_config_cache: NPM_CACHE }
  const cli = join(dirname(process.execPath), 'node_modules', 'npm', 'bin', 'npm-cli.js')
  if (existsSync(cli)) {
    return spawnSync(process.execPath, [cli, ...args], { cwd: LAB_DIR, encoding: "utf8", env })
  }
  return spawnSync('npm', args, { cwd: LAB_DIR, encoding: 'utf8', shell: process.platform === 'win32', env })
}

function ensureDependency(force) {
  const current = installedDshVersion()
  if (!force && current === DSH_VERSION) {
    log(`dsh ${DSH_VERSION} already installed — skipping install (offline fast path)`)
    return
  }
  if (force && current !== undefined) log(`--force: reinstalling dsh ${DSH_VERSION}`)
  if (!existsSync(PLUGIN_DIST)) {
    fail(`built plugin not found at ${PLUGIN_DIST}. Run "corepack pnpm -r build" first.`)
  }
  mkdirSync(LAB_DIR, { recursive: true })
  writeFile(
    join(LAB_DIR, 'package.json'),
    `${JSON.stringify(
      {
        name: 'sealed-skills-dsh-lab',
        version: '0.0.0',
        private: true,
        description: 'GENERATED by scripts/dsh-lab.mjs — the optional out-of-tree dsh harness.',
        dependencies: { '@deepseek-ai/dsh': DSH_VERSION },
      },
      null,
      2,
    )}\n`,
  )
  log(`installing @deepseek-ai/dsh@${DSH_VERSION} into .dsh-lab (large, one-time; cached afterwards)`)
  const result = runNpm(['install', '--no-audit', '--no-fund', '--loglevel=error', '--prefer-offline'])
  if (result.error) {
    fail(`could not run npm (${result.error.message}). Node.js >= 20 with npm on PATH is required.`)
  }
  if (result.status !== 0) {
    const detail = `${result.stderr ?? ''}${result.stdout ?? ''}`.trim()
    const network = /(ENOTFOUND|EAI_AGAIN|ETIMEDOUT|ECONNREFUSED|network|registry|fetch failed)/i.test(detail)
    const reason = network
      ? 'the npm registry is unreachable (no network / proxy / offline). Reconnect and retry, or pre-populate .dsh-lab/npm-cache.'
      : 'npm install failed. See the output above.'
    fail(`${reason}\n${detail}`)
  }
  const after = installedDshVersion()
  if (after !== DSH_VERSION) {
    fail(`npm install finished but @deepseek-ai/dsh@${DSH_VERSION} is not present (found ${after ?? 'nothing'}).`)
  }
  log(`installed dsh ${after}`)
}
/**
 * Generate (idempotently) the profile that mounts our built plugin.
 *
 * Preferred mount: our *genuine* package identity. When `packages/dsh-sealed-skills` declares
 * `dsh.bundle`, the lab junctions that package into the profile's own `node_modules` and lists
 * `@sealed/dsh-sealed-skills` in `dsh.profile.bundles`, so app-boot's bundle resolver and its dsh
 * peer compatibility gate see the real package. This profile's pack configuration rides the
 * profile's own patch layer, targeting the `sealed-skills` row our shipped bundle patch inserts.
 *
 * Fallback (no `dsh.bundle`): a generated *bundle shim* in the profile `node_modules` that copies
 * our real peer declarations and inserts our plugin row by absolute `file://` URL.
 */
function writeProfileFiles() {
  if (!existsSync(PLUGIN_DIST)) {
    fail(`built plugin not found at ${PLUGIN_DIST}. Run "corepack pnpm -r build" first.`)
  }
  const mounts = loadMounts()
  const pluginConfig = { ...loadPluginConfig(), keystoreDir: toPosix(SEALED_HOME), mounts }
  const real = pluginBundle()
  const bundle = real ?? { name: BUNDLE_NAME, patch: './cordis.patch.yml' }
  writeFile(
    join(PROFILE_DIR, 'package.json'),
    `${JSON.stringify(
      {
        name: `dsh-profile-${PROFILE_NAME}`,
        version: '0.0.0',
        private: true,
        dependencies: {},
        dsh: {
          profile: {
            bundles: ['@deepseek-ai/dsh-base', '@deepseek-ai/dsh-headless', bundle.name],
          },
        },
      },
      null,
      2,
    )}\n`,
  )
  writeFile(join(PROFILE_DIR, 'cordis.yml'), '# dsh profile root — composed from the bundle patch layers.\n[]\n')
  // The profile's own patch layer carries this profile's pack configuration; it targets the
  // `sealed-skills` row a bundle layer inserts and is applied after every bundle layer.
  writeFile(
    join(PROFILE_DIR, 'cordis.patch.yml'),
    [
      '# GENERATED by scripts/dsh-lab.mjs — re-run --ensure to regenerate. Do not edit by hand.',
      `- id: ${PLUGIN_ID}`,
      `  config: ${JSON.stringify(pluginConfig)}`,
      '',
    ].join('\n'),
  )
  writeFile(
    join(PROFILE_DIR, 'pnpm-workspace.yaml'),
    'packages:\n  - .\nnodeLinker: hoisted\nautoInstallPeers: false\n',
  )
  if (real) {
    linkRealBundle(PROFILE_DIR)
    // A previous run may have left the generated shim behind; drop it so only the real bundle resolves.
    rmSync(join(PROFILE_DIR, 'node_modules', '@sealed-lab'), { recursive: true, force: true })
  } else {
    writeFile(
      join(BUNDLE_DIR, 'package.json'),
      `${JSON.stringify(
        {
          name: BUNDLE_NAME,
          version: '0.0.0',
          private: true,
          type: 'module',
          description: 'GENERATED by scripts/dsh-lab.mjs — mounts @sealed/dsh-sealed-skills into this profile.',
          dsh: { bundle: { patch: './cordis.patch.yml' } },
          peerDependencies: pluginPeerDependencies(),
        },
        null,
        2,
      )}\n`,
    )
    writeFile(
      join(BUNDLE_DIR, 'cordis.patch.yml'),
      [
        '# GENERATED by scripts/dsh-lab.mjs — re-run --ensure to regenerate. Do not edit by hand.',
        '- insert:',
        `    - id: ${PLUGIN_ID}`,
        `      name: ${JSON.stringify(pathToFileURL(PLUGIN_DIST).href)}`,
        `      config: ${JSON.stringify(pluginConfig)}`,
        '',
      ].join('\n'),
    )
  }
  mkdirSync(SEALED_HOME, { recursive: true })
  log(`wrote profile ${toPosix(PROFILE_DIR)} (bundle ${bundle.name}, ${mounts.length} mount(s))`)
}

/** Install the harness if needed and (re)generate the profile. Idempotent. */
export function ensureLab({ force = false } = {}) {
  ensureDependency(force)
  writeProfileFiles()
}

function requireLab() {
  if (!existsSync(DSH_BIN)) {
    fail(`the lab is not installed at ${toPosix(DSH_BIN)}. Run: node scripts/dsh-lab.mjs --ensure`)
  }
}

function runDsh(args, { timeoutMs } = {}) {
  requireLab()
  return spawnSync(process.execPath, [DSH_BIN, ...args], {
    encoding: 'utf8',
    timeout: timeoutMs,
    killSignal: 'SIGKILL',
    env: { ...process.env, DSH_HOME, SEALED_HOME },
  })
}

function reportResult(result) {
  if (result.stdout) process.stdout.write(result.stdout)
  if (result.stderr) process.stderr.write(result.stderr)
}

function cmdVersion() {
  const result = runDsh(['--version'])
  reportResult(result)
  if (result.error) fail(`could not run dsh: ${result.error.message}`)
  return result.status ?? 1
}

function cmdDumpConfig() {
  const result = runDsh(['--profile', PROFILE_NAME, '--dump-config'], { timeoutMs: 60_000 })
  reportResult(result)
  if (result.error) fail(`dsh --dump-config did not run: ${result.error.message}`)
  if (result.status !== 0) return result.status ?? 1
  if (result.stdout?.includes(`id: ${PLUGIN_ID}`)) {
    log(`self-check: plugin "${PLUGIN_ID}" is mounted`)
  } else {
    log(`self-check: FAILED — plugin "${PLUGIN_ID}" is not in the composed config`)
    return 1
  }
  if (/skipping profile bundle/.test(result.stderr ?? '')) {
    log('self-check: FAILED — a profile bundle was skipped (see the dsh output above)')
    return 1
  }
  log('self-check: no profile bundle was skipped')
  return 0
}

const HEADLESS_TIMEOUT_MS = 180_000

function cmdHeadless(task) {
  if (!process.env.DEEPSEEK_API_KEY) {
    fail(
      'headless needs model credentials: the shipped profile routes to the "deepseek-official" provider.\n' +
        '  Set DEEPSEEK_API_KEY in the environment (or store credentials via the dsh web "Models" page), then retry.\n' +
        '  Refusing to boot without credentials so the run cannot hang on an interactive prompt.',
      3,
    )
  }
  const result = runDsh(['--profile', PROFILE_NAME, 'headless', task], { timeoutMs: HEADLESS_TIMEOUT_MS })
  reportResult(result)
  if (result.error?.code === 'ETIMEDOUT' || result.signal) {
    fail(`headless did not finish within ${HEADLESS_TIMEOUT_MS / 1000}s and was killed.`, 4)
  }
  if (result.error) fail(`could not run dsh headless: ${result.error.message}`)
  return result.status ?? 1
}

function cmdClean() {
  const target = resolve(LAB_DIR)
  // Guard: only ever delete the lab directory, resolved and verified, inside the repo root.
  if (target !== join(REPO_ROOT, '.dsh-lab') || dirname(target) !== REPO_ROOT || basename(target) !== '.dsh-lab') {
    fail(`refusing to clean: resolved path ${toPosix(target)} is not the lab directory`)
  }
  if (!existsSync(target)) {
    log('nothing to clean (.dsh-lab does not exist)')
    return 0
  }
  rmSync(target, { recursive: true, force: true })
  log(`removed ${toPosix(target)}`)
  return 0
}

function usage() {
  process.stdout.write(
    [
      'Sealed Skills — optional out-of-tree dsh lab',
      '',
      'Usage:',
      '  node scripts/dsh-lab.mjs --ensure [--force]     install + (re)generate the profile',
      '  node scripts/dsh-lab.mjs --dump-config          compose and print the profile tree',
      '  node scripts/dsh-lab.mjs --version              print the pinned dsh version',
      '  node scripts/dsh-lab.mjs --headless "<task>"    run a one-shot headless task',
      '  node scripts/dsh-lab.mjs --clean                remove .dsh-lab/ (path-checked)',
      '  node scripts/dsh-lab.mjs --help',
      '',
      'Env: SEALED_DSH_LAB=1 enables the gated tests; SEALED_DSH_LAB_MOUNTS_FILE points at a',
      '     JSON mounts array; DEEPSEEK_API_KEY is required for --headless.',
      '',
      `Everything lives under ${toPosix(LAB_DIR)} (git-ignored); nothing outside it is written.`,
      '',
    ].join('\n'),
  )
}

export function main(argv = process.argv.slice(2)) {
  const has = (flag) => argv.includes(flag)
  if (argv.length === 0 || has('--help') || has('-h')) {
    usage()
    return 0
  }
  if (has('--clean')) return cmdClean()

  const headlessAt = argv.indexOf('--headless')
  const headlessTask = headlessAt === -1 ? undefined : argv[headlessAt + 1]
  if (headlessAt !== -1 && (headlessTask === undefined || headlessTask.startsWith('--'))) {
    fail('--headless requires a task string, e.g. --headless "say hello"')
  }

  const needsLab = has('--ensure') || has('--dump-config') || headlessAt !== -1
  if (needsLab) ensureLab({ force: has('--force') })

  if (has('--version')) return cmdVersion()
  if (has('--dump-config')) return cmdDumpConfig()
  if (headlessAt !== -1) return cmdHeadless(headlessTask)
  if (has('--ensure')) return 0

  usage()
  return 0
}

// Run only when invoked directly, so tests can import the helpers above.
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = main()
}
