import { DatabaseSync } from 'node:sqlite'
import { ServerError } from './server-errors.js'

export interface PackRecord {
  packId: string; version: string; label: string; authorPub: string
  masterWrapped: string; trialEntries: string[]; entries: { id: string; type: string; size: number }[]
}
export interface LicenseRecord {
  licenseId: string; sub: string; packId: string; version: string; devicePub: string
  caps: string[]; plan: string; seatLimit: number; iat: number; exp: number; graceUntil: number; revoked: boolean
}
export interface PurchaseRecord { token: string; sub: string; packId: string; version: string; plan: string; seats: number; expiresAt?: number }
export interface SeatRecord { sub: string; packId: string; version: string; devicePub: string; licenseId: string }
export interface AuditRecord { at: number; action: string; actor: string; subject: string; detail: string }

const SCHEMA = `
CREATE TABLE IF NOT EXISTS packs (
  pack_id TEXT NOT NULL, version TEXT NOT NULL, label TEXT NOT NULL, author_pub TEXT NOT NULL,
  master_wrapped TEXT NOT NULL, trial_entries TEXT NOT NULL, entries TEXT NOT NULL,
  created_at INTEGER NOT NULL, PRIMARY KEY (pack_id, version));
CREATE TABLE IF NOT EXISTS purchases (
  token TEXT PRIMARY KEY, sub TEXT NOT NULL, pack_id TEXT NOT NULL, version TEXT NOT NULL,
  plan TEXT NOT NULL, seats INTEGER NOT NULL, expires_at INTEGER);
CREATE TABLE IF NOT EXISTS devices (
  device_pub TEXT PRIMARY KEY, sub TEXT NOT NULL, created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS seats (
  sub TEXT NOT NULL, pack_id TEXT NOT NULL, version TEXT NOT NULL, device_pub TEXT NOT NULL,
  license_id TEXT NOT NULL, created_at INTEGER NOT NULL,
  PRIMARY KEY (sub, pack_id, version, device_pub));
CREATE TABLE IF NOT EXISTS licenses (
  license_id TEXT PRIMARY KEY, sub TEXT NOT NULL, pack_id TEXT NOT NULL, version TEXT NOT NULL,
  device_pub TEXT NOT NULL, caps TEXT NOT NULL, plan TEXT NOT NULL, seat_limit INTEGER NOT NULL,
  iat INTEGER NOT NULL, exp INTEGER NOT NULL, grace_until INTEGER NOT NULL,
  revoked INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS trials (
  device_pub TEXT NOT NULL, pack_id TEXT NOT NULL, version TEXT NOT NULL, license_id TEXT NOT NULL,
  created_at INTEGER NOT NULL, PRIMARY KEY (device_pub, pack_id, version));
CREATE TABLE IF NOT EXISTS nonces (
  license_id TEXT NOT NULL, nonce TEXT NOT NULL, seen_at INTEGER NOT NULL,
  PRIMARY KEY (license_id, nonce));
CREATE TABLE IF NOT EXISTS audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT, at INTEGER NOT NULL, action TEXT NOT NULL,
  actor TEXT NOT NULL, subject TEXT NOT NULL, detail TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS idempotency (
  key TEXT PRIMARY KEY, response TEXT NOT NULL, created_at INTEGER NOT NULL);
`

interface PackDbRow { pack_id: string; version: string; label: string; author_pub: string; master_wrapped: string; trial_entries: string; entries: string }
interface LicenseDbRow {
  license_id: string; sub: string; pack_id: string; version: string; device_pub: string
  caps: string; plan: string; seat_limit: number; iat: number; exp: number; grace_until: number; revoked: number
}

export class Store {
  private readonly db: DatabaseSync
  constructor(path: string) {
    this.db = new DatabaseSync(path)
    this.db.exec(SCHEMA)
  }

  close(): void { this.db.close() }

  putPack(record: PackRecord, now = Date.now()): void {
    this.db.prepare(
      `INSERT INTO packs (pack_id, version, label, author_pub, master_wrapped, trial_entries, entries, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(pack_id, version) DO UPDATE SET label=excluded.label, author_pub=excluded.author_pub,
         master_wrapped=excluded.master_wrapped, trial_entries=excluded.trial_entries, entries=excluded.entries`,
    ).run(record.packId, record.version, record.label, record.authorPub, record.masterWrapped,
      JSON.stringify(record.trialEntries), JSON.stringify(record.entries), now)
  }

  getPack(packId: string, version: string): PackRecord | undefined {
    const row = this.db.prepare('SELECT * FROM packs WHERE pack_id = ? AND version = ?').get(packId, version) as PackDbRow | undefined
    if (!row) return undefined
    return {
      packId: row.pack_id, version: row.version, label: row.label, authorPub: row.author_pub,
      masterWrapped: row.master_wrapped, trialEntries: JSON.parse(row.trial_entries) as string[],
      entries: JSON.parse(row.entries) as { id: string; type: string; size: number }[],
    }
  }

  putPurchase(record: PurchaseRecord): void {
    this.db.prepare('INSERT INTO purchases (token, sub, pack_id, version, plan, seats, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)')
      .run(record.token, record.sub, record.packId, record.version, record.plan, record.seats, record.expiresAt ?? null)
  }

  getPurchase(token: string): PurchaseRecord | undefined {
    const row = this.db.prepare('SELECT * FROM purchases WHERE token = ?').get(token) as
      | { token: string; sub: string; pack_id: string; version: string; plan: string; seats: number; expires_at: number | null }
      | undefined
    if (!row) return undefined
    return { token: row.token, sub: row.sub, packId: row.pack_id, version: row.version, plan: row.plan, seats: row.seats, ...(row.expires_at !== null ? { expiresAt: row.expires_at } : {}) }
  }

  upsertDevice(devicePub: string, sub: string, now = Date.now()): void {
    this.db.prepare('INSERT INTO devices (device_pub, sub, created_at) VALUES (?, ?, ?) ON CONFLICT(device_pub) DO UPDATE SET sub=excluded.sub')
      .run(devicePub, sub, now)
  }

  countSeats(sub: string, packId: string, version: string): number {
    const row = this.db.prepare('SELECT COUNT(*) AS n FROM seats WHERE sub = ? AND pack_id = ? AND version = ?').get(sub, packId, version) as { n: number }
    return row.n
  }

  putSeat(seat: SeatRecord, now = Date.now()): void {
    this.db.prepare('INSERT OR REPLACE INTO seats (sub, pack_id, version, device_pub, license_id, created_at) VALUES (?, ?, ?, ?, ?, ?)')
      .run(seat.sub, seat.packId, seat.version, seat.devicePub, seat.licenseId, now)
  }

  deleteSeat(sub: string, packId: string, version: string, devicePub: string): void {
    this.db.prepare('DELETE FROM seats WHERE sub = ? AND pack_id = ? AND version = ? AND device_pub = ?').run(sub, packId, version, devicePub)
  }

  deleteSeatsForSubject(sub: string): void { this.db.prepare('DELETE FROM seats WHERE sub = ?').run(sub) }

  putLicense(record: LicenseRecord): void {
    this.db.prepare(
      `INSERT OR REPLACE INTO licenses (license_id, sub, pack_id, version, device_pub, caps, plan, seat_limit, iat, exp, grace_until, revoked)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run(record.licenseId, record.sub, record.packId, record.version, record.devicePub,
      JSON.stringify(record.caps), record.plan, record.seatLimit, record.iat, record.exp, record.graceUntil, record.revoked ? 1 : 0)
  }

  private toLicense(row: LicenseDbRow): LicenseRecord {
    return {
      licenseId: row.license_id, sub: row.sub, packId: row.pack_id, version: row.version, devicePub: row.device_pub,
      caps: JSON.parse(row.caps) as string[], plan: row.plan, seatLimit: row.seat_limit,
      iat: row.iat, exp: row.exp, graceUntil: row.grace_until, revoked: row.revoked === 1,
    }
  }

  getLicense(licenseId: string): LicenseRecord | undefined {
    const row = this.db.prepare('SELECT * FROM licenses WHERE license_id = ?').get(licenseId) as LicenseDbRow | undefined
    return row ? this.toLicense(row) : undefined
  }

  getLicenseForDevice(packId: string, version: string, devicePub: string): LicenseRecord | undefined {
    const row = this.db.prepare('SELECT * FROM licenses WHERE pack_id = ? AND version = ? AND device_pub = ? AND revoked = 0').get(packId, version, devicePub) as LicenseDbRow | undefined
    return row ? this.toLicense(row) : undefined
  }

  markRevoked(licenseId: string): boolean {
    const result = this.db.prepare('UPDATE licenses SET revoked = 1 WHERE license_id = ?').run(licenseId)
    return Number(result.changes) > 0
  }

  getTrial(devicePub: string, packId: string, version: string): { licenseId: string } | undefined {
    const row = this.db.prepare('SELECT license_id FROM trials WHERE device_pub = ? AND pack_id = ? AND version = ?').get(devicePub, packId, version) as { license_id: string } | undefined
    return row ? { licenseId: row.license_id } : undefined
  }

  putTrial(devicePub: string, packId: string, version: string, licenseId: string, now = Date.now()): void {
    try {
      this.db.prepare('INSERT INTO trials (device_pub, pack_id, version, license_id, created_at) VALUES (?, ?, ?, ?, ?)').run(devicePub, packId, version, licenseId, now)
    } catch {
      throw new ServerError('TRIAL_ALREADY_USED', 'this device already used the trial for this pack')
    }
  }

  insertNonce(licenseId: string, nonce: string, seenAt: number): boolean {
    try {
      this.db.prepare('INSERT INTO nonces (license_id, nonce, seen_at) VALUES (?, ?, ?)').run(licenseId, nonce, seenAt)
      return true
    } catch {
      return false
    }
  }

  pruneNonces(minSeenAt: number, maxSeenAt: number): void {
    this.db.prepare('DELETE FROM nonces WHERE seen_at >= ? AND seen_at < ?').run(minSeenAt, maxSeenAt)
  }

  appendAudit(record: AuditRecord): void {
    this.db.prepare('INSERT INTO audit (at, action, actor, subject, detail) VALUES (?, ?, ?, ?, ?)').run(record.at, record.action, record.actor, record.subject, record.detail)
  }

  listAudit(): AuditRecord[] {
    const rows = this.db.prepare('SELECT at, action, actor, subject, detail FROM audit ORDER BY id').all() as unknown as AuditRecord[]
    return rows.map((row) => ({ at: row.at, action: row.action, actor: row.actor, subject: row.subject, detail: row.detail }))
  }

  putIdempotent(key: string, response: string, now = Date.now()): void {
    this.db.prepare('INSERT OR REPLACE INTO idempotency (key, response, created_at) VALUES (?, ?, ?)').run(key, response, now)
  }

  getIdempotent(key: string): string | undefined {
    const row = this.db.prepare('SELECT response FROM idempotency WHERE key = ?').get(key) as { response: string } | undefined
    return row?.response
  }
}

export function openStore(path: string): Store {
  return new Store(path)
}
