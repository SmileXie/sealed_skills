export interface LicenseGrant { eid: string; eph: string; n: string; c: string }
export interface LicensePayload {
  v: 1
  lid: string
  sub: string
  pack: { id: string; version: string; author_pub: string }
  dev: string
  iat: number
  exp: number
  grace_until: number
  caps: ('trial' | 'full')[]
  groups: string[]
  keys: LicenseGrant[]
  seats: { plan: string; limit: number }
}
