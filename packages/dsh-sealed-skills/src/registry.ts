import { readdirSync } from 'node:fs'
import { join } from 'node:path'

export class PackRegistry {
  constructor(private readonly opts: { dir: string }) {}

  scan(): string[] {
    try {
      return readdirSync(this.opts.dir)
        .filter((file) => file.endsWith('.sealedpack'))
        .map((file) => join(this.opts.dir, file))
        .sort()
    } catch {
      return []
    }
  }
}
