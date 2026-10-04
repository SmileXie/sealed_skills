import type { ProtocolErrorCode } from '@sealed/license-format'

export class ServerError extends Error {
  constructor(readonly code: ProtocolErrorCode, message: string) {
    super(message)
    this.name = 'ServerError'
  }
}
