import type { IncomingMessage, ServerResponse } from 'node:http'
import type { ProtocolErrorCode } from '@sealed/license-format'

export class HttpError extends Error {
  constructor(readonly status: number, readonly code: ProtocolErrorCode, message: string) {
    super(message)
    this.name = 'HttpError'
  }
}

export const MAX_BODY_BYTES = 1_048_576

export async function readJsonBody(req: IncomingMessage, limit = MAX_BODY_BYTES): Promise<unknown> {
  const chunks: Buffer[] = []
  let size = 0
  for await (const chunk of req) {
    const buf = chunk as Buffer
    size += buf.length
    if (size > limit) {
      req.resume()
      throw new HttpError(413, 'BAD_REQUEST', 'request body is too large')
    }
    chunks.push(buf)
  }
  if (size === 0) return undefined
  try {
    return JSON.parse(Buffer.concat(chunks).toString('utf8'))
  } catch {
    throw new HttpError(400, 'BAD_REQUEST', 'request body is not valid JSON')
  }
}

export function sendJson(res: ServerResponse, status: number, body: unknown): void {
  const payload = Buffer.from(JSON.stringify(body), 'utf8')
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'content-length': String(payload.length) })
  res.end(payload)
}

export function sendError(res: ServerResponse, status: number, code: ProtocolErrorCode, message: string): void {
  sendJson(res, status, { error: { code, message } })
}
