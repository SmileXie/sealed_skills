import { createServer, type IncomingMessage, type Server } from 'node:http'
import { ENDPOINTS, PROTOCOL_VERSION, ProtocolRequestError } from '@sealed/license-format'
import { HttpError, readJsonBody, sendError, sendJson } from './http.js'
import type { ServerKeys } from './keys.js'
import { handleActivate, handleTrial, type RouteResult } from './routes.js'
import type { Store } from './store.js'

export interface AppOptions {
  store: Store
  keys: ServerKeys
  adminToken: string
  now?: () => number
  rateLimit?: { windowMs: number; max: number }
}

type Handler = (body: unknown, now: number) => RouteResult | Promise<RouteResult>

export function createApp(opts: AppOptions): Server {
  const now = opts.now ?? (() => Math.floor(Date.now() / 1000))
  const routes: Record<string, Handler> = {
    [ENDPOINTS.health]: () => ({ status: 200, body: { ok: true, version: String(PROTOCOL_VERSION) } }),
    [ENDPOINTS.trial]: (body, t) => handleTrial(opts.store, opts.keys, body, t),
    [ENDPOINTS.activate]: (body, t) => handleActivate(opts.store, opts.keys, body, t),
  }

  return createServer(async (req: IncomingMessage, res) => {
    try {
      const path = (req.url ?? '').split('?')[0]
      const handler = req.method === 'POST' || path === ENDPOINTS.health ? routes[path] : undefined
      if (!handler) { sendError(res, 404, 'BAD_REQUEST', 'no such endpoint'); return }
      const body = path === ENDPOINTS.health ? undefined : await readJsonBody(req)
      const result = await handler(body, now())
      sendJson(res, result.status, result.body)
    } catch (error) {
      if (error instanceof HttpError) { sendError(res, error.status, error.code, error.message); return }
      if (error instanceof ProtocolRequestError) { sendError(res, 400, error.code, error.message); return }
      sendError(res, 500, 'INTERNAL', 'internal error')
    }
  })
}
