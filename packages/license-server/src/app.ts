import { createServer, type IncomingMessage, type Server } from 'node:http'
import { ENDPOINTS, PROTOCOL_VERSION, ProtocolRequestError } from '@sealed/license-format'
import { HttpError, createRateLimiter, isAuthorized, readJsonBody, sendError, sendJson } from './http.js'
import type { ServerKeys } from './keys.js'
import { handleActivate, handlePublishPack, handleRenew, handleRevoke, handleTrial, type RouteResult } from './routes.js'
import type { Store } from './store.js'

export interface AppOptions {
  store: Store
  keys: ServerKeys
  adminToken: string
  now?: () => number
  rateLimit?: { windowMs: number; max: number }
}

interface Route {
  handler: (body: unknown, now: number) => RouteResult | Promise<RouteResult>
  admin?: boolean
}

export function createApp(opts: AppOptions): Server {
  const now = opts.now ?? (() => Math.floor(Date.now() / 1000))
  const limiter = createRateLimiter(opts.rateLimit ?? { windowMs: 60_000, max: 60 })
  const routes: Record<string, Route> = {
    [ENDPOINTS.health]: { handler: () => ({ status: 200, body: { ok: true, version: String(PROTOCOL_VERSION) } }) },
    [ENDPOINTS.trial]: { handler: (body, t) => handleTrial(opts.store, opts.keys, body, t) },
    [ENDPOINTS.activate]: { handler: (body, t) => handleActivate(opts.store, opts.keys, body, t) },
    [ENDPOINTS.renew]: { handler: (body, t) => handleRenew(opts.store, opts.keys, body, t) },
    [ENDPOINTS.revoke]: { handler: (body, t) => handleRevoke(opts.store, body, t), admin: true },
    [ENDPOINTS.publishPack]: { handler: (body, t) => handlePublishPack(opts.store, opts.keys, body, t), admin: true },
  }

  return createServer(async (req: IncomingMessage, res) => {
    try {
      const path = (req.url ?? '').split('?')[0]
      const route = routes[path]
      if (!route || (req.method !== 'POST' && path !== ENDPOINTS.health)) { sendError(res, 404, 'BAD_REQUEST', 'no such endpoint'); return }
      if (route.admin && !isAuthorized(req, opts.adminToken)) { sendError(res, 401, 'UNAUTHORIZED', 'admin token is missing or invalid'); return }
      if (req.method === 'POST' && path !== ENDPOINTS.health) {
        const key = req.socket.remoteAddress ?? 'unknown'
        if (!limiter.check(key)) { sendError(res, 429, 'RATE_LIMITED', 'too many requests'); return }
      }
      const body = path === ENDPOINTS.health ? undefined : await readJsonBody(req)
      const result = await route.handler(body, now())
      sendJson(res, result.status, result.body)
    } catch (error) {
      if (error instanceof HttpError) { sendError(res, error.status, error.code, error.message); return }
      if (error instanceof ProtocolRequestError) { sendError(res, 400, error.code, error.message); return }
      sendError(res, 500, 'INTERNAL', 'internal error')
    }
  })
}
