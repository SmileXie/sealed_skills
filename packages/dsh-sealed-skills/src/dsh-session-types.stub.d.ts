// Compile-only stub for `@deepseek-ai/dsh-session/types`.
//
// Why this file exists: `session-events.ts` augments `SessionEventMap` with
// `declare module '@deepseek-ai/dsh-session/types' { … }`. TypeScript only accepts a module
// augmentation when the target specifier RESOLVES (an unresolvable one is TS2664). The real
// `@deepseek-ai/dsh-session` is an OPTIONAL peer and must never enter this repo's dependency
// graph, so `tsconfig.json` maps the specifier here through `paths`.
//
// It is a declaration input, never emitted into `dist/` and never published. It mirrors just
// enough of the real shape (verified against `@deepseek-ai/dsh-session@0.2.0-rc.2`:
// `lib/types/types.d.ts:255` `export interface SessionEventMap {`, `:435`
// `export type SessionEventType = keyof SessionEventMap;`). In a consumer that has the real
// package, `paths` does not apply, the real module resolves instead, and our augmentation
// MERGES with the in-tree declarations (e.g. `'image/offload'`) instead of shadowing them.
export interface SessionEventMap {
  'image/offload': { id: string }
}
export type SessionEventType = keyof SessionEventMap
