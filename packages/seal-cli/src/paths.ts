export function assertSafeRelPath(rel: string): string {
  const parts = rel.split('/')
  if (rel.startsWith('/') || rel.includes('\\')) throw new Error('ENTRY_PATH_INVALID: ' + rel)
  if (parts.some((part) => part === '' || part === '.' || part === '..')) throw new Error('ENTRY_PATH_INVALID: ' + rel)
  return rel
}
