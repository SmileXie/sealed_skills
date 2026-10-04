export function parseSkillMarkdown(text: string): { frontmatter: Record<string, string | boolean>; body: string } {
  const src = text.replace(/^\uFEFF/, '').replace(/\r\n/g, '\n')
  if (!src.startsWith('---\n')) throw new Error('SKILL_MD_NO_FRONTMATTER')
  const end = src.indexOf('\n---', 3)
  if (end < 0) throw new Error('SKILL_MD_NO_FRONTMATTER')
  const block = src.slice(4, end)
  const body = src.slice(end + 4).replace(/^(?:\r?\n)+/, '')
  const frontmatter: Record<string, string | boolean> = {}
  for (const line of block.split('\n')) {
    const trimmed = line.trim()
    if (trimmed === '' || trimmed.startsWith('#')) continue
    const at = trimmed.indexOf(':')
    if (at <= 0) throw new Error('SKILL_MD_BAD_FRONTMATTER')
    const key = trimmed.slice(0, at).trim()
    const raw = trimmed.slice(at + 1).trim()
    frontmatter[key] = raw === 'true' ? true : raw === 'false' ? false : raw
  }
  if (typeof frontmatter.name !== 'string') throw new Error('SKILL_MD_BAD_FRONTMATTER')
  if (typeof frontmatter.description !== 'string') throw new Error('SKILL_MD_BAD_FRONTMATTER')
  return { frontmatter, body }
}
