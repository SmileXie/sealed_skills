export class CanonicalJsonError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'CanonicalJsonError'
  }
}

/**
 * RFC 8785 的子集：对象键按 UTF-16 code unit 升序，无空白，
 * 仅支持 string / boolean / null / 安全整数 / 数组 / 普通对象。
 */
export function canonicalJson(value: unknown): string {
  if (value === null) return 'null'
  switch (typeof value) {
    case 'boolean':
      return value ? 'true' : 'false'
    case 'number':
      if (!Number.isSafeInteger(value)) throw new CanonicalJsonError('only safe integers are supported')
      return Object.is(value, -0) ? '0' : String(value)
    case 'string':
      return JSON.stringify(value)
    case 'object': {
      if (Array.isArray(value)) {
        return '[' + value.map((item) => {
          if (item === undefined) throw new CanonicalJsonError('undefined is not allowed in arrays')
          return canonicalJson(item)
        }).join(',') + ']'
      }
      const obj = value as Record<string, unknown>
      const keys = Object.keys(obj).filter((k) => obj[k] !== undefined).sort()
      return '{' + keys.map((k) => JSON.stringify(k) + ':' + canonicalJson(obj[k])).join(',') + '}'
    }
    default:
      throw new CanonicalJsonError('unsupported type: ' + typeof value)
  }
}