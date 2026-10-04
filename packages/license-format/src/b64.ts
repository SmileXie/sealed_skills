export function b64u(buf: Buffer): string { return buf.toString('base64url') }
export function unb64u(s: string): Buffer { return Buffer.from(s, 'base64url') }
