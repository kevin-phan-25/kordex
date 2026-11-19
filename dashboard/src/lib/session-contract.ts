import {createHash} from 'node:crypto'

export type EncryptedSession = {
  token: string
  sub: string
  name: string
  email: string
  role: string
  organizationID: string
  organizationName: string
  expiresAt: number
}

function keyFromSecret(secret: string): Buffer {
  if (Buffer.byteLength(secret) < 32) throw new Error('KORDEX_SESSION_SECRET must contain at least 32 bytes')
  return createHash('sha256').update(secret).digest()
}

export async function encryptSession(session: EncryptedSession, secret: string): Promise<string> {
  const {EncryptJWT} = await import('jose')
  return new EncryptJWT(session as unknown as Record<string, unknown>)
    .setProtectedHeader({alg: 'dir', enc: 'A256GCM'})
    .setIssuedAt()
    .setExpirationTime(Math.floor(session.expiresAt / 1000))
    .encrypt(keyFromSecret(secret))
}

export async function decryptSession(value: string, secret: string): Promise<EncryptedSession | null> {
  try {
    const {jwtDecrypt} = await import('jose')
    const {payload} = await jwtDecrypt(value, keyFromSecret(secret))
    const session = payload as unknown as EncryptedSession
    if (!session.token || !session.sub || !session.organizationID || !session.expiresAt || session.expiresAt <= Date.now()) return null
    return session
  } catch {
    return null
  }
}
