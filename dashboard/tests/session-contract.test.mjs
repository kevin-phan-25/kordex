import assert from 'node:assert/strict'
import {test} from 'node:test'
import {decodeProtectedHeader} from 'jose'
import {decryptSession, encryptSession} from '../src/lib/session-contract.ts'

const key = 'a-local-test-session-secret-with-more-than-thirty-two-bytes'
const session = {
  token: 'api-token-fixture', sub: 'keycloak-subject', name: 'Local Test', email: 'user@example.test',
  role: 'viewer', organizationID: '80bd80f9-f097-4474-86f4-b80986fd5423',
  organizationName: 'Local Org', expiresAt: Date.now() + 60_000,
}

test('session is an encrypted A256GCM JWE and round-trips without plaintext fields', async () => {
  const value = await encryptSession(session, key)
  assert.equal(value.split('.').length, 5)
  assert.equal(value.includes(session.token), false)
  assert.equal(value.includes(session.sub), false)
  const header = decodeProtectedHeader(value)
  assert.equal(header.alg, 'dir')
  assert.equal(header.enc, 'A256GCM')
  const decoded = await decryptSession(value, key)
  for (const [field, expected] of Object.entries(session)) assert.equal(decoded?.[field], expected)
})

test('expired, tampered, and too-weak-secret sessions fail closed', async () => {
  const expired = await encryptSession({...session, expiresAt: Date.now() - 1000}, key).catch(() => '')
  assert.equal(await decryptSession(expired, key), null)
  const value = await encryptSession(session, key)
  const tampered = `${value.slice(0, -1)}${value.endsWith('a') ? 'b' : 'a'}`
  assert.equal(await decryptSession(tampered, key), null)
  await assert.rejects(encryptSession(session, 'short'), /at least 32 bytes/)
})
