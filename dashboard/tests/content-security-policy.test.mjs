import assert from 'node:assert/strict'
import {test} from 'node:test'
import {contentSecurityPolicy} from '../src/lib/content-security-policy.ts'

test('development CSP enables eval needed by React debugging only in development', () => {
  const development = contentSecurityPolicy(true)
  const production = contentSecurityPolicy(false)
  assert.match(development, /script-src[^;]*'unsafe-eval'/)
  assert.doesNotMatch(production, /'unsafe-eval'/)
  assert.match(development, /frame-ancestors 'none'/)
  assert.match(production, /form-action 'self'/)
})
