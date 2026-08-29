import assert from 'node:assert/strict'
import test from 'node:test'
import { readFile } from 'node:fs/promises'

const expectedMethods = [
  'wallet_ucan_session',
  'wallet_ucan_sign',
  'wallet_encrypt',
  'wallet_decrypt',
  'wallet_getCipherSuites'
]

test('SDK uses the generic wallet RPC method names only', async () => {
  const sources = await Promise.all([
    readFile(new URL('../src/auth/ucan.ts', import.meta.url), 'utf8'),
    readFile(new URL('../src/auth/encrypt.ts', import.meta.url), 'utf8')
  ])
  const source = sources.join('\n')
  for (const method of expectedMethods) {
    assert.match(source, new RegExp(`['"]${method}['"]`), `${method} is missing from the SDK`)
  }
  assert.doesNotMatch(source, /['"]yeying_[A-Za-z0-9_]+['"]/)
})
