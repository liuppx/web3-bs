import assert from 'node:assert/strict'
import test from 'node:test'
import vm from 'node:vm'
import { readFile } from 'node:fs/promises'

test('UMD bundle loads without Node globals', async () => {
  const source = await readFile(new URL('../dist/web3-bs.umd.js', import.meta.url), 'utf8')
  const context = { console, TextEncoder, TextDecoder, URL, URLSearchParams, setTimeout, clearTimeout }
  context.globalThis = context
  vm.runInNewContext(source, context)
  assert.equal(typeof context.YeYingWeb3.loginWithSiwe, 'function')
  assert.equal(typeof context.YeYingWeb3.loginWithWalletIdentity, 'function')
  assert.equal(typeof context.YeYingWeb3.createRootUcan, 'function')
  assert.equal(typeof context.YeYingWeb3.getOrCreateUcanRoot, 'function')
  assert.equal(context.YeYingWeb3.createSiweUcanRoot, undefined)
})
