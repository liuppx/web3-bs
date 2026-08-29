import assert from 'node:assert/strict'
import test from 'node:test'

const { loginWithChallenge, loginWithSiwe } = await import('../dist/web3-bs.esm.js')

const address = '0x1111111111111111111111111111111111111111'

function provider(chainId = '0x1') {
  return {
    async request({ method }) {
      if (method === 'eth_accounts') return [address]
      if (method === 'eth_chainId') return chainId
      if (method === 'personal_sign') return '0xsigned'
      throw new Error(`unexpected method ${method}`)
    }
  }
}

function fetcherFor(challenge, inspectVerify = () => {}) {
  return async (url, options) => {
    if (String(url).endsWith('/challenge')) {
      return new Response(JSON.stringify({ data: { challenge } }), { status: 200, headers: { 'content-type': 'application/json' } })
    }
    if (String(url).endsWith('/verify')) {
      inspectVerify(JSON.parse(options.body))
      return new Response(JSON.stringify({ data: { token: 'token-1' } }), { status: 200, headers: { 'content-type': 'application/json' } })
    }
    throw new Error(`unexpected url ${url}`)
  }
}

function siweMessage(overrides = {}) {
  const values = {
    domain: 'app.example',
    uri: 'https://app.example',
    chainId: 1,
    issuedAt: '2026-08-29T00:00:00.000Z',
    expirationTime: '2026-08-29T01:00:00.000Z',
    ...overrides
  }
  return [
    `${values.domain} wants you to sign in with your Ethereum account:`,
    address,
    '',
    'Sign in to App',
    '',
    `URI: ${values.uri}`,
    'Version: 1',
    `Chain ID: ${values.chainId}`,
    'Nonce: abcdef12',
    `Issued At: ${values.issuedAt}`,
    `Expiration Time: ${values.expirationTime}`
  ].join('\n')
}

test('loginWithSiwe validates EIP-4361 and submits the signed message', async () => {
  const challenge = siweMessage()
  let verifyBody
  const result = await loginWithSiwe({
    provider: provider(),
    fetcher: fetcherFor(challenge, body => { verifyBody = body }),
    baseUrl: 'https://app.example/api/auth',
    domain: 'app.example',
    uri: 'https://app.example',
    chainId: 1,
    now: new Date('2026-08-29T00:10:00.000Z'),
    storeToken: false
  })

  assert.equal(result.token, 'token-1')
  assert.equal(verifyBody.challenge, challenge)
  assert.equal(verifyBody.address, address)
  assert.equal(verifyBody.signature, '0xsigned')
})

test('loginWithSiwe rejects a generic challenge while loginWithChallenge remains generic', async () => {
  const challenge = 'Sign this one-time challenge: abcdef12'
  await assert.rejects(() => loginWithSiwe({ provider: provider(), fetcher: fetcherFor(challenge), baseUrl: 'https://app.example/api/auth', domain: 'app.example', uri: 'https://app.example', chainId: 1, storeToken: false }), /SIWE_MESSAGE_INVALID/)
  assert.equal((await loginWithChallenge({ provider: provider(), fetcher: fetcherFor(challenge), baseUrl: 'https://app.example/api/auth', storeToken: false })).token, 'token-1')
})

test('loginWithSiwe accepts decimal provider chain IDs', async () => {
  const result = await loginWithSiwe({ provider: provider('1'), fetcher: fetcherFor(siweMessage()), baseUrl: 'https://app.example/api/auth', domain: 'app.example', uri: 'https://app.example', now: new Date('2026-08-29T00:10:00.000Z'), storeToken: false })
  assert.equal(result.token, 'token-1')
})

for (const [name, challenge, options, error] of [
  ['domain', siweMessage({ domain: 'other.example' }), {}, /SIWE_DOMAIN_MISMATCH/],
  ['URI', siweMessage({ uri: 'https://other.example' }), {}, /SIWE_URI_MISMATCH/],
  ['chain ID', siweMessage({ chainId: 10 }), {}, /SIWE_CHAIN_ID_MISMATCH/],
  ['expiration', siweMessage({ expirationTime: '2026-08-29T00:05:00.000Z' }), {}, /SIWE_EXPIRED/]
]) {
  test(`loginWithSiwe rejects an invalid ${name}`, async () => {
    await assert.rejects(() => loginWithSiwe({ provider: provider(), fetcher: fetcherFor(challenge), baseUrl: 'https://app.example/api/auth', domain: 'app.example', uri: 'https://app.example', now: new Date('2026-08-29T00:10:00.000Z'), storeToken: false, ...options }), error)
  })
}
