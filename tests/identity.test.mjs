import assert from 'node:assert/strict'
import test from 'node:test'
import { webcrypto } from 'node:crypto'

globalThis.crypto ||= webcrypto
const { verifyIdentityCredential, queryCredentialStatuses, requestIdentityPresentation, verifyIdentityPresentation, verifyIdentityPresentationCredentials, loginWithWalletIdentity } = await import('../dist/web3-bs.esm.js')

function b64(value) { return Buffer.from(value).toString('base64url') }

const canonicalize = value => value === null ? 'null' : typeof value !== 'object' ? JSON.stringify(value) : Array.isArray(value) ? `[${value.map(canonicalize).join(',')}]` : `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonicalize(value[key])}`).join(',')}}`

async function signedIdentityDocument({ pair, holder, controllerId = 'controller-1', publicKey }) {
  const unsigned = {
    version: 1,
    id: holder,
    walletIdentityId: holder.replace('did:yeying:', ''),
    createdAt: new Date(Date.now() - 1000).toISOString(),
    updatedAt: new Date().toISOString(),
    revision: 1,
    controllers: [{ controllerId, publicKey, algorithm: 'Ed25519', purposes: ['authentication', 'assertion', 'manage'], status: 'active' }],
    accounts: [],
    issuers: []
  }
  const signature = await crypto.subtle.sign('Ed25519', pair.privateKey, new TextEncoder().encode(canonicalize(unsigned)))
  return { ...unsigned, proof: { type: 'YeyingIdentityDocumentProofV1', verificationMethod: `${holder}#${controllerId}`, purpose: 'assertionMethod', proofValue: Buffer.from(signature).toString('base64url') } }
}

test('identity credential verifies with browser WebCrypto Ed25519', async () => {
  const pair = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify'])
  const publicJwk = await crypto.subtle.exportKey('jwk', pair.publicKey)
  const now = Math.floor(Date.now() / 1000)
  const header = { alg: 'EdDSA', typ: 'JWT', kid: 'test-key' }
  const payload = { iss: 'did:web:node.example', sub: 'did:yeying:wid_test', iat: now, nbf: now, exp: now + 3600, jti: 'urn:test:email', vc: { type: ['VerifiableCredential', 'EmailCredential'], credentialSubject: { id: 'did:yeying:wid_test', email: 'alice@example.com' } } }
  const signingInput = `${b64(JSON.stringify(header))}.${b64(JSON.stringify(payload))}`
  const signature = await crypto.subtle.sign({ name: 'Ed25519' }, pair.privateKey, new TextEncoder().encode(signingInput))
  const token = `${signingInput}.${b64(new Uint8Array(signature))}`
  const result = await verifyIdentityCredential(token, { issuer: 'did:web:node.example', publicJwk, expectedSubject: payload.sub, expectedType: 'EmailCredential' })
  assert.equal(result.credentialId, payload.jti)
  await assert.rejects(() => verifyIdentityCredential(token, { issuer: 'did:web:other.example', publicJwk, expectedType: 'EmailCredential' }), /IDENTITY_ISSUER_UNTRUSTED/)
})

test('avatar credential verifies with browser WebCrypto Ed25519', async () => {
  const pair = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify'])
  const publicJwk = await crypto.subtle.exportKey('jwk', pair.publicKey)
  const now = Math.floor(Date.now() / 1000)
  const header = { alg: 'EdDSA', typ: 'JWT', kid: 'test-key' }
  const payload = { iss: 'did:web:node.example', sub: 'did:yeying:wid_test', iat: now, nbf: now, exp: now + 3600, jti: 'urn:test:avatar', vc: { type: ['VerifiableCredential', 'AvatarCredential'], credentialSubject: { id: 'did:yeying:wid_test', avatarUri: 'https://avatar.example/alice.png' } } }
  const signingInput = `${b64(JSON.stringify(header))}.${b64(JSON.stringify(payload))}`
  const signature = await crypto.subtle.sign({ name: 'Ed25519' }, pair.privateKey, new TextEncoder().encode(signingInput))
  const token = `${signingInput}.${b64(new Uint8Array(signature))}`
  const result = await verifyIdentityCredential(token, { issuer: 'did:web:node.example', publicJwk, expectedSubject: payload.sub, expectedType: 'AvatarCredential' })
  assert.equal(result.credentialType, 'AvatarCredential')
})

test('status query sends issuer and credentials and fails closed', async () => {
  let request
  const response = await queryCredentialStatuses('http://localhost:8100', 'did:web:node.example', ['urn:test:email'], async (url, options) => {
    request = { url, options }
    return new Response(JSON.stringify({ code: 0, data: { issuer: 'did:web:node.example', checkedAt: new Date().toISOString(), nextUpdateAt: new Date().toISOString(), statuses: { 'urn:test:email': 'active' } } }), { status: 200, headers: { 'content-type': 'application/json' } })
  })
  assert.equal(request.url, 'http://localhost:8100/api/v1/public/identity/credentials/status')
  assert.deepEqual(JSON.parse(request.options.body), { issuer: 'did:web:node.example', credentials: ['urn:test:email'] })
  assert.equal(response.statuses['urn:test:email'], 'active')
})

test('identity presentation verifies controller proof and request context', async () => {
  const pair = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify'])
  const publicJwk = await crypto.subtle.exportKey('jwk', pair.publicKey)
  const holder = 'did:yeying:wid_test'
  const document = await signedIdentityDocument({ pair, holder, publicKey: publicJwk })
  const unsigned = { version: 1, holder, audience: 'https://app.example/login', nonce: 'nonce-1', issuedAt: new Date(Date.now() - 1000).toISOString(), expiresAt: new Date(Date.now() + 60000).toISOString(), scopes: ['identity.basic'] , identityDocument: document }
  const signature = await crypto.subtle.sign({ name: 'Ed25519' }, pair.privateKey, new TextEncoder().encode(canonicalize(unsigned)))
  const presentation = { ...unsigned, proof: { type: 'YeyingIdentityPresentationProofV1', verificationMethod: `${holder}#controller-1`, purpose: 'authentication', proofValue: Buffer.from(signature).toString('base64url') } }
  assert.equal((await verifyIdentityPresentation(presentation, { expectedAudience: unsigned.audience, expectedNonce: unsigned.nonce, expectedScopes: ['identity.basic'], trustedIdentityDocument: document })).holder, holder)
  await assert.rejects(() => verifyIdentityPresentation(presentation, { expectedAudience: unsigned.audience, expectedNonce: 'wrong', trustedIdentityDocument: document }), /IDENTITY_PRESENTATION_CONTEXT_MISMATCH/)
  await assert.rejects(() => verifyIdentityPresentation(presentation, { expectedAudience: unsigned.audience, expectedNonce: unsigned.nonce }), /IDENTITY_DOCUMENT_TRUST_REQUIRED/)

  const attacker = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify'])
  const attackerJwk = await crypto.subtle.exportKey('jwk', attacker.publicKey)
  const forgedDocument = await signedIdentityDocument({ pair: attacker, holder, publicKey: attackerJwk })
  const forgedUnsigned = { ...unsigned, identityDocument: forgedDocument }
  const forgedSignature = await crypto.subtle.sign('Ed25519', attacker.privateKey, new TextEncoder().encode(canonicalize(forgedUnsigned)))
  const forged = { ...forgedUnsigned, proof: { ...presentation.proof, proofValue: Buffer.from(forgedSignature).toString('base64url') } }
  await assert.rejects(() => verifyIdentityPresentation(forged, { expectedAudience: unsigned.audience, expectedNonce: unsigned.nonce, trustedIdentityDocument: document }), /IDENTITY_DOCUMENT_MISMATCH/)
})

test('identity presentation does not request accounts by default', async () => {
  const calls = []
  const provider = {
    async request(request) {
      calls.push(request.method)
      if (request.method !== 'wallet_identity_presentation') throw new Error(`unexpected method ${request.method}`)
      return {
        version: 1,
        holder: 'did:yeying:wid_test',
        audience: 'https://app.example',
        nonce: 'nonce-identity-only',
        issuedAt: new Date().toISOString(),
        expiresAt: new Date(Date.now() + 60000).toISOString(),
        scopes: ['identity.basic'],
        proof: { type: 'YeyingIdentityPresentationProofV1', verificationMethod: 'did:yeying:wid_test#controller-1', purpose: 'authentication', proofValue: 'proof' }
      }
    }
  }

  await requestIdentityPresentation({
    provider,
    audience: 'https://app.example',
    nonce: 'nonce-identity-only',
    scopes: ['identity.basic']
  })

  assert.deepEqual(calls, ['wallet_identity_presentation'])
})

test('identity presentation requests accounts only when explicitly enabled', async () => {
  const calls = []
  const provider = {
    async request(request) {
      calls.push(request.method)
      if (request.method === 'eth_requestAccounts') return ['0xabc']
      if (request.method === 'wallet_identity_presentation') {
        return {
          version: 1,
          holder: 'did:yeying:wid_test',
          audience: 'https://app.example',
          nonce: 'nonce-connected',
          issuedAt: new Date().toISOString(),
          expiresAt: new Date(Date.now() + 60000).toISOString(),
          scopes: ['identity.basic'],
          proof: { type: 'YeyingIdentityPresentationProofV1', verificationMethod: 'did:yeying:wid_test#controller-1', purpose: 'authentication', proofValue: 'proof' }
        }
      }
      throw new Error(`unexpected method ${request.method}`)
    }
  }

  await requestIdentityPresentation({
    provider,
    audience: 'https://app.example',
    nonce: 'nonce-connected',
    scopes: ['identity.basic'],
    ensureConnected: true
  })

  assert.deepEqual(calls, ['eth_requestAccounts', 'wallet_identity_presentation'])
})

test('wallet identity login does not require appId in local presentation sessions', async () => {
  let identityRequest
  const provider = {
    async request({ method, params }) {
      if (method === 'wallet_requestPermissions') {
        assert.deepEqual(params[0], { wallet_identity: { scopes: ['identity.basic', 'identity.email'] } })
        return [{ parentCapability: 'wallet_identity' }]
      }
      if (method === 'eth_chainId') return '0x1'
      if (method === 'wallet_identity_presentation') {
        identityRequest = params[0]
        return {
          version: 1,
          holder: 'did:yeying:wid_test',
          audience: identityRequest.audience,
          nonce: identityRequest.nonce,
          issuedAt: new Date().toISOString(),
          expiresAt: new Date(Date.now() + 60000).toISOString(),
          scopes: identityRequest.scopes,
          proof: { type: 'YeyingIdentityPresentationProofV1', verificationMethod: 'did:yeying:wid_test#controller-1', purpose: 'authentication', proofValue: 'proof' }
        }
      }
      throw new Error(`unexpected method ${method}`)
    }
  }
  const fetcher = async (url, options) => {
    if (String(url).endsWith('/identity/login/session')) {
      return new Response(JSON.stringify({ code: 0, data: { session_id: 'sid-1', audience: 'http://router.local', nonce: 'nonce-1', scopes: ['identity.basic', 'identity.email'] } }), { status: 200, headers: { 'content-type': 'application/json' } })
    }
    if (String(url).endsWith('/identity/login/verify')) {
      const body = JSON.parse(options.body)
      assert.equal(body.session_id, 'sid-1')
      return new Response(JSON.stringify({ code: 0, data: { token: 'token-1' } }), { status: 200, headers: { 'content-type': 'application/json' } })
    }
    throw new Error(`unexpected url ${url}`)
  }

  const result = await loginWithWalletIdentity({ provider, fetcher, baseUrl: 'http://router.local/api/v1/public/auth', storeToken: false })

  assert.equal(result.token, 'token-1')
  assert.equal(result.did, 'did:yeying:wid_test')
  assert.equal(result.walletAddress, undefined)
  assert.equal(identityRequest.appId, undefined)
  assert.equal(identityRequest.audience, 'http://router.local')
  assert.equal(identityRequest.nonce, 'nonce-1')
})

test('wallet identity login rejects a server session with different scopes', async () => {
  const provider = { async request() { throw new Error('provider must not be called after scope mismatch') } }
  const fetcher = async () => new Response(JSON.stringify({ code: 0, data: { session_id: 'sid-1', audience: 'https://app.example', nonce: 'nonce-1', scopes: ['identity.basic'] } }), { status: 200, headers: { 'content-type': 'application/json' } })
  await assert.rejects(() => loginWithWalletIdentity({ provider, fetcher, baseUrl: 'https://app.example/api/auth', scopes: ['identity.basic', 'identity.email'], storeToken: false }), /IDENTITY_SCOPE_MISMATCH/)
})

test('identity presentation verifies the Wallet V1 raw controller key format', async () => {
  const pair = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify'])
  const rawPublicKey = Buffer.from(await crypto.subtle.exportKey('raw', pair.publicKey)).toString('base64url')
  const holder = 'did:yeying:wid_wallet_v1'
  const document = await signedIdentityDocument({ pair, holder, controllerId: 'wallet-controller', publicKey: rawPublicKey })
  const unsigned = { version: 1, holder, audience: 'https://app.example', nonce: 'nonce-wallet-v1', issuedAt: new Date().toISOString(), expiresAt: new Date(Date.now() + 60000).toISOString(), scopes: ['identity.basic'], identityDocument: document }
  const signature = await crypto.subtle.sign({ name: 'Ed25519' }, pair.privateKey, new TextEncoder().encode(canonicalize(unsigned)))
  const proof = { type: 'YeyingIdentityPresentationProofV1', verificationMethod: `${holder}#wallet-controller`, purpose: 'authentication', proofValue: Buffer.from(signature).toString('base64url') }
  assert.equal((await verifyIdentityPresentation({ ...unsigned, proof }, { expectedAudience: unsigned.audience, expectedNonce: unsigned.nonce, trustedIdentityDocument: document })).holder, holder)
})

test('identity presentation credentials verify JWT-VC and active status', async () => {
  const controller = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify'])
  const controllerJwk = await crypto.subtle.exportKey('jwk', controller.publicKey)
  const issuerPair = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify'])
  const issuerJwk = await crypto.subtle.exportKey('jwk', issuerPair.publicKey)
  const holder = 'did:yeying:wid_test'
  const now = Math.floor(Date.now() / 1000)
  const header = { alg: 'EdDSA', typ: 'JWT', kid: 'issuer-1' }
  const payload = { iss: 'did:web:node.example', sub: holder, iat: now, nbf: now, exp: now + 3600, jti: 'urn:test:email', vc: { type: ['VerifiableCredential', 'EmailCredential'], credentialSubject: { id: holder, email: 'alice@example.com' } } }
  const input = `${b64(JSON.stringify(header))}.${b64(JSON.stringify(payload))}`
  const jwtSignature = await crypto.subtle.sign({ name: 'Ed25519' }, issuerPair.privateKey, new TextEncoder().encode(input))
  const token = `${input}.${Buffer.from(jwtSignature).toString('base64url')}`
  const document = await signedIdentityDocument({ pair: controller, holder, publicKey: controllerJwk })
  const unsigned = { version: 1, holder, audience: 'https://app.example/login', nonce: 'nonce-1', issuedAt: new Date().toISOString(), expiresAt: new Date(Date.now() + 60000).toISOString(), scopes: ['identity.basic', 'identity.email'], identityDocument: document, credentials: [token] }
  const signature = await crypto.subtle.sign({ name: 'Ed25519' }, controller.privateKey, new TextEncoder().encode(canonicalize(unsigned)))
  const presentation = { ...unsigned, proof: { type: 'YeyingIdentityPresentationProofV1', verificationMethod: `${holder}#controller-1`, purpose: 'authentication', proofValue: Buffer.from(signature).toString('base64url') } }
  const result = await verifyIdentityPresentationCredentials(presentation, { expectedAudience: unsigned.audience, expectedNonce: unsigned.nonce, expectedScopes: ['identity.email'], trustedIdentityDocument: document, issuer: payload.iss, publicJwk: issuerJwk, nodeBaseUrl: 'http://node', fetcher: async () => new Response(JSON.stringify({ code: 0, data: { issuer: payload.iss, checkedAt: new Date().toISOString(), nextUpdateAt: new Date().toISOString(), statuses: { [payload.jti]: 'active' } } }), { status: 200 }) })
  assert.equal(result.credentials[0].credentialType, 'EmailCredential')
})
