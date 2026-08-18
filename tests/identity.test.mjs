import assert from 'node:assert/strict'
import test from 'node:test'
import { webcrypto } from 'node:crypto'

globalThis.crypto ||= webcrypto
const { verifyIdentityCredential, queryCredentialStatuses, verifyIdentityPresentation, verifyIdentityPresentationCredentials } = await import('../dist/web3-bs.esm.js')

function b64(value) { return Buffer.from(value).toString('base64url') }

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
  const document = { id: holder, controllers: [{ id: 'controller-1', publicKey: publicJwk, status: 'active' }] }
  const unsigned = { version: 1, holder, audience: 'https://app.example/login', nonce: 'nonce-1', issuedAt: new Date(Date.now() - 1000).toISOString(), expiresAt: new Date(Date.now() + 60000).toISOString(), scopes: ['identity.basic'] , identityDocument: document }
  const canonicalize = value => value === null ? 'null' : typeof value !== 'object' ? JSON.stringify(value) : Array.isArray(value) ? `[${value.map(canonicalize).join(',')}]` : `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonicalize(value[key])}`).join(',')}}`
  const signature = await crypto.subtle.sign({ name: 'Ed25519' }, pair.privateKey, new TextEncoder().encode(canonicalize(unsigned)))
  const presentation = { ...unsigned, proof: { type: 'YeyingIdentityPresentationProofV1', verificationMethod: `${holder}#controller-1`, purpose: 'authentication', proofValue: Buffer.from(signature).toString('base64url') } }
  assert.equal((await verifyIdentityPresentation(presentation, { expectedAudience: unsigned.audience, expectedNonce: unsigned.nonce, expectedScopes: ['identity.basic'] })).holder, holder)
  await assert.rejects(() => verifyIdentityPresentation(presentation, { expectedAudience: unsigned.audience, expectedNonce: 'wrong' }), /IDENTITY_PRESENTATION_CONTEXT_MISMATCH/)
})

test('identity presentation verifies the Wallet V1 raw controller key format', async () => {
  const pair = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify'])
  const rawPublicKey = Buffer.from(await crypto.subtle.exportKey('raw', pair.publicKey)).toString('base64url')
  const holder = 'did:yeying:wid_wallet_v1'
  const document = { id: holder, controllers: [{ controllerId: 'wallet-controller', publicKey: rawPublicKey, algorithm: 'Ed25519', purposes: ['authentication'], status: 'active' }] }
  const unsigned = { version: 1, holder, audience: 'https://app.example', nonce: 'nonce-wallet-v1', issuedAt: new Date().toISOString(), expiresAt: new Date(Date.now() + 60000).toISOString(), scopes: ['identity.basic'], identityDocument: document }
  const canonicalize = value => value === null ? 'null' : typeof value !== 'object' ? JSON.stringify(value) : Array.isArray(value) ? `[${value.map(canonicalize).join(',')}]` : `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonicalize(value[key])}`).join(',')}}`
  const signature = await crypto.subtle.sign({ name: 'Ed25519' }, pair.privateKey, new TextEncoder().encode(canonicalize(unsigned)))
  const proof = { type: 'YeyingIdentityPresentationProofV1', verificationMethod: `${holder}#wallet-controller`, purpose: 'authentication', proofValue: Buffer.from(signature).toString('base64url') }
  assert.equal((await verifyIdentityPresentation({ ...unsigned, proof }, { expectedAudience: unsigned.audience, expectedNonce: unsigned.nonce })).holder, holder)
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
  const document = { id: holder, controllers: [{ id: 'controller-1', publicKey: controllerJwk, status: 'active' }] }
  const unsigned = { version: 1, holder, audience: 'https://app.example/login', nonce: 'nonce-1', issuedAt: new Date().toISOString(), expiresAt: new Date(Date.now() + 60000).toISOString(), scopes: ['identity.basic', 'identity.email'], identityDocument: document, credentials: [token] }
  const canonicalize = value => value === null ? 'null' : typeof value !== 'object' ? JSON.stringify(value) : Array.isArray(value) ? `[${value.map(canonicalize).join(',')}]` : `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonicalize(value[key])}`).join(',')}}`
  const signature = await crypto.subtle.sign({ name: 'Ed25519' }, controller.privateKey, new TextEncoder().encode(canonicalize(unsigned)))
  const presentation = { ...unsigned, proof: { type: 'YeyingIdentityPresentationProofV1', verificationMethod: `${holder}#controller-1`, purpose: 'authentication', proofValue: Buffer.from(signature).toString('base64url') } }
  const result = await verifyIdentityPresentationCredentials(presentation, { expectedAudience: unsigned.audience, expectedNonce: unsigned.nonce, expectedScopes: ['identity.email'], issuer: payload.iss, publicJwk: issuerJwk, nodeBaseUrl: 'http://node', fetcher: async () => new Response(JSON.stringify({ code: 0, data: { issuer: payload.iss, checkedAt: new Date().toISOString(), nextUpdateAt: new Date().toISOString(), statuses: { [payload.jti]: 'active' } } }), { status: 200 }) })
  assert.equal(result.credentials[0].credentialType, 'EmailCredential')
})
