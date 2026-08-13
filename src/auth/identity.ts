export type CredentialStatusResponse = {
  issuer: string
  checkedAt: string
  nextUpdateAt: string
  statuses: Record<string, 'active' | 'revoked' | 'superseded' | 'expired' | 'unknown'>
}

export type IdentityCredentialValidation = {
  issuer: string
  subject: string
  credentialType: 'EmailCredential' | 'UsernameCredential'
  credentialId: string
  payload: Record<string, unknown>
}

function decodePart(value: string) {
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/')
  const bytes = Uint8Array.from(atob(`${normalized}${'='.repeat((4 - normalized.length % 4) % 4)}`), char => char.charCodeAt(0))
  return JSON.parse(new TextDecoder().decode(bytes)) as Record<string, unknown>
}

function decodeBase64Url(value: string) {
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/')
  return Uint8Array.from(atob(`${normalized}${'='.repeat((4 - normalized.length % 4) % 4)}`), char => char.charCodeAt(0))
}

export function decodeIdentityCredential(token: string) {
  const parts = String(token || '').split('.')
  if (parts.length !== 3) throw new Error('IDENTITY_CREDENTIAL_INVALID')
  const header = decodePart(parts[0])
  const payload = decodePart(parts[1])
  if (header.alg !== 'EdDSA' || header.typ !== 'JWT' || typeof header.kid !== 'string') throw new Error('IDENTITY_CREDENTIAL_INVALID')
  return { header, payload, signingInput: `${parts[0]}.${parts[1]}`, signature: parts[2] }
}

export async function verifyIdentityCredential(token: string, options: { issuer: string; publicJwk: JsonWebKey; expectedSubject?: string; expectedType: 'EmailCredential' | 'UsernameCredential'; now?: number }) {
  const decoded = decodeIdentityCredential(token)
  const payload = decoded.payload
  if (payload.iss !== options.issuer || (options.expectedSubject && payload.sub !== options.expectedSubject)) throw new Error('IDENTITY_ISSUER_UNTRUSTED')
  const vc = payload.vc as Record<string, unknown> | undefined
  const types = Array.isArray(vc?.type) ? vc.type : []
  if (!types.includes('VerifiableCredential') || !types.includes(options.expectedType)) throw new Error('IDENTITY_CREDENTIAL_INVALID')
  const now = options.now || Math.floor(Date.now() / 1000)
  if (typeof payload.exp !== 'number' || typeof payload.nbf !== 'number' || payload.nbf > now || payload.exp <= now) throw new Error('IDENTITY_CREDENTIAL_EXPIRED')
  let valid = false
  try {
    const key = await globalThis.crypto.subtle.importKey('jwk', options.publicJwk, { name: 'Ed25519' }, false, ['verify'])
    valid = await globalThis.crypto.subtle.verify({ name: 'Ed25519' }, key, decodeBase64Url(decoded.signature), new TextEncoder().encode(decoded.signingInput))
  } catch { valid = false }
  if (!valid) throw new Error('IDENTITY_CREDENTIAL_INVALID')
  return { issuer: String(payload.iss), subject: String(payload.sub), credentialType: options.expectedType, credentialId: String(payload.jti || ''), payload }
}

export async function queryCredentialStatuses(nodeBaseUrl: string, issuer: string, credentials: string[], fetcher: typeof fetch = fetch): Promise<CredentialStatusResponse> {
  if (!issuer || credentials.length === 0) throw new Error('IDENTITY_CREDENTIAL_STATUS_REQUEST_INVALID')
  const response = await fetcher(`${nodeBaseUrl.replace(/\/$/, '')}/api/v1/public/identity/credentials/status`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ issuer, credentials }) })
  if (!response.ok) throw new Error('IDENTITY_CREDENTIAL_STATUS_UNKNOWN')
  const envelope = await response.json() as { code: number; data?: CredentialStatusResponse }
  if (envelope.code !== 0 || !envelope.data) throw new Error('IDENTITY_CREDENTIAL_STATUS_UNKNOWN')
  return envelope.data
}
import { requestAccounts, requireProvider } from './provider'
import type { Eip1193Provider, IdentityPresentation, IdentityPresentationRequest, IdentityPresentationScope, IdentityPresentationValidationOptions, IdentityPresentationCredentialValidationOptions } from './types'

const ALLOWED_SCOPES: IdentityPresentationScope[] = ['identity.basic', 'identity.wallet', 'identity.username', 'identity.email']

function normalizeScopes(scopes: readonly string[]) {
  const values = [...new Set(scopes.map(value => String(value || '').trim()))]
  if (values.length === 0) throw new Error('IDENTITY_SCOPE_REQUIRED')
  for (const value of values) if (!ALLOWED_SCOPES.includes(value as IdentityPresentationScope)) throw new Error('IDENTITY_SCOPE_UNSUPPORTED')
  if (!values.includes('identity.basic')) values.unshift('identity.basic')
  return values as IdentityPresentationScope[]
}

function required(value: unknown, name: string) {
  const normalized = String(value || '').trim()
  if (!normalized) throw new Error(`${name} is required`)
  return normalized
}

function canonicalize(value: unknown): string {
  if (value === null) return 'null'
  if (typeof value !== 'object') return JSON.stringify(value)
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`
  return `{${Object.keys(value as Record<string, unknown>).sort().map(key => `${JSON.stringify(key)}:${canonicalize((value as Record<string, unknown>)[key])}`).join(',')}}`
}

function normalizePresentation(value: unknown): IdentityPresentation {
  if (!value || typeof value !== 'object') throw new Error('IDENTITY_PRESENTATION_INVALID')
  const result = value as Record<string, unknown>
  const proof = result.proof as Record<string, unknown>
  if (result.version !== 1 || typeof result.holder !== 'string' || !Array.isArray(result.scopes) || !proof || proof.type !== 'YeyingIdentityPresentationProofV1' || proof.purpose !== 'authentication' || typeof proof.verificationMethod !== 'string' || typeof proof.proofValue !== 'string') throw new Error('IDENTITY_PRESENTATION_INVALID')
  return result as unknown as IdentityPresentation
}

export async function requestIdentityPresentation(options: IdentityPresentationRequest & { provider?: Eip1193Provider; ensureConnected?: boolean }): Promise<IdentityPresentation> {
  const provider = options.provider || await requireProvider()
  if (options.ensureConnected !== false) await requestAccounts({ provider })
  const scopes = normalizeScopes(options.scopes)
  const request = {
    appId: required(options.appId, 'appId'),
    audience: required(options.audience, 'audience'),
    nonce: required(options.nonce, 'nonce'),
    scopes,
    ...(options.account ? { account: options.account } : {}),
    ...(options.issuer ? { issuer: options.issuer } : {}),
    ...(options.expiresAt ? { expiresAt: options.expiresAt } : {}),
    ...(options.statement ? { statement: options.statement } : {}),
    ...(options.requestId ? { requestId: options.requestId } : {})
  }
  const response = await provider.request({ method: 'yeying_identity_presentation', params: [request] })
  return normalizePresentation(response)
}

export async function verifyIdentityPresentation(presentation: unknown, options: IdentityPresentationValidationOptions): Promise<IdentityPresentation> {
  const value = normalizePresentation(presentation)
  const skew = Math.max(0, options.clockSkewSeconds ?? 60)
  if (value.audience !== options.expectedAudience || value.nonce !== options.expectedNonce) throw new Error('IDENTITY_PRESENTATION_CONTEXT_MISMATCH')
  const requested = new Set(value.scopes)
  for (const scope of options.expectedScopes || []) if (!requested.has(scope)) throw new Error('IDENTITY_PRESENTATION_SCOPE_MISMATCH')
  const issued = Date.parse(value.issuedAt)
  const expires = Date.parse(value.expiresAt)
  const now = (options.now ?? Date.now() / 1000) * 1000
  if (!Number.isFinite(issued) || !Number.isFinite(expires) || issued > now + skew * 1000 || expires <= now - skew * 1000) throw new Error('IDENTITY_PRESENTATION_EXPIRED')
  const method = value.proof.verificationMethod
  if (method !== `${value.holder}#controller-1`) throw new Error('IDENTITY_PRESENTATION_PROOF_INVALID')
  const document = value.identityDocument as Record<string, unknown> | undefined
  const controllers = Array.isArray(document?.controllers) ? document.controllers : []
  const controller = controllers.find((item) => item && typeof item === 'object' && (item as Record<string, unknown>).id === 'controller-1') as Record<string, unknown> | undefined
  const publicKey = controller?.publicKey as JsonWebKey | undefined
  if (!publicKey) throw new Error('IDENTITY_PRESENTATION_KEY_MISSING')
  const { proof, ...unsigned } = value as unknown as Record<string, unknown>
  try {
    const key = await globalThis.crypto.subtle.importKey('jwk', publicKey, { name: 'Ed25519' }, false, ['verify'])
    const valid = await globalThis.crypto.subtle.verify({ name: 'Ed25519' }, key, decodeBase64Url(value.proof.proofValue), new TextEncoder().encode(canonicalize(unsigned)))
    if (!valid) throw new Error('IDENTITY_PRESENTATION_PROOF_INVALID')
  } catch (error) {
    if (error instanceof Error && error.message === 'IDENTITY_PRESENTATION_PROOF_INVALID') throw error
    throw new Error('IDENTITY_PRESENTATION_PROOF_INVALID')
  }
  return value
}

export async function verifyIdentityPresentationCredentials(presentation: unknown, options: IdentityPresentationCredentialValidationOptions) {
  const value = await verifyIdentityPresentation(presentation, options)
  const credentials = value.credentials || []
  const requiredTypes = (options.expectedScopes || value.scopes).filter(scope => scope === 'identity.email' || scope === 'identity.username').map(scope => scope === 'identity.email' ? 'EmailCredential' as const : 'UsernameCredential' as const)
  const uniqueTypes = [...new Set(requiredTypes)]
  const validations = []
  for (const expectedType of uniqueTypes) {
    const token = credentials.find(item => {
      try { return (decodeIdentityCredential(item).payload.vc as Record<string, unknown> | undefined)?.type instanceof Array && ((decodeIdentityCredential(item).payload.vc as Record<string, unknown>).type as unknown[]).includes(expectedType) } catch { return false }
    })
    if (!token) throw new Error(`IDENTITY_CREDENTIAL_MISSING:${expectedType}`)
    validations.push(await verifyIdentityCredential(token, { issuer: options.issuer, publicJwk: options.publicJwk, expectedSubject: value.holder, expectedType, now: options.now }))
  }
  let status: CredentialStatusResponse | undefined
  if (options.nodeBaseUrl) {
    status = await queryCredentialStatuses(options.nodeBaseUrl, options.issuer, validations.map(item => item.credentialId), options.fetcher)
    for (const item of validations) if (status.statuses[item.credentialId] !== 'active') throw new Error(`IDENTITY_CREDENTIAL_NOT_ACTIVE:${item.credentialId}`)
  }
  return { presentation: value, credentials: validations, status }
}
