import { SiweMessage } from 'siwe'
import { getAccounts, getChainId, requireProvider } from './provider'
import {
    AuthBaseOptions,
    AuthFetchOptions,
    AuthTokenResult,
    Eip1193Provider,
    LoginWithChallengeOptions,
    LoginWithSiweOptions,
    LogoutOptions,
    RefreshAccessTokenOptions,
    SignMessageOptions
} from './types'
import { clearAccessToken, getAccessToken, persistAccessToken } from './token'

function normalizeBaseUrl(baseUrl: string): string {
    return baseUrl.replace(/\/+$/, '')
}

function joinUrl(baseUrl: string, path: string): string {
    const trimmed = path.replace(/^\/+/, '')
    return `${normalizeBaseUrl(baseUrl)}/${trimmed}`
}

let refreshInFlight: Promise<AuthTokenResult> | null = null

function resolveFetcher(options?: AuthBaseOptions): typeof fetch {
    return options?.fetcher || fetch
}

function resolveCredentials(options?: AuthBaseOptions): RequestCredentials {
    return options?.credentials ?? 'include'
}

async function resolveAddress(provider: Eip1193Provider, address?: string): Promise<string> {
    if (address) return address
    let accounts = await getAccounts(provider)
    if (!accounts[0]) {
        const requested = (await provider.request({
            method: 'eth_requestAccounts'
        })) as string[]
        if (Array.isArray(requested)) {
            accounts = requested
        }
    }
    if (!accounts[0]) {
        throw new Error('No account available')
    }
    return accounts[0]
}

function extractChallenge(payload: unknown): string | null {
    if (!payload || typeof payload !== 'object') return null
    const data = payload as Record<string, unknown>
    const envelope = data.data as Record<string, unknown> | undefined
    if (envelope) {
        const value = envelope.challenge
        if (typeof value === 'string') return value
    }
    const direct = data.challenge || data.result
    if (typeof direct === 'string') return direct
    if (direct && typeof direct === 'object') {
        const nested = (direct as Record<string, unknown>).challenge
        if (typeof nested === 'string') return nested
    }
    const body = data.body as Record<string, unknown> | undefined
    if (body) {
        const bodyResult = body.result
        if (typeof bodyResult === 'string') return bodyResult
        if (bodyResult && typeof bodyResult === 'object') {
            const nested = (bodyResult as Record<string, unknown>).challenge
            if (typeof nested === 'string') return nested
        }
    }
    return null
}

function extractToken(payload: unknown): string | null {
    if (!payload || typeof payload !== 'object') return null
    const data = payload as Record<string, unknown>
    const envelope = data.data as Record<string, unknown> | undefined
    if (envelope) {
        const value = envelope.token
        if (typeof value === 'string') return value
    }
    const direct = data.token || data.result
    if (typeof direct === 'string') return direct
    const body = data.body as Record<string, unknown> | undefined
    if (body) {
        const bodyToken = body.token
        if (typeof bodyToken === 'string') return bodyToken
        const bodyResult = body.result
        if (typeof bodyResult === 'string') return bodyResult
        if (bodyResult && typeof bodyResult === 'object') {
            const nested = (bodyResult as Record<string, unknown>).token
            if (typeof nested === 'string') return nested
        }
    }
    return null
}

export async function signMessage(options: SignMessageOptions): Promise<string> {
    const provider = options.provider || (await requireProvider())
    const address = await resolveAddress(provider, options.address)
    const method = options.method || 'personal_sign'

    const params = method === 'eth_sign' ? [address, options.message] : [options.message, address]

    const signature = await provider.request({
        method,
        params
    })

    if (typeof signature !== 'string') {
        throw new Error('Invalid signature response')
    }

    return signature
}

export type ChallengeLoginResult = {
    token: string
    address: string
    signature: string
    challenge: string
    response: unknown
}

async function performChallengeLogin(
    options: LoginWithChallengeOptions,
    validateChallenge?: (challenge: string, address: string, provider: Eip1193Provider) => Promise<void>
): Promise<ChallengeLoginResult> {
    const provider = options.provider || (await requireProvider())
    const address = await resolveAddress(provider, options.address)
    const fetcher = resolveFetcher(options)
    const credentials = resolveCredentials(options)
    const baseUrl = options.baseUrl || '/api/v1/public/auth'
    const challengeUrl = joinUrl(baseUrl, options.challengePath || 'challenge')
    const verifyUrl = joinUrl(baseUrl, options.verifyPath || 'verify')

    const challengeBody = {
        address
    }

    const challengeRes = await fetcher(challengeUrl, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            accept: 'application/json'
        },
        credentials,
        body: JSON.stringify(challengeBody)
    })

    if (!challengeRes.ok) {
        const text = await challengeRes.text()
        throw new Error(`Challenge request failed: ${challengeRes.status} ${text}`)
    }

    const challengePayload = await challengeRes.json()
    const challenge = extractChallenge(challengePayload)
    if (!challenge) {
        throw new Error('Challenge response missing challenge')
    }
    await validateChallenge?.(challenge, address, provider)

    const signature = await signMessage({
        provider,
        address,
        message: challenge,
        method: options.signMethod || 'personal_sign'
    })

    const verifyBody = {
        address,
        signature,
        challenge
    }

    const verifyRes = await fetcher(verifyUrl, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            accept: 'application/json'
        },
        credentials,
        body: JSON.stringify(verifyBody)
    })

    if (!verifyRes.ok) {
        const text = await verifyRes.text()
        throw new Error(`Verify request failed: ${verifyRes.status} ${text}`)
    }

    const verifyPayload = await verifyRes.json()
    const token = extractToken(verifyPayload)
    if (!token) {
        throw new Error('Verify response missing token')
    }

    persistAccessToken(token, options)

    return {
        token,
        address,
        signature,
        challenge,
        response: verifyPayload
    }
}

/**
 * @deprecated Use loginWithSiwe for wallet login. This custom challenge
 * contract is retained for 1.x migrations and will be removed in the next
 * major version.
 */
export async function loginWithChallenge(options: LoginWithChallengeOptions = {}): Promise<ChallengeLoginResult> {
    return performChallengeLogin(options)
}

export async function loginWithSiwe(options: LoginWithSiweOptions = {}): Promise<ChallengeLoginResult> {
    return performChallengeLogin(options, async (challenge, address, provider) => {
        let message: SiweMessage
        try {
            message = new SiweMessage(challenge)
        } catch {
            throw new Error('SIWE_MESSAGE_INVALID')
        }

        const expectedDomain = options.domain || (typeof window !== 'undefined' ? window.location.host : '')
        const expectedUri = options.uri || (typeof window !== 'undefined' ? window.location.origin : '')
        const providerChainId = await getChainId(provider)
        const parsedProviderChainId = providerChainId
            ? Number.parseInt(providerChainId, providerChainId.toLowerCase().startsWith('0x') ? 16 : 10)
            : undefined
        const expectedChainId = String(options.chainId ?? (Number.isFinite(parsedProviderChainId) ? parsedProviderChainId : ''))
        const now = (options.now || new Date()).getTime()

        if (message.version !== '1') throw new Error('SIWE_VERSION_INVALID')
        if (message.address.toLowerCase() !== address.toLowerCase()) throw new Error('SIWE_ADDRESS_MISMATCH')
        if (expectedDomain && message.domain !== expectedDomain) throw new Error('SIWE_DOMAIN_MISMATCH')
        if (expectedUri && message.uri !== expectedUri) throw new Error('SIWE_URI_MISMATCH')
        if (expectedChainId && String(message.chainId) !== expectedChainId) throw new Error('SIWE_CHAIN_ID_MISMATCH')
        if (!message.issuedAt || !Number.isFinite(Date.parse(message.issuedAt))) throw new Error('SIWE_ISSUED_AT_INVALID')
        if (Date.parse(message.issuedAt) > now + 60_000) throw new Error('SIWE_ISSUED_AT_INVALID')
        if (message.notBefore && Date.parse(message.notBefore) > now) throw new Error('SIWE_NOT_BEFORE')
        if (message.expirationTime && Date.parse(message.expirationTime) <= now) throw new Error('SIWE_EXPIRED')
    })
}

export async function refreshAccessToken(options: RefreshAccessTokenOptions = {}): Promise<AuthTokenResult> {
    if (refreshInFlight) {
        return refreshInFlight
    }

    const task = (async () => {
        const fetcher = resolveFetcher(options)
        const credentials = resolveCredentials(options)
        const baseUrl = options.baseUrl || '/api/v1/public/auth'
        const refreshUrl = joinUrl(baseUrl, options.refreshPath || 'refresh')

        const refreshRes = await fetcher(refreshUrl, {
            method: 'POST',
            headers: {
                accept: 'application/json'
            },
            credentials
        })

        if (!refreshRes.ok) {
            const text = await refreshRes.text()
            throw new Error(`Refresh request failed: ${refreshRes.status} ${text}`)
        }

        const refreshPayload = await refreshRes.json()
        const token = extractToken(refreshPayload)
        if (!token) {
            throw new Error('Refresh response missing token')
        }

        persistAccessToken(token, options)

        return { token, response: refreshPayload }
    })()

    refreshInFlight = task
    try {
        return await task
    } finally {
        refreshInFlight = null
    }
}

export async function logout(options: LogoutOptions = {}): Promise<{ response: unknown }> {
    const fetcher = resolveFetcher(options)
    const credentials = resolveCredentials(options)
    const baseUrl = options.baseUrl || '/api/v1/public/auth'
    const logoutUrl = joinUrl(baseUrl, options.logoutPath || 'logout')

    const logoutRes = await fetcher(logoutUrl, {
        method: 'POST',
        headers: {
            accept: 'application/json'
        },
        credentials
    })

    if (!logoutRes.ok) {
        const text = await logoutRes.text()
        throw new Error(`Logout request failed: ${logoutRes.status} ${text}`)
    }

    let payload: unknown = null
    try {
        payload = await logoutRes.json()
    } catch {
        payload = null
    }

    clearAccessToken(options)

    return { response: payload }
}

export async function authFetch(
    input: RequestInfo | URL,
    init: RequestInit = {},
    options: AuthFetchOptions = {}
): Promise<Response> {
    const fetcher = resolveFetcher(options)
    const credentials = resolveCredentials(options)
    const retryOnUnauthorized = options.retryOnUnauthorized !== false

    const performRequest = async (tokenOverride?: string | null): Promise<Response> => {
        const headers = new Headers(init.headers || {})
        const token = tokenOverride ?? options.accessToken ?? getAccessToken(options)
        if (token && !headers.has('Authorization')) {
            headers.set('Authorization', `Bearer ${token}`)
        }

        return fetcher(input, {
            ...init,
            headers,
            credentials
        })
    }

    const initialRes = await performRequest()
    if (initialRes.status !== 401 || !retryOnUnauthorized) {
        return initialRes
    }

    try {
        const refreshed = await refreshAccessToken(options)
        return await performRequest(refreshed.token)
    } catch {
        return initialRes
    }
}
