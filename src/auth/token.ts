import type { AuthBaseOptions } from './types'

const DEFAULT_TOKEN_KEY = 'authToken'
let cachedAccessToken: string | null = null

function resolveTokenKey(options?: AuthBaseOptions): string {
    return options?.tokenStorageKey || DEFAULT_TOKEN_KEY
}

function shouldStoreToken(options?: AuthBaseOptions): boolean {
    return options?.storeToken !== false
}

function readStoredToken(options?: AuthBaseOptions): string | null {
    if (!shouldStoreToken(options) || typeof localStorage === 'undefined') return null
    return localStorage.getItem(resolveTokenKey(options))
}

export function persistAccessToken(token: string | null, options?: AuthBaseOptions): void {
    cachedAccessToken = token
    if (!shouldStoreToken(options) || typeof localStorage === 'undefined') return
    const key = resolveTokenKey(options)
    if (token) localStorage.setItem(key, token)
    else localStorage.removeItem(key)
}

export function getAccessToken(options?: AuthBaseOptions): string | null {
    if (cachedAccessToken) return cachedAccessToken
    const stored = readStoredToken(options)
    if (stored) cachedAccessToken = stored
    return stored
}

export function setAccessToken(token: string | null, options?: AuthBaseOptions): void {
    persistAccessToken(token, options)
}

export function clearAccessToken(options?: AuthBaseOptions): void {
    cachedAccessToken = null
    if (typeof localStorage !== 'undefined') localStorage.removeItem(resolveTokenKey(options))
}
