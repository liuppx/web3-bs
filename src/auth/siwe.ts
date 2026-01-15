import { getAccounts, requireProvider } from './provider';
import {
  AuthBaseOptions,
  AuthFetchOptions,
  AuthTokenResult,
  Eip1193Provider,
  LoginWithChallengeOptions,
  LogoutOptions,
  RefreshAccessTokenOptions,
  SignMessageOptions,
} from './types';

function normalizeBaseUrl(baseUrl: string): string {
  return baseUrl.replace(/\/+$/, '');
}

function joinUrl(baseUrl: string, path: string): string {
  const trimmed = path.replace(/^\/+/, '');
  return `${normalizeBaseUrl(baseUrl)}/${trimmed}`;
}

const DEFAULT_TOKEN_KEY = 'authToken';
let cachedAccessToken: string | null = null;
let refreshInFlight: Promise<AuthTokenResult> | null = null;

function resolveTokenKey(options?: AuthBaseOptions): string {
  return options?.tokenStorageKey || DEFAULT_TOKEN_KEY;
}

function shouldStoreToken(options?: AuthBaseOptions): boolean {
  return options?.storeToken !== false;
}

function resolveFetcher(options?: AuthBaseOptions): typeof fetch {
  return options?.fetcher || fetch;
}

function resolveCredentials(options?: AuthBaseOptions): RequestCredentials {
  return options?.credentials ?? 'include';
}

function readStoredToken(options?: AuthBaseOptions): string | null {
  if (!shouldStoreToken(options)) return null;
  if (typeof localStorage === 'undefined') return null;
  const key = resolveTokenKey(options);
  return localStorage.getItem(key);
}

function persistToken(token: string | null, options?: AuthBaseOptions): void {
  cachedAccessToken = token;
  if (!shouldStoreToken(options)) return;
  if (typeof localStorage === 'undefined') return;
  const key = resolveTokenKey(options);
  if (!token) {
    localStorage.removeItem(key);
  } else {
    localStorage.setItem(key, token);
  }
}

export function getAccessToken(options?: AuthBaseOptions): string | null {
  if (cachedAccessToken) return cachedAccessToken;
  const stored = readStoredToken(options);
  if (stored) {
    cachedAccessToken = stored;
  }
  return stored;
}

export function setAccessToken(token: string | null, options?: AuthBaseOptions): void {
  persistToken(token, options);
}

export function clearAccessToken(options?: AuthBaseOptions): void {
  cachedAccessToken = null;
  if (typeof localStorage === 'undefined') return;
  const key = resolveTokenKey(options);
  localStorage.removeItem(key);
}

async function resolveAddress(
  provider: Eip1193Provider,
  address?: string
): Promise<string> {
  if (address) return address;
  let accounts = await getAccounts(provider);
  if (!accounts[0]) {
    const requested = (await provider.request({
      method: 'eth_requestAccounts',
    })) as string[];
    if (Array.isArray(requested)) {
      accounts = requested;
    }
  }
  if (!accounts[0]) {
    throw new Error('No account available');
  }
  return accounts[0];
}

function extractChallenge(payload: unknown): string | null {
  if (!payload || typeof payload !== 'object') return null;
  const data = payload as Record<string, unknown>;
  const envelope = data.data as Record<string, unknown> | undefined;
  if (envelope) {
    const value = envelope.challenge;
    if (typeof value === 'string') return value;
  }
  const direct = data.challenge || data.result;
  if (typeof direct === 'string') return direct;
  if (direct && typeof direct === 'object') {
    const nested = (direct as Record<string, unknown>).challenge;
    if (typeof nested === 'string') return nested;
  }
  const body = data.body as Record<string, unknown> | undefined;
  if (body) {
    const bodyResult = body.result;
    if (typeof bodyResult === 'string') return bodyResult;
    if (bodyResult && typeof bodyResult === 'object') {
      const nested = (bodyResult as Record<string, unknown>).challenge;
      if (typeof nested === 'string') return nested;
    }
  }
  return null;
}

function extractToken(payload: unknown): string | null {
  if (!payload || typeof payload !== 'object') return null;
  const data = payload as Record<string, unknown>;
  const envelope = data.data as Record<string, unknown> | undefined;
  if (envelope) {
    const value = envelope.token;
    if (typeof value === 'string') return value;
  }
  const direct = data.token || data.result;
  if (typeof direct === 'string') return direct;
  const body = data.body as Record<string, unknown> | undefined;
  if (body) {
    const bodyToken = body.token;
    if (typeof bodyToken === 'string') return bodyToken;
    const bodyResult = body.result;
    if (typeof bodyResult === 'string') return bodyResult;
    if (bodyResult && typeof bodyResult === 'object') {
      const nested = (bodyResult as Record<string, unknown>).token;
      if (typeof nested === 'string') return nested;
    }
  }
  return null;
}

export async function signMessage(options: SignMessageOptions): Promise<string> {
  const provider = options.provider || (await requireProvider());
  const address = await resolveAddress(provider, options.address);
  const method = options.method || 'personal_sign';

  const params =
    method === 'eth_sign'
      ? [address, options.message]
      : [options.message, address];

  const signature = await provider.request({
    method,
    params,
  });

  if (typeof signature !== 'string') {
    throw new Error('Invalid signature response');
  }

  return signature;
}

export async function loginWithChallenge(
  options: LoginWithChallengeOptions = {}
): Promise<{
  token: string;
  address: string;
  signature: string;
  challenge: string;
  response: unknown;
}> {
  const provider = options.provider || (await requireProvider());
  const address = await resolveAddress(provider, options.address);
  const fetcher = resolveFetcher(options);
  const credentials = resolveCredentials(options);
  const baseUrl = options.baseUrl || '/api/v1/public/auth';
  const challengeUrl = joinUrl(baseUrl, options.challengePath || 'challenge');
  const verifyUrl = joinUrl(baseUrl, options.verifyPath || 'verify');

  const challengeBody = {
    address,
  };

  const challengeRes = await fetcher(challengeUrl, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      accept: 'application/json',
    },
    credentials,
    body: JSON.stringify(challengeBody),
  });

  if (!challengeRes.ok) {
    const text = await challengeRes.text();
    throw new Error(`Challenge request failed: ${challengeRes.status} ${text}`);
  }

  const challengePayload = await challengeRes.json();
  const challenge = extractChallenge(challengePayload);
  if (!challenge) {
    throw new Error('Challenge response missing challenge');
  }

  const signature = await signMessage({
    provider,
    address,
    message: challenge,
    method: options.signMethod || 'personal_sign',
  });

  const verifyBody = {
    address,
    signature,
  };

  const verifyRes = await fetcher(verifyUrl, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      accept: 'application/json',
    },
    credentials,
    body: JSON.stringify(verifyBody),
  });

  if (!verifyRes.ok) {
    const text = await verifyRes.text();
    throw new Error(`Verify request failed: ${verifyRes.status} ${text}`);
  }

  const verifyPayload = await verifyRes.json();
  const token = extractToken(verifyPayload);
  if (!token) {
    throw new Error('Verify response missing token');
  }

  persistToken(token, options);

  return {
    token,
    address,
    signature,
    challenge,
    response: verifyPayload,
  };
}

export async function refreshAccessToken(
  options: RefreshAccessTokenOptions = {}
): Promise<AuthTokenResult> {
  if (refreshInFlight) {
    return refreshInFlight;
  }

  const task = (async () => {
    const fetcher = resolveFetcher(options);
    const credentials = resolveCredentials(options);
    const baseUrl = options.baseUrl || '/api/v1/public/auth';
    const refreshUrl = joinUrl(baseUrl, options.refreshPath || 'refresh');

    const refreshRes = await fetcher(refreshUrl, {
      method: 'POST',
      headers: {
        accept: 'application/json',
      },
      credentials,
    });

    if (!refreshRes.ok) {
      const text = await refreshRes.text();
      throw new Error(`Refresh request failed: ${refreshRes.status} ${text}`);
    }

    const refreshPayload = await refreshRes.json();
    const token = extractToken(refreshPayload);
    if (!token) {
      throw new Error('Refresh response missing token');
    }

    persistToken(token, options);

    return { token, response: refreshPayload };
  })();

  refreshInFlight = task;
  try {
    return await task;
  } finally {
    refreshInFlight = null;
  }
}

export async function logout(options: LogoutOptions = {}): Promise<{ response: unknown }> {
  const fetcher = resolveFetcher(options);
  const credentials = resolveCredentials(options);
  const baseUrl = options.baseUrl || '/api/v1/public/auth';
  const logoutUrl = joinUrl(baseUrl, options.logoutPath || 'logout');

  const logoutRes = await fetcher(logoutUrl, {
    method: 'POST',
    headers: {
      accept: 'application/json',
    },
    credentials,
  });

  if (!logoutRes.ok) {
    const text = await logoutRes.text();
    throw new Error(`Logout request failed: ${logoutRes.status} ${text}`);
  }

  let payload: unknown = null;
  try {
    payload = await logoutRes.json();
  } catch {
    payload = null;
  }

  clearAccessToken(options);

  return { response: payload };
}

export async function authFetch(
  input: RequestInfo | URL,
  init: RequestInit = {},
  options: AuthFetchOptions = {}
): Promise<Response> {
  const fetcher = resolveFetcher(options);
  const credentials = resolveCredentials(options);
  const retryOnUnauthorized = options.retryOnUnauthorized !== false;

  const performRequest = async (tokenOverride?: string | null): Promise<Response> => {
    const headers = new Headers(init.headers || {});
    const token = tokenOverride ?? options.accessToken ?? getAccessToken(options);
    if (token && !headers.has('Authorization')) {
      headers.set('Authorization', `Bearer ${token}`);
    }

    return fetcher(input, {
      ...init,
      headers,
      credentials,
    });
  };

  const initialRes = await performRequest();
  if (initialRes.status !== 401 || !retryOnUnauthorized) {
    return initialRes;
  }

  try {
    const refreshed = await refreshAccessToken(options);
    return await performRequest(refreshed.token);
  } catch {
    return initialRes;
  }
}
