export type JsonRpcRequest = {
  method: string;
  params?: unknown[] | Record<string, unknown>;
};

export interface Eip1193Provider {
  request: (args: JsonRpcRequest) => Promise<unknown>;
  on?: {
    (event: 'accountsChanged', listener: (accounts: string[]) => void): void;
    (event: 'chainChanged', listener: (chainId: string) => void): void;
    (event: string, listener: (...args: unknown[]) => void): void;
  };
  removeListener?: {
    (event: 'accountsChanged', listener: (accounts: string[]) => void): void;
    (event: 'chainChanged', listener: (chainId: string) => void): void;
    (event: string, listener: (...args: unknown[]) => void): void;
  };
  isMetaMask?: boolean;
  isYeYing?: boolean;
  providers?: Eip1193Provider[];
  [key: string]: unknown;
}

export interface ProviderInfo {
  uuid?: string;
  name?: string;
  icon?: string;
  rdns?: string;
}

export interface Eip6963ProviderDetail {
  info: ProviderInfo;
  provider: Eip1193Provider;
}

export interface ProviderDiscoveryOptions {
  timeoutMs?: number;
  preferYeYing?: boolean;
}

export interface WatchProviderOptions extends ProviderDiscoveryOptions {
  pollIntervalMs?: number;
  maxPolls?: number;
}

export type ProviderChangedHandler = (payload: {
  provider: Eip1193Provider | null;
  present: boolean;
}) => void;

export type WalletErrorType =
  | 'userRejected'
  | 'disconnected'
  | 'timeout'
  | 'notFound'
  | 'unknown';

export type WalletErrorInfo = {
  type: WalletErrorType;
  code: number | null;
  message: string;
};

export interface RequestAccountsOptions {
  provider?: Eip1193Provider;
  dedupe?: boolean;
}

export type FocusPendingApprovalResult = {
  focused: boolean;
  type: string | null;
  requestId?: string | null;
  origin?: string;
  tabId?: number | null;
};

export type AccountSelection = {
  account: string | null;
  accounts: string[];
};

export interface PreferredAccountOptions extends RequestAccountsOptions {
  storageKey?: string;
  autoConnect?: boolean;
  preferStored?: boolean;
}

export interface ResolveWalletAccountOptions extends RequestAccountsOptions {
  expectedAccount?: string | null;
  autoConnect?: boolean;
}

export type WalletAccountResolution =
  | {
      status: 'wallet';
      account: string;
      walletAccount: string;
      expectedAccount: null;
      accounts: string[];
    }
  | {
      status: 'matched';
      account: string;
      walletAccount: string;
      expectedAccount: string;
      accounts: string[];
    }
  | {
      status: 'mismatch';
      account: null;
      walletAccount: string;
      expectedAccount: string;
      accounts: string[];
    }
  | {
      status: 'unavailable';
      account: null;
      walletAccount: null;
      expectedAccount: string | null;
      accounts: string[];
    };

export interface WatchAccountsOptions {
  storageKey?: string;
  preferStored?: boolean;
}

export type AccountsChangedHandler = (payload: AccountSelection) => void;

export interface SignMessageOptions {
  provider?: Eip1193Provider;
  message: string;
  address?: string;
  method?: 'personal_sign' | 'eth_sign';
}

export interface AuthBaseOptions {
  baseUrl?: string;
  fetcher?: typeof fetch;
  credentials?: RequestCredentials;
  storeToken?: boolean;
  tokenStorageKey?: string;
}

export interface LoginWithChallengeOptions extends AuthBaseOptions {
  provider?: Eip1193Provider;
  address?: string;
  challengePath?: string;
  verifyPath?: string;
  signMethod?: 'personal_sign' | 'eth_sign';
}

export type IdentityPresentationScope = 'identity.basic' | 'identity.wallet' | 'identity.username' | 'identity.email';

export type IdentityPresentationRequest = {
  appId?: string;
  audience: string;
  nonce: string;
  scopes: IdentityPresentationScope[];
  account?: { chainKey: string; address: string };
  issuer?: string;
  expiresAt?: string;
  statement?: string;
  requestId?: string;
};

export type IdentityPresentation = {
  version: 1;
  holder: string;
  audience: string;
  nonce: string;
  issuedAt: string;
  expiresAt: string;
  scopes: IdentityPresentationScope[];
  identityDocument?: Record<string, unknown>;
  walletProof?: Record<string, unknown>;
  credentials?: string[];
  proof: {
    type: 'YeyingIdentityPresentationProofV1';
    verificationMethod: string;
    purpose: 'authentication';
    proofValue: string;
  };
};

export type IdentityPresentationValidationOptions = {
  expectedAudience: string;
  expectedNonce: string;
  expectedScopes?: IdentityPresentationScope[];
  now?: number;
  clockSkewSeconds?: number;
};

export type IdentityPresentationCredentialValidationOptions = IdentityPresentationValidationOptions & {
  issuer: string;
  publicJwk: JsonWebKey;
  nodeBaseUrl?: string;
  fetcher?: typeof fetch;
};

export type WalletIdentityLoginOptions = AuthBaseOptions & {
  provider?: Eip1193Provider;
  address?: string;
  sessionPath?: string;
  verifyPath?: string;
  accountChallengePath?: string;
  accountVerifyPath?: string;
};

export type WalletIdentityLoginResult = {
  token: string;
  did: string;
  walletAddress?: string;
  /** @deprecated use walletAddress for the verified wallet account. */
  address: string;
  response: unknown;
};

export interface RefreshAccessTokenOptions extends AuthBaseOptions {
  refreshPath?: string;
}

export interface LogoutOptions extends AuthBaseOptions {
  logoutPath?: string;
}

export interface AuthFetchOptions extends AuthBaseOptions {
  refreshPath?: string;
  accessToken?: string | null;
  retryOnUnauthorized?: boolean;
}

export interface AuthTokenResult {
  token: string;
  response: unknown;
}
