import {
  Eip1193Provider,
  Eip6963ProviderDetail,
  ProviderDiscoveryOptions,
  ProviderInfo,
  RequestAccountsOptions,
} from './types';

const YEYING_RDNS = 'io.github.yeying';
const DEFAULT_TIMEOUT = 1000;

function getWindowEthereum(): Eip1193Provider | null {
  if (typeof window === 'undefined') return null;
  return (window as unknown as { ethereum?: Eip1193Provider }).ethereum || null;
}

export function isYeYingProvider(provider?: Eip1193Provider | null, info?: ProviderInfo): boolean {
  if (!provider) return false;
  if (provider.isYeYing) return true;
  const name = (info?.name || '').toLowerCase();
  const rdns = (info?.rdns || '').toLowerCase();
  return rdns === YEYING_RDNS || name.includes('yeying');
}

function selectBestProvider(
  candidates: Eip6963ProviderDetail[],
  preferYeYing: boolean
): Eip1193Provider | null {
  if (candidates.length === 0) return null;
  if (preferYeYing) {
    const yeying = candidates.find(c => isYeYingProvider(c.provider, c.info));
    if (yeying) return yeying.provider;
  }
  return candidates[0].provider;
}

export async function getProvider(
  options: ProviderDiscoveryOptions = {}
): Promise<Eip1193Provider | null> {
  const preferYeYing = options.preferYeYing !== false;
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT;
  const windowProvider = getWindowEthereum();

  if (preferYeYing && isYeYingProvider(windowProvider)) {
    return windowProvider;
  }

  if (typeof window === 'undefined') {
    return windowProvider;
  }

  const discovered: Eip6963ProviderDetail[] = [];
  let resolved = false;

  return await new Promise(resolve => {
    const cleanup = () => {
      window.removeEventListener('eip6963:announceProvider', onAnnounce as EventListener);
      window.removeEventListener('ethereum#initialized', onEthereumInitialized as EventListener);
      if (timeoutId) clearTimeout(timeoutId);
    };

    const safeResolve = (provider: Eip1193Provider | null) => {
      if (resolved) return;
      resolved = true;
      cleanup();
      resolve(provider);
    };

    const onAnnounce = (event: Event) => {
      const detail = (event as CustomEvent<Eip6963ProviderDetail>).detail;
      if (!detail?.provider) return;
      discovered.push(detail);

      if (preferYeYing && isYeYingProvider(detail.provider, detail.info)) {
        safeResolve(detail.provider);
      }
    };

    const onEthereumInitialized = () => {
      const injected = getWindowEthereum();
      if (preferYeYing && isYeYingProvider(injected)) {
        safeResolve(injected);
      }
    };

    window.addEventListener('eip6963:announceProvider', onAnnounce as EventListener);
    window.addEventListener('ethereum#initialized', onEthereumInitialized as EventListener, { once: true });

    const timeoutId = setTimeout(() => {
      if (resolved) return;
      const best =
        selectBestProvider(discovered, preferYeYing) ||
        windowProvider ||
        getWindowEthereum();
      safeResolve(best || null);
    }, timeoutMs);

    try {
      window.dispatchEvent(new Event('eip6963:requestProvider'));
    } catch {
      // Ignore if browser doesn't support CustomEvent target
    }

    if (!preferYeYing && windowProvider) {
      safeResolve(windowProvider);
    }
  });
}

export async function requireProvider(
  options: ProviderDiscoveryOptions = {}
): Promise<Eip1193Provider> {
  const provider = await getProvider(options);
  if (!provider) {
    throw new Error('No injected wallet provider found');
  }
  return provider;
}

export async function requestAccounts(
  options: RequestAccountsOptions = {}
): Promise<string[]> {
  const provider = options.provider || (await requireProvider());
  const accounts = (await provider.request({
    method: 'eth_requestAccounts',
  })) as string[];
  return Array.isArray(accounts) ? accounts : [];
}

export async function getAccounts(provider?: Eip1193Provider): Promise<string[]> {
  const p = provider || (await requireProvider());
  const accounts = (await p.request({ method: 'eth_accounts' })) as string[];
  return Array.isArray(accounts) ? accounts : [];
}

export async function getChainId(provider?: Eip1193Provider): Promise<string | null> {
  const p = provider || (await requireProvider());
  const chainId = (await p.request({ method: 'eth_chainId' })) as string;
  return typeof chainId === 'string' ? chainId : null;
}

export async function getBalance(
  provider?: Eip1193Provider,
  address?: string,
  blockTag: string = 'latest'
): Promise<string> {
  const p = provider || (await requireProvider());
  let target = address;
  if (!target) {
    const accounts = await getAccounts(p);
    target = accounts[0];
  }
  if (!target) {
    throw new Error('No account available for balance');
  }

  const balance = (await p.request({
    method: 'eth_getBalance',
    params: [target, blockTag],
  })) as string;
  if (typeof balance !== 'string') {
    throw new Error('Invalid balance response');
  }
  return balance;
}

export function onAccountsChanged(
  provider: Eip1193Provider,
  handler: (accounts: string[]) => void
): () => void {
  provider.on?.('accountsChanged', handler);
  return () => provider.removeListener?.('accountsChanged', handler);
}

export function onChainChanged(
  provider: Eip1193Provider,
  handler: (chainId: string) => void
): () => void {
  provider.on?.('chainChanged', handler);
  return () => provider.removeListener?.('chainChanged', handler);
}
