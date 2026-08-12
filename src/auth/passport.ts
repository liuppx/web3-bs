import { requestAccounts, requireProvider } from './provider';
import {
  Eip1193Provider,
  PassportAssertionOptions,
  PassportAssertionResult,
} from './types';

const DEFAULT_SCOPES = ['identity.basic', 'identity.wallet'] as const;

function normalizeScopes(scopes?: readonly string[]): string[] {
  const source = scopes && scopes.length > 0 ? scopes : DEFAULT_SCOPES;
  const normalized: string[] = [];
  for (const scope of source) {
    const value = String(scope || '').trim();
    if (!value) continue;
    if (!normalized.includes(value)) normalized.push(value);
  }
  if (!normalized.includes('identity.basic')) normalized.unshift('identity.basic');
  return normalized;
}

function requireString(value: unknown, name: string): string {
  const normalized = String(value || '').trim();
  if (!normalized) throw new Error(`${name} is required`);
  return normalized;
}

function normalizeResult(value: unknown): PassportAssertionResult {
  if (!value || typeof value !== 'object') {
    throw new Error('Wallet returned an invalid Passport assertion response');
  }
  const result = value as Record<string, unknown>;
  if (
    typeof result.address !== 'string' ||
    typeof result.passportAssertion !== 'string' ||
    !result.walletProof ||
    typeof result.walletProof !== 'object'
  ) {
    throw new Error('Wallet returned an invalid Passport assertion response');
  }
  return result as unknown as PassportAssertionResult;
}

export async function requestPassportAssertion(
  options: PassportAssertionOptions
): Promise<PassportAssertionResult> {
  const provider: Eip1193Provider = options.provider || (await requireProvider());
  if (options.ensureConnected !== false) {
    await requestAccounts({ provider });
  }

  const response = await provider.request({
    method: 'yeying_passport_assertion',
    params: [{
      appId: requireString(options.appId, 'appId'),
      audience: requireString(options.audience, 'audience'),
      nonce: requireString(options.nonce, 'nonce'),
      scopes: normalizeScopes(options.scopes || options.scope),
      ...(options.passportEndpoint ? { passportEndpoint: options.passportEndpoint } : {}),
      ...(options.statement ? { statement: options.statement } : {}),
      ...(options.requestId ? { requestId: options.requestId } : {}),
    }],
  });

  return normalizeResult(response);
}

export { normalizeScopes as normalizePassportScopes };
