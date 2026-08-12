import test from 'node:test';
import assert from 'node:assert/strict';

import {
  normalizePassportScopes,
  requestPassportAssertion,
} from '../dist/web3-bs.esm.js';

function createProvider(handler) {
  const calls = [];
  return {
    calls,
    async request(request) {
      calls.push(request);
      return handler(request, calls);
    },
  };
}

test('normalizePassportScopes defaults basic and wallet scopes', () => {
  assert.deepEqual(normalizePassportScopes(), ['identity.basic', 'identity.wallet']);
  assert.deepEqual(normalizePassportScopes(['identity.email']), ['identity.basic', 'identity.email']);
});

test('requestPassportAssertion connects wallet and calls Wallet Passport RPC', async () => {
  const provider = createProvider((request) => {
    if (request.method === 'eth_requestAccounts') return ['0xabc'];
    if (request.method === 'yeying_passport_assertion') {
      assert.deepEqual(request.params, [{
        appId: 'community-app',
        audience: 'https://app.example',
        nonce: 'nonce-1',
        scopes: ['identity.basic', 'identity.wallet', 'identity.email'],
        passportEndpoint: 'https://node.example',
      }]);
      return {
        address: '0xabc',
        walletProof: {
          method: 'personal_sign',
          address: '0xabc',
          message: 'message',
          signature: '0xsig',
          appId: 'community-app',
          audience: 'https://app.example',
          nonce: 'nonce-1',
          scopes: ['identity.basic', 'identity.wallet', 'identity.email'],
        },
        passportAssertion: 'jwt-1',
      };
    }
    throw new Error(`Unexpected method: ${request.method}`);
  });

  const result = await requestPassportAssertion({
    provider,
    appId: 'community-app',
    audience: 'https://app.example',
    nonce: 'nonce-1',
    scope: ['identity.wallet', 'identity.email'],
    passportEndpoint: 'https://node.example',
  });

  assert.equal(result.passportAssertion, 'jwt-1');
  assert.deepEqual(provider.calls.map((call) => call.method), [
    'eth_requestAccounts',
    'yeying_passport_assertion',
  ]);
});

test('requestPassportAssertion can skip connect when caller already connected', async () => {
  const provider = createProvider((request) => {
    assert.equal(request.method, 'yeying_passport_assertion');
    return {
      address: '0xabc',
      walletProof: {
        method: 'personal_sign',
        address: '0xabc',
        message: 'message',
        signature: '0xsig',
        appId: 'community-app',
        audience: 'https://app.example',
        nonce: 'nonce-1',
        scopes: ['identity.basic'],
      },
      passportAssertion: 'jwt-1',
    };
  });

  await requestPassportAssertion({
    provider,
    appId: 'community-app',
    audience: 'https://app.example',
    nonce: 'nonce-1',
    scopes: ['identity.basic'],
    ensureConnected: false,
  });
  assert.equal(provider.calls.length, 1);
});
