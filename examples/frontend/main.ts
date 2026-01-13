import {
  getProvider,
  requestAccounts,
  loginWithChallenge,
  authFetch,
  refreshAccessToken,
  getAccessToken,
} from '@yeying-community/web3';

async function connectAndLogin() {
  const provider = await getProvider();
  if (!provider) {
    throw new Error('No injected wallet provider');
  }

  const accounts = await requestAccounts({ provider });
  const address = accounts[0];
  if (!address) {
    throw new Error('No account returned');
  }

  const login = await loginWithChallenge({
    provider,
    address,
    baseUrl: 'http://localhost:4001/api/v1/public/auth',
    storeToken: false,
  });

  console.log('token', login.token);

  const profileRes = await authFetch('http://localhost:4001/api/v1/private/profile', { method: 'GET' }, {
    baseUrl: 'http://localhost:4001/api/v1/public/auth',
    storeToken: false,
  });

  console.log('profile', await profileRes.json());

  const refreshed = await refreshAccessToken({
    baseUrl: 'http://localhost:4001/api/v1/public/auth',
    storeToken: false,
  });

  console.log('refreshed token', refreshed.token);
  console.log('current token', getAccessToken({ storeToken: false }));
}

connectAndLogin().catch(error => {
  console.error('Login failed:', error);
});
