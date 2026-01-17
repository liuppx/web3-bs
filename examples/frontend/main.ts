import {
  getProvider,
  requestAccounts,
  loginWithChallenge,
  authFetch,
  refreshAccessToken,
  getAccessToken,
  createUcanSession,
  createRootUcan,
  createInvocationUcan,
  authUcanFetch,
  createWebDavClient,
} from '@yeying-community/web3-bs';

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
    baseUrl: 'http://localhost:3203/api/v1/public/auth',
    storeToken: false,
  });

  console.log('token', login.token);

  const profileRes = await authFetch('http://localhost:3203/api/v1/public/profile', { method: 'GET' }, {
    baseUrl: 'http://localhost:3203/api/v1/public/auth',
    storeToken: false,
  });

  console.log('profile', await profileRes.json());

  const refreshed = await refreshAccessToken({
    baseUrl: 'http://localhost:3203/api/v1/public/auth',
    storeToken: false,
  });

  console.log('refreshed token', refreshed.token);
  console.log('current token', getAccessToken({ storeToken: false }));

  // WebDAV Storage (requires webdav server running on 6065)
  try {
    const webdav = createWebDavClient({
      baseUrl: 'http://localhost:6065',
      token: login.token,
      prefix: '/',
    });
    const listing = await webdav.listDirectory('/');
    console.log('webdav list', listing);
    await webdav.upload('/web3-bs.txt', 'Hello WebDAV');
    console.log('webdav uploaded');
    const content = await webdav.downloadText('/web3-bs.txt');
    console.log('webdav download', content);
  } catch (error) {
    console.warn('webdav not available', error);
  }

  const session = await createUcanSession();
  const root = await createRootUcan({
    provider,
    session,
    capabilities: [{ resource: 'profile', action: 'read' }],
  });
  const ucanToken = await createInvocationUcan({
    issuer: session,
    audience: 'did:web:localhost:3203',
    capabilities: [{ resource: 'profile', action: 'read' }],
    proofs: [root],
  });
  const ucanRes = await authUcanFetch(
    'http://localhost:3203/api/v1/public/profile',
    { method: 'GET' },
    { ucan: ucanToken }
  );
  console.log('ucan profile', await ucanRes.json());
}

connectAndLogin().catch(error => {
  console.error('Login failed:', error);
});
