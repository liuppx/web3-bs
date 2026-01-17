# YeYing Inject Wallet SDK

轻量级注入钱包 SDK，专注浏览器端 EIP-1193 Provider。默认优先选择 YeYing Wallet（支持 EIP-6963 多钱包发现）。
仅支持浏览器环境（依赖 `window` / `localStorage` / `fetch`）。

## 安装

```bash
npm install @yeying-community/web3-bs
```

## 钱包交互 API

### Provider 发现
- `getProvider(options?)`
  - 自动监听 `eip6963:announceProvider`
  - 默认优先 YeYing（`isYeYing` 或 `rdns: io.github.yeying`）

### 核心方法
- `requestAccounts({ provider? })`
- `getAccounts(provider?)`
- `getChainId(provider?)`
- `getBalance(provider?, address?, blockTag?)`
- `signMessage({ provider?, message, address?, method? })`
  - `method` 默认 `personal_sign`

### 事件
- `onAccountsChanged(provider, handler)`
- `onChainChanged(provider, handler)`

## 后端交互 API（推荐标准）
OpenAPI 规范：`docs/openapi.yaml`

### 响应封装（严格）
所有响应必须使用以下封装结构：

```json
{
  "code": 0,
  "message": "ok",
  "data": { "...": "..." },
  "timestamp": 1730000000000
}
```

- `code = 0` 表示成功
- `code != 0` 表示失败；`data` 应为 `null`

### 1) 获取 Challenge

`POST /api/v1/public/auth/challenge`

请求
```json
{ "address": "0xabc123..." }
```

响应
```json
{
  "code": 0,
  "message": "ok",
  "data": {
    "address": "0xabc123...",
    "challenge": "Sign to login...",
    "nonce": "random",
    "issuedAt": 1730000000000,
    "expiresAt": 1730000300000
  },
  "timestamp": 1730000000000
}
```

### 2) 验证签名

`POST /api/v1/public/auth/verify`

请求
```json
{ "address": "0xabc123...", "signature": "0x..." }
```

响应
```json
{
  "code": 0,
  "message": "ok",
  "data": {
    "address": "0xabc123...",
    "token": "access-token",
    "expiresAt": 1730086400000,
    "refreshExpiresAt": 1730686400000
  },
  "timestamp": 1730000000000
}
```

说明
- `verify` 应设置 httpOnly 的 `refresh_token` Cookie（用于刷新 access token）。
- 访问受保护接口时，前端使用 `Authorization: Bearer <access-token>`。

### 3) 刷新 Access Token

`POST /api/v1/public/auth/refresh`

请求
- 依赖 httpOnly `refresh_token` Cookie

响应
```json
{
  "code": 0,
  "message": "ok",
  "data": {
    "address": "0xabc123...",
    "token": "new-access-token",
    "expiresAt": 1730086400000,
    "refreshExpiresAt": 1730686400000
  },
  "timestamp": 1730000000000
}
```

### 4) 退出登录

`POST /api/v1/public/auth/logout`

响应
```json
{
  "code": 0,
  "message": "ok",
  "data": { "logout": true },
  "timestamp": 1730000000000
}
```

### SDK 绑定
- `loginWithChallenge` 会从 `data.challenge` 读取 challenge，从 `data.token` 读取 token。
- `refreshAccessToken` 调用 `/refresh` 并更新 access token（默认 `credentials: 'include'`）。
- `authFetch` 会自动携带 access token，遇到 401 会尝试刷新再重试一次。
- `logout` 会清理刷新 Cookie 并清空本地 access token（若设置 `storeToken`）。

## 示例

- Frontend Dapp (HTML): `examples/frontend/dapp.html`
- Frontend Dapp (TS module): `examples/frontend/main.ts`
- Backend server (Node): `examples/backend/node/server.js`
- Backend server (Go): `examples/backend/go/main.go`
- Backend server (Python): `examples/backend/python/app.py`
- Backend server (Java): `examples/backend/java/src/main/java/com/yeying/demo/AuthServer.java`

## UCAN 授权（SIWE Bridge）

SDK 通过 YeYing 钱包生成 UCAN Session Key 并完成签名（由钱包后台隔离私钥）。
Root UCAN 基于 SIWE 签名，
用于多后端统一鉴权。UCAN 以 `Authorization: Bearer <UCAN>` 发送，后端会验证 UCAN 证明链与能力。

新增 API：
- `createUcanSession(options?)`
- `createRootUcan(options)`
- `createDelegationUcan(options)`
- `createInvocationUcan(options)`
- `authUcanFetch(url, init?, options?)`

示例：
```ts
const session = await createUcanSession();
const root = await createRootUcan({
  provider,
  session,
  capabilities: [{ resource: 'profile', action: 'read' }],
});

const ucan = await createInvocationUcan({
  issuer: session,
  audience: 'did:web:localhost:3203',
  capabilities: [{ resource: 'profile', action: 'read' }],
  proofs: [root],
});

const res = await authUcanFetch('http://localhost:3203/api/v1/public/profile', { method: 'GET' }, { ucan });
console.log(await res.json());
```

后端默认要求的能力为 `resource=profile`、`action=read`，可通过环境变量覆盖：
- `UCAN_AUD`：服务 DID（默认 `did:web:localhost:3203`）
- `UCAN_RESOURCE`：资源（默认 `profile`）
- `UCAN_ACTION`：动作（默认 `read`）

提示：如需可转授权，使用 `createDelegationUcan` 创建委任链，再用被委任的 Key 生成 Invocation UCAN。

## WebDAV 存储（Storage）

提供基于 WebDAV 服务的文件操作封装（上传/下载/删除/目录等），适配 `webdav` 项目 API。

示例：
```ts
import { createWebDavClient, loginWithChallenge } from '@yeying-community/web3-bs';

const login = await loginWithChallenge({
  provider,
  baseUrl: 'http://localhost:6065/api/v1/public/auth',
  storeToken: false,
});

const client = createWebDavClient({
  baseUrl: 'http://localhost:6065',
  token: login.token,
  prefix: '/',
});

const listingXml = await client.listDirectory('/');
await client.upload('/docs/hello.txt', 'Hello WebDAV');
const content = await client.downloadText('/docs/hello.txt');
```

常用方法：
- `listDirectory(path?, depth?)`（PROPFIND，返回 XML 文本）
- `upload(path, content, contentType?)`
- `download(path)` / `downloadText(path)` / `downloadArrayBuffer(path)`
- `createDirectory(path)`（MKCOL）
- `remove(path)`（DELETE）
- `move(path, destination, overwrite?)`
- `copy(path, destination, overwrite?)`
- `getQuota()` / `listRecycle()` / `recoverRecycle(hash)` / `deleteRecycle(hash)` / `clearRecycle()`

## 本地验证

1. 构建 SDK：`npm run build`
2. 启动后端：`node examples/backend/node/server.js`
3. 启动前端：`python3 -m http.server 8001`，然后在浏览器输入访问地址：`http://localhost:8001/examples/frontend/dapp.html`
4. 确保安装 YeYing 钱包扩展插件
5. 点击：`Detect Provider` → `Connect Wallet` → `Login`

提示：如果前端来自其他域名，请设置
`COOKIE_SAMESITE=none` 且 `COOKIE_SECURE=true` 并使用 HTTPS，
以便 `refresh_token` Cookie 能随 `credentials: 'include'` 发送。

## 多后端联调（不同端口）

可同时启动多语言后端（不同端口），验证 UCAN 多后端授权：

```bash
./scripts/backend.sh start all
./scripts/backend.sh start all --setup
```

默认端口：
- Go `3201`
- Java `3202`
- Node `3203`
- Python `3204`

前端调用不同端口的后端时：
- 将前端 Origin 加入 `CORS_ORIGINS`（例如 `http://localhost:3203`）
- UCAN 调用的 `audience` 与后端 `UCAN_AUD` 一致（如 `did:web:localhost:3202`）

提示：`examples/frontend/dapp.html` 已内置多后端列表，可在一次 UCAN 授权后依次调用多个服务。

## 常见问题

### 刷新token失败

清理旧 Cookie 后重新登录：在浏览器 DevTools → Application → Cookies → http://localhost:8001 删除 refresh_token，再点 Login 后再点 Refresh Token。
