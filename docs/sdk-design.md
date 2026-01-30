# SDK 能力与账户管理设计

## 1. SDK 能力概览

当前 SDK 面向浏览器环境，主要能力如下：

- Provider 发现与选择（EIP-6963 / EIP-1193）
- 账户/链/余额读取与事件监听
- SIWE 登录（challenge/verify/refresh/logout）
- UCAN 授权（Session / Root / Delegation / Invocation）
- WebDAV 存储能力（基于 UCAN token）
- Dapp 快速初始化（`initDappSession`）

## 2. 账户使用场景设计

### 2.1 使用“之前连接的账户”

钱包会记录“已授权账户”，Dapp 不需要每次都弹出授权弹窗。
在页面初始化阶段，可以先读取已授权账户（`eth_accounts`）：

```ts
import { getProvider, getPreferredAccount } from '@yeying-community/web3-bs';

const provider = await getProvider({ timeoutMs: 3000 });
const { account, accounts } = await getPreferredAccount({
  provider,
  autoConnect: false,
});

if (!account) {
  // 用户尚未授权，可提示点击“Connect Wallet”
}
```

### 2.2 首次连接或主动授权

当用户主动点击“Connect Wallet”，再触发授权弹窗：

```ts
const { account } = await getPreferredAccount({
  provider,
  autoConnect: true,
});
```

### 2.3 账户切换感知与更新

钱包账户发生变化时，需要更新 Dapp 的登录态与业务状态：

```ts
import { watchAccounts, clearAccessToken, clearUcanSession } from '@yeying-community/web3-bs';

const unsubscribe = watchAccounts(provider, ({ account, accounts }) => {
  // UI 刷新
  console.log('accountsChanged', account, accounts);

  // 登录态建议清理并重新走授权
  clearAccessToken({ storeToken: false });
  clearUcanSession();
  // 重新发起 SIWE / UCAN 登录流程
});

// 页面销毁时：unsubscribe();
```

## 3. 账户选择策略

SDK 提供“优先使用上次选择账户”的策略：

- `getPreferredAccount()` 会在本地缓存上次选择的账户
- 若该账户仍在 `eth_accounts` 返回列表中，则优先使用
- 否则回退到 `accounts[0]`

相关配置：

- `storageKey`：自定义本地缓存 key（默认 `yeying:last_account`）
- `preferStored`：是否优先使用缓存账户（默认 true）
- `autoConnect`：若未授权账户，是否自动发起授权请求

## 4. 设计要点

- “已授权账户”由钱包决定；Dapp 只读取 `eth_accounts`
- `eth_requestAccounts` 会触发用户授权弹窗，仅在用户主动操作时调用
- 账户切换后，应清理 SIWE token 与 UCAN Root，并重新登录

## 5. 新增 API

- `getPreferredAccount(options?) -> { account, accounts }`
- `watchAccounts(provider, handler, options?) -> unsubscribe`

建议与现有 API 一起使用：

- `getAccounts` / `requestAccounts`
- `onAccountsChanged`

