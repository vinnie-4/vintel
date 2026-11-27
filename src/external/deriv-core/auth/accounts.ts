import type { AuthInfo, DerivAccount } from '../types';
import { setActiveLoginId, setAccountType, clearAllAuthData } from './storage';
import { DerivWSAccountsService } from '@/services/derivws-accounts.service';

/** Compatibility wrapper; all account REST calls are owned by DerivWSAccountsService. */
export async function fetchAccounts(authInfo: AuthInfo, _clientId?: string): Promise<DerivAccount[]> {
  const accounts = await DerivWSAccountsService.fetchAccountsList(authInfo.access_token);
  if (accounts.length) {
    setActiveLoginId(accounts[0].account_id);
    setAccountType(accounts[0].account_type);
  }
  return accounts;
}

/** Compatibility wrapper; all OTP calls are owned by DerivWSAccountsService. */
export function getWebSocketOTP(accountId: string, authInfo: AuthInfo, _clientId?: string): Promise<string> {
  return DerivWSAccountsService.fetchOTPWebSocketURL(authInfo.access_token, accountId);
}

export function logout(): void {
  DerivWSAccountsService.clearStoredAccounts();
  DerivWSAccountsService.clearCache();
  clearAllAuthData();
}
