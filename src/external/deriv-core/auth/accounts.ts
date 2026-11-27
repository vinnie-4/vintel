import type { AuthInfo, DerivAccount, OTPResponse } from '../types';
import { storeDerivAccounts, setActiveLoginId, setAccountType, clearAllAuthData } from './storage';
import { getApiBaseUrl } from '../config/urls';

/** Legacy compatibility wrapper. New application code uses DerivWSAccountsService. */
export async function fetchAccounts(authInfo: AuthInfo, _clientId?: string): Promise<DerivAccount[]> {
  const response = await fetch(`${getApiBaseUrl()}/accounts`, {
    headers: { Authorization: `Bearer ${authInfo.access_token}`, Accept: 'application/json' },
  });
  if (!response.ok) throw new Error(`Failed to fetch Deriv accounts (${response.status})`);
  const payload = await response.json();
  const accounts: DerivAccount[] = Array.isArray(payload.data) ? payload.data : [];
  storeDerivAccounts(accounts);
  if (accounts.length) {
    setActiveLoginId(accounts[0].account_id);
    setAccountType(accounts[0].account_type);
  }
  return accounts;
}

/** Legacy compatibility wrapper. New application code uses DerivWSAccountsService. */
export async function getWebSocketOTP(accountId: string, authInfo: AuthInfo, _clientId?: string): Promise<string> {
  const response = await fetch(`${getApiBaseUrl()}/accounts/${encodeURIComponent(accountId)}/otp`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${authInfo.access_token}`, Accept: 'application/json' },
  });
  if (!response.ok) throw new Error(`Failed to get Deriv WebSocket OTP (${response.status})`);
  const payload: OTPResponse = await response.json();
  if (!payload.data?.url) throw new Error('Deriv returned an empty WebSocket OTP URL.');
  return payload.data.url;
}

export function logout(): void { clearAllAuthData(); }
