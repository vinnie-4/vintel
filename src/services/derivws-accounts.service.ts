import { getApiBaseUrl } from '@/external/deriv-core/config/urls';
import { storeDerivAccounts, clearDerivAccounts } from '@/external/deriv-core/auth/storage';

export interface DerivAccount {
  account_id: string;
  balance: string;
  currency: string;
  group: string;
  status: string;
  account_type: 'demo' | 'real';
}
interface AccountsResponse { data?: DerivAccount[]; }
interface OTPResponse { data?: { url?: string }; }

const notifyExpiredToken = (status: number) => {
  if (status === 401) window.dispatchEvent(new CustomEvent('vintel:auth-expired'));
};

/** The single account/OTP implementation shared by OAuth and WebSocket flows. */
export class DerivWSAccountsService {
  private static accountsFetchPromise: Promise<DerivAccount[]> | null = null;
  private static otpFetchPromises = new Map<string, Promise<string>>();

  static clearCache(): void {
    this.accountsFetchPromise = null;
    this.otpFetchPromises.clear();
  }

  static storeAccounts(accounts: DerivAccount[]): void {
    sessionStorage.setItem('deriv_accounts', JSON.stringify(accounts));
    storeDerivAccounts(accounts);
  }

  static getStoredAccounts(): DerivAccount[] | null {
    try {
      const raw = sessionStorage.getItem('deriv_accounts') || localStorage.getItem('deriv_accounts');
      if (!raw) return null;
      const accounts = JSON.parse(raw);
      return Array.isArray(accounts) ? accounts : null;
    } catch {
      this.clearStoredAccounts();
      return null;
    }
  }

  static getDefaultAccount(): DerivAccount | null {
    return this.getStoredAccounts()?.[0] || null;
  }

  static clearStoredAccounts(): void {
    sessionStorage.removeItem('deriv_accounts');
    clearDerivAccounts();
  }

  static async fetchAccountsList(accessToken: string): Promise<DerivAccount[]> {
    if (this.accountsFetchPromise) return this.accountsFetchPromise;
    this.accountsFetchPromise = (async () => {
      try {
        const response = await fetch(`${getApiBaseUrl()}/accounts`, {
          headers: { Authorization: `Bearer ${accessToken}`, Accept: 'application/json' },
        });
        if (!response.ok) {
          notifyExpiredToken(response.status);
          throw new Error(`Deriv accounts request failed (${response.status} ${response.statusText}).`);
        }
        const payload: AccountsResponse = await response.json();
        const accounts = Array.isArray(payload.data) ? payload.data : [];
        this.storeAccounts(accounts);
        return accounts;
      } catch (error) {
        this.accountsFetchPromise = null;
        throw error;
      } finally {
        this.accountsFetchPromise = null;
      }
    })();
    return this.accountsFetchPromise;
  }

  static async fetchOTPWebSocketURL(accessToken: string, accountId: string): Promise<string> {
    const cacheKey = accountId;
    const existing = this.otpFetchPromises.get(cacheKey);
    if (existing) return existing;

    const request = (async () => {
      const response = await fetch(`${getApiBaseUrl()}/accounts/${encodeURIComponent(accountId)}/otp`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${accessToken}`, Accept: 'application/json' },
      });
      if (!response.ok) {
        notifyExpiredToken(response.status);
        throw new Error(`Deriv WebSocket OTP request failed (${response.status} ${response.statusText}).`);
      }
      const payload: OTPResponse = await response.json();
      if (!payload.data?.url) throw new Error('Deriv returned an empty WebSocket OTP URL.');
      return payload.data.url;
    })();

    this.otpFetchPromises.set(cacheKey, request);
    try {
      return await request;
    } finally {
      this.otpFetchPromises.delete(cacheKey);
    }
  }

  static async getAuthenticatedWebSocketURL(accessToken: string): Promise<string> {
    let accounts = this.getStoredAccounts();
    if (!accounts?.length) accounts = await this.fetchAccountsList(accessToken);
    const activeLoginId = localStorage.getItem('active_loginid');
    const selected = (activeLoginId && accounts.find(account => account.account_id === activeLoginId)) || accounts[0];
    if (!selected) throw new Error('No active Deriv trading account is available.');
    return this.fetchOTPWebSocketURL(accessToken, selected.account_id);
  }
}
