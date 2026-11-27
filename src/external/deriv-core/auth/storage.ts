import type { AuthInfo, DerivAccount, StoredCSRFToken, StoredCodeVerifier } from '../types';

const CSRF_TOKEN_KEY = 'oauth_csrf_token';
const CODE_VERIFIER_KEY = 'oauth_code_verifier';
const AUTH_INFO_KEY = 'auth_info';
const DERIV_ACCOUNTS_KEY = 'deriv_accounts';
const ACTIVE_LOGINID_KEY = 'active_loginid';
const ACCOUNT_TYPE_KEY = 'account_type';
const TOKEN_EXPIRY_SKEW_SECONDS = 60;
const TOKEN_MAX_AGE_MS = 10 * 60 * 1000;

export function storeCSRFToken(token: string): void {
  sessionStorage.setItem(CSRF_TOKEN_KEY, JSON.stringify({ value: token, createdAt: Date.now() }));
}

export function getCSRFToken(): string | null {
  const raw = sessionStorage.getItem(CSRF_TOKEN_KEY);
  if (!raw) return null;
  try {
    const stored: StoredCSRFToken = JSON.parse(raw);
    if (!stored.value || Date.now() - stored.createdAt > TOKEN_MAX_AGE_MS) {
      clearCSRFToken();
      return null;
    }
    return stored.value;
  } catch {
    clearCSRFToken();
    return null;
  }
}

export function clearCSRFToken(): void {
  sessionStorage.removeItem(CSRF_TOKEN_KEY);
}

export function storeCodeVerifier(verifier: string): void {
  sessionStorage.setItem(CODE_VERIFIER_KEY, JSON.stringify({ value: verifier, createdAt: Date.now() }));
}

export function getCodeVerifier(): string | null {
  const raw = sessionStorage.getItem(CODE_VERIFIER_KEY);
  if (!raw) return null;
  try {
    const stored: StoredCodeVerifier = JSON.parse(raw);
    if (!stored.value || Date.now() - stored.createdAt > TOKEN_MAX_AGE_MS) {
      clearCodeVerifier();
      return null;
    }
    return stored.value;
  } catch {
    clearCodeVerifier();
    return null;
  }
}

export function clearCodeVerifier(): void {
  sessionStorage.removeItem(CODE_VERIFIER_KEY);
}

export function storeAuthInfo(authInfo: AuthInfo): void {
  localStorage.setItem(AUTH_INFO_KEY, JSON.stringify(authInfo));
}

export function hasStoredAuthInfo(): boolean {
  return localStorage.getItem(AUTH_INFO_KEY) !== null;
}

export function getAuthInfo(): AuthInfo | null {
  const raw = localStorage.getItem(AUTH_INFO_KEY);
  if (!raw) return null;
  try {
    const authInfo: AuthInfo = JSON.parse(raw);
    if (!authInfo.access_token || !authInfo.expires_at ||
        Date.now() >= (authInfo.expires_at - TOKEN_EXPIRY_SKEW_SECONDS) * 1000) {
      clearAuthInfo();
      return null;
    }
    return authInfo;
  } catch {
    clearAuthInfo();
    return null;
  }
}

export function clearAuthInfo(): void {
  localStorage.removeItem(AUTH_INFO_KEY);
}

export function storeDerivAccounts(accounts: DerivAccount[]): void {
  localStorage.setItem(DERIV_ACCOUNTS_KEY, JSON.stringify(accounts));
}

export function getDerivAccounts(): DerivAccount[] | null {
  const raw = localStorage.getItem(DERIV_ACCOUNTS_KEY);
  if (!raw) return null;
  try {
    return JSON.parse(raw);
  } catch {
    clearDerivAccounts();
    return null;
  }
}

export function clearDerivAccounts(): void {
  localStorage.removeItem(DERIV_ACCOUNTS_KEY);
}

export function setActiveLoginId(loginId: string): void {
  localStorage.setItem(ACTIVE_LOGINID_KEY, loginId);
}

export function getActiveLoginId(): string | null {
  return localStorage.getItem(ACTIVE_LOGINID_KEY);
}

export function setAccountType(type: 'demo' | 'real'): void {
  localStorage.setItem(ACCOUNT_TYPE_KEY, type);
}

export function getAccountType(): string | null {
  return localStorage.getItem(ACCOUNT_TYPE_KEY);
}

export function clearAllAuthData(): void {
  clearCSRFToken();
  clearCodeVerifier();
  clearAuthInfo();
  clearDerivAccounts();
  localStorage.removeItem(ACTIVE_LOGINID_KEY);
  localStorage.removeItem(ACCOUNT_TYPE_KEY);
  sessionStorage.removeItem(DERIV_ACCOUNTS_KEY);
}
