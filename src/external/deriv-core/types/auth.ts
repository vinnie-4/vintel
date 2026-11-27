export interface AuthConfig {
  clientId: string;
  redirectUri: string;
  /** OAuth scopes as a space-separated string. Defaults to 'trade'. */
  scopes?: string;
  affiliateToken?: string;
  affiliateTokenParam?: 't' | 'affiliate_token' | 'sidi' | 'ca';
  utmCampaign?: string;
  utmSource?: string;
  utmMedium?: string;
  lang?: string;
}

export interface AuthInfo {
  access_token: string;
  token_type: string;
  expires_in: number;
  expires_at: number;
  scope: string;
}

export interface DerivAccount {
  account_id: string;
  account_type: 'demo' | 'real';
  currency: string;
  balance: string;
  group: string;
  status: string;
}

export interface OTPResponse {
  data: { url: string };
}

export interface TokenExchangeParams {
  code: string;
  clientId: string;
  redirectUri: string;
  codeVerifier: string;
}

export interface CallbackParams {
  code?: string | null;
  state?: string | null;
  scope?: string | null;
  error?: string | null;
  error_description?: string | null;
}

export type AuthState = 'unauthenticated' | 'authenticating' | 'authenticated' | 'error';

export interface StoredCSRFToken {
  value: string;
  createdAt: number;
}

export interface StoredCodeVerifier {
  value: string;
  createdAt: number;
}
