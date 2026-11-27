import type { AuthConfig, AuthInfo, CallbackParams, TokenExchangeParams } from '../types';
import { generateRandomBase64url, sha256Base64url } from './crypto';
import {
  storeCSRFToken,
  getCSRFToken,
  clearCSRFToken,
  storeCodeVerifier,
  getCodeVerifier,
  clearCodeVerifier,
  storeAuthInfo,
  clearAllAuthData,
} from './storage';
import { getAuthBaseUrl } from '../config/urls';

async function buildPkceParams(config: AuthConfig): Promise<URLSearchParams> {
  const csrfToken = generateRandomBase64url(32);
  const codeVerifier = generateRandomBase64url(32);
  const codeChallenge = await sha256Base64url(codeVerifier);

  storeCSRFToken(csrfToken);
  storeCodeVerifier(codeVerifier);

  return new URLSearchParams({
    scope: config.scopes ?? 'trade',
    response_type: 'code',
    client_id: config.clientId,
    redirect_uri: config.redirectUri,
    state: csrfToken,
    code_challenge: codeChallenge,
    code_challenge_method: 'S256',
  });
}

function appendAttributionParams(params: URLSearchParams, config: AuthConfig): void {
  if (config.affiliateToken) params.set(config.affiliateTokenParam ?? 't', config.affiliateToken);
  if (config.utmSource) params.set('utm_source', config.utmSource);
  if (config.utmMedium) params.set('utm_medium', config.utmMedium);
  if (config.utmCampaign) params.set('utm_campaign', config.utmCampaign);
  if (config.lang) params.set('lang', config.lang.toUpperCase());
}

export async function buildAuthorizationUrl(config: AuthConfig): Promise<string> {
  const params = await buildPkceParams(config);
  appendAttributionParams(params, config);
  return `${getAuthBaseUrl()}/auth?${params.toString()}`;
}

export async function buildSignUpUrl(config: AuthConfig): Promise<string> {
  const params = await buildPkceParams(config);
  params.set('prompt', 'registration');
  appendAttributionParams(params, config);
  return `${getAuthBaseUrl()}/auth?${params.toString()}`;
}

export async function initiateLogin(config: AuthConfig): Promise<void> {
  window.location.assign(await buildAuthorizationUrl(config));
}

export async function initiateSignUp(config: AuthConfig): Promise<void> {
  window.location.assign(await buildSignUpUrl(config));
}

export function parseCallbackParams(url: string): CallbackParams {
  const urlObj = new URL(url);
  return {
    code: urlObj.searchParams.get('code'),
    state: urlObj.searchParams.get('state'),
    scope: urlObj.searchParams.get('scope'),
    error: urlObj.searchParams.get('error'),
    error_description: urlObj.searchParams.get('error_description'),
  };
}

export function validateCallback(params: CallbackParams, redirectUri: string): string {
  if (params.error) {
    clearAllAuthData();
    cleanupUrl(redirectUri);
    throw new OAuthError(`Deriv authorization failed: ${params.error_description || params.error}`);
  }

  if (!params.state) {
    clearAllAuthData();
    cleanupUrl(redirectUri);
    throw new OAuthError('The Deriv login response did not include a state value. Please try again.');
  }

  const storedToken = getCSRFToken();
  if (!storedToken || storedToken !== params.state) {
    clearAllAuthData();
    cleanupUrl(redirectUri);
    throw new OAuthError('The Deriv login session could not be verified. Please start login again.');
  }

  if (!params.code) {
    clearAllAuthData();
    cleanupUrl(redirectUri);
    throw new OAuthError('The Deriv login response did not include an authorization code.');
  }

  clearCSRFToken();
  return params.code;
}

/**
 * Exchanges the one-time authorization code through the same-origin backend.
 * Deriv's current OAuth guidance requires the token exchange to happen server-side.
 */
export async function exchangeCodeForTokens(params: TokenExchangeParams): Promise<AuthInfo> {
  const response = await fetch('/api/deriv/oauth/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    credentials: 'same-origin',
    body: JSON.stringify({
      code: params.code,
      client_id: params.clientId,
      redirect_uri: params.redirectUri,
      code_verifier: params.codeVerifier,
    }),
  });

  const tokenData = await response.json().catch(() => ({}));
  if (!response.ok) {
    const detail = tokenData.error_description || tokenData.error || `HTTP ${response.status}`;
    throw new OAuthError(`Deriv token exchange failed: ${detail}`);
  }

  if (!tokenData.access_token || !Number.isFinite(Number(tokenData.expires_in))) {
    throw new OAuthError('Deriv returned an incomplete access-token response.');
  }

  const expiresIn = Number(tokenData.expires_in);
  const authInfo: AuthInfo = {
    access_token: tokenData.access_token,
    token_type: tokenData.token_type || 'Bearer',
    expires_in: expiresIn,
    expires_at: Math.floor(Date.now() / 1000) + expiresIn,
    scope: tokenData.scope || 'trade',
  };

  storeAuthInfo(authInfo);
  clearCodeVerifier();
  return authInfo;
}

/**
 * Deriv does not issue refresh tokens to third-party OAuth apps.
 * When this access token expires, the user must authorize again.
 */
export async function handleOAuthCallback(callbackUrl: string, config: AuthConfig): Promise<AuthInfo> {
  const params = parseCallbackParams(callbackUrl);
  const code = validateCallback(params, config.redirectUri);
  const codeVerifier = getCodeVerifier();

  if (!codeVerifier) {
    clearAllAuthData();
    cleanupUrl(config.redirectUri);
    throw new OAuthError('The secure login session expired. Please start login again.');
  }

  const authInfo = await exchangeCodeForTokens({
    code,
    clientId: config.clientId,
    redirectUri: config.redirectUri,
    codeVerifier,
  });

  cleanupUrl(config.redirectUri);
  return authInfo;
}

export function cleanupUrl(baseUrl: string): void {
  if (typeof window === 'undefined') return;
  const url = new URL(window.location.href);
  ['code', 'state', 'scope', 'error', 'error_description'].forEach(param => url.searchParams.delete(param));
  window.history.replaceState(window.history.state, '', url.pathname + url.search);
}

export class OAuthError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'OAuthError';
  }
}
