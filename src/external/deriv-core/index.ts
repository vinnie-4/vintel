// Vendored subset of @deriv/core. OAuth Authorization Code + PKCE is used;
// the one-time code exchange runs through the same-origin serverless endpoint.
export {
  buildAuthorizationUrl, buildSignUpUrl, initiateLogin, initiateSignUp,
  parseCallbackParams, validateCallback, exchangeCodeForTokens, handleOAuthCallback,
  cleanupUrl, refreshAccessToken, OAuthError, fetchAccounts, getWebSocketOTP, logout,
  generateRandomBase64url, sha256Base64url, base64urlEncode,
  storeCSRFToken, getCSRFToken, clearCSRFToken, storeCodeVerifier, getCodeVerifier,
  clearCodeVerifier, storeAuthInfo, getAuthInfo, hasStoredAuthInfo, clearAuthInfo,
  storeDerivAccounts, getDerivAccounts, clearDerivAccounts, setActiveLoginId,
  getActiveLoginId, setAccountType, getAccountType, clearAllAuthData,
  parseReferralLink, parseLandingParams, resolveReferralViaProxy,
} from './auth';
export type {
  AuthConfig, AuthInfo, DerivAccount, OTPResponse, TokenExchangeParams, CallbackParams,
  AuthState, StoredCSRFToken, StoredCodeVerifier, ActiveSymbol, Tick, TicksHistoryResponse,
  ContractsForResponse, ContractInfo, DurationLimits, ProposalResponse, ProposalInfo,
  BuyResponse, BuyResult, ProposalParams,
} from './types';
export { getAuthBaseUrl, getApiBaseUrl, getPublicWsUrl } from './config';
