import {
  buildAuthorizationUrl, buildSignUpUrl, getAuthInfo, parseReferralLink,
  parseLandingParams, resolveReferralViaProxy,
} from '@/external/deriv-core';
import type { AuthConfig } from '@/external/deriv-core';
import { getInitialLanguage } from '@deriv-com/translations';
import { DerivWSAccountsService } from '@/services/derivws-accounts.service';
import brandConfig from '../../../../../brand.config.json';

// Deriv OAuth requires this exact URL to be registered on the OAuth application.
export const DERIV_OAUTH_REDIRECT_URI = 'https://www.optafx.site';

export const PRODUCTION_DOMAINS = { COM: brandConfig.platform.hostname.production.com } as const;
export const STAGING_DOMAINS = { COM: brandConfig.platform.hostname.staging.com } as const;
export const WS_SERVERS = {
  STAGING: `${brandConfig.platform.derivws.url.staging}options/ws/public`,
  PRODUCTION: `${brandConfig.platform.derivws.url.production}options/ws/public`,
} as const;

export const isProduction = () => {
  const env = process.env.NEXT_PUBLIC_DERIV_ENV;
  if (env === 'production') return true;
  if (env === 'preview' || env === 'staging') return false;
  return Object.values(PRODUCTION_DOMAINS).includes(window.location.hostname);
};
export const isLocal = () => /localhost(:\d+)?$/i.test(window.location.hostname);
const getDefaultServerURL = () => isProduction() ? WS_SERVERS.PRODUCTION : WS_SERVERS.STAGING;

/** Never silently downgrade an existing authenticated session to the public socket. */
export const getSocketURL = async (): Promise<string> => {
  const authInfo = getAuthInfo();
  if (!authInfo?.access_token) {
    if (localStorage.getItem('active_loginid')) {
      window.dispatchEvent(new CustomEvent('vintel:auth-expired'));
      throw new Error('Your Deriv session expired. Please sign in again.');
    }
    return getDefaultServerURL();
  }
  try {
    return await DerivWSAccountsService.getAuthenticatedWebSocketURL(authInfo.access_token);
  } catch (error) {
    if (error instanceof Error && /401|unauthorized|invalid token/i.test(error.message)) {
      window.dispatchEvent(new CustomEvent('vintel:auth-expired'));
    }
    throw error;
  }
};

export const getDebugServiceWorker = () => {
  const flag = window.localStorage.getItem('debug_service_worker');
  return flag ? !!parseInt(flag) : false;
};

export const generateOAuthURL = async (prompt?: string): Promise<string> => {
  const clientId = process.env.NEXT_PUBLIC_DERIV_APP_ID?.trim();
  if (!clientId) throw new Error('Deriv registered App ID is missing. Set NEXT_PUBLIC_DERIV_APP_ID in the deployment environment.');
  const config: AuthConfig = {
    clientId, redirectUri: DERIV_OAUTH_REDIRECT_URI, scopes: 'trade', lang: getInitialLanguage(),
  };
  const referralLink = process.env.NEXT_PUBLIC_DERIV_REFERRAL_LINK;
  if (referralLink) {
    const referral = parseReferralLink(referralLink);
    if (referral) {
      config.affiliateToken = referral.affiliateToken;
      config.affiliateTokenParam = referral.affiliateTokenParam;
      config.utmCampaign = referral.utmCampaign;
      if (referral.utmSource) config.utmSource = referral.utmSource;
      if (referral.utmMedium) config.utmMedium = referral.utmMedium;
    }
  }
  const landing = parseLandingParams();
  if (landing) {
    if (landing.affiliateToken) {
      config.affiliateToken = landing.affiliateToken;
      config.affiliateTokenParam = landing.affiliateTokenParam;
    }
    if (landing.utmSource) config.utmSource = landing.utmSource;
    if (landing.utmMedium) config.utmMedium = landing.utmMedium;
    if (landing.utmCampaign) config.utmCampaign = landing.utmCampaign;
  }
  if (!config.affiliateToken && referralLink) {
    const resolved = await resolveReferralViaProxy(referralLink);
    if (resolved) {
      config.affiliateToken = resolved.affiliateToken;
      config.affiliateTokenParam = resolved.affiliateTokenParam;
      if (resolved.utmSource) config.utmSource = resolved.utmSource;
      if (resolved.utmMedium) config.utmMedium = resolved.utmMedium;
      if (resolved.utmCampaign) config.utmCampaign = resolved.utmCampaign;
    }
  }
  return prompt === 'registration' ? buildSignUpUrl(config) : buildAuthorizationUrl(config);
};
