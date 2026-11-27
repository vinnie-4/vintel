import { lazy, Suspense, useEffect, useState } from 'react';
import React from 'react';
import { createBrowserRouter, createRoutesFromElements, Route, RouterProvider } from 'react-router';
import { cleanupUrl, clearAllAuthData, getAuthInfo, handleOAuthCallback } from '@/external/deriv-core';
import ChunkLoader from '@/components/loader/chunk-loader';
import LocalStorageSyncWrapper from '@/components/localStorage-sync-wrapper';
import RoutePromptDialog from '@/components/route-prompt-dialog';
import { useAccountSwitching } from '@/hooks/useAccountSwitching';
import { useInvalidTokenHandler } from '@/hooks/useInvalidTokenHandler';
import { useLanguageFromURL } from '@/hooks/useLanguageFromURL';
import { StoreProvider } from '@/hooks/useStore';
import { isPreviewMode, PREVIEW_BASE_PATH } from '@/utils/is-preview-mode';
import { localize, TranslationProvider } from '@deriv-com/translations';
import { DerivWSAccountsService } from '@/services/derivws-accounts.service';
import { DERIV_OAUTH_REDIRECT_URI, generateOAuthURL } from '@/components/shared';
import CoreStoreProvider from './CoreStoreProvider';
import i18nInstance from './i18n';
import './app-root.scss';

const Layout = lazy(() => import('../components/layout'));
const AppRoot = lazy(() => import('./app-root'));

const LanguageHandler = ({ children }: { children: React.ReactNode }) => {
  useLanguageFromURL();
  return <>{children}</>;
};

const routerBasename = isPreviewMode() ? PREVIEW_BASE_PATH : undefined;
let loginRedirectInProgress = false;
const router = createBrowserRouter(
  createRoutesFromElements(
    <Route path='/' element={
      <Suspense fallback={<ChunkLoader message={localize('Please wait while we connect to the server...')} />}>
        <TranslationProvider defaultLang='EN' i18nInstance={i18nInstance}>
          <LanguageHandler>
            <StoreProvider>
              <LocalStorageSyncWrapper>
                <RoutePromptDialog />
                <CoreStoreProvider><Layout /></CoreStoreProvider>
              </LocalStorageSyncWrapper>
            </StoreProvider>
          </LanguageHandler>
        </TranslationProvider>
      </Suspense>
    }>
      <Route index element={<AppRoot />} />
      <Route path='preview' element={<AppRoot />} />
    </Route>
  ),
  { basename: routerBasename }
);

function App() {
  const [authError, setAuthError] = useState('');
  const [isRetrying, setIsRetrying] = useState(false);
  useAccountSwitching();
  useInvalidTokenHandler();

  useEffect(() => {
    const showAuthError = (event: Event) => {
      const detail = (event as CustomEvent<{ message?: string }>).detail;
      setAuthError(detail?.message || 'Deriv authentication failed. Please try again.');
    };
    const handleExpiredSession = () => {
      void restartLogin('Your Deriv session expired. Please sign in again.');
    };
    window.addEventListener('vintel:auth-error', showAuthError);
    window.addEventListener('vintel:auth-expired', handleExpiredSession);

    const params = new URLSearchParams(window.location.search);
    const isOAuthCallback = params.has('code') || params.has('error');

    const restartIfExpired = async () => {
      if (isOAuthCallback || !localStorage.getItem('active_loginid') || getAuthInfo()) return;
      await restartLogin('Your Deriv session expired. Please sign in again.');
    };

    const handleCallback = async () => {
      try {
        const clientId = process.env.NEXT_PUBLIC_DERIV_APP_ID?.trim();
        if (!clientId) throw new Error('Deriv registered App ID is missing. Configure NEXT_PUBLIC_DERIV_APP_ID in the deployment environment.');

        const authInfo = await handleOAuthCallback(window.location.href, {
          clientId,
          redirectUri: DERIV_OAUTH_REDIRECT_URI,
          scopes: 'trade',
        });

        DerivWSAccountsService.clearStoredAccounts();
        DerivWSAccountsService.clearCache();
        const accounts = await DerivWSAccountsService.fetchAccountsList(authInfo.access_token);
        const activeAccounts = accounts.filter(account => !account.status || account.status === 'active');
        if (!activeAccounts.length) throw new Error('Deriv login succeeded, but no active trading accounts were returned.');

        DerivWSAccountsService.storeAccounts(activeAccounts);
        const selected = activeAccounts[0];
        localStorage.setItem('active_loginid', selected.account_id);
        localStorage.setItem('account_type', selected.account_type);
        const { api_base } = await import('@/external/bot-skeleton');
        await api_base.init(true);
        setAuthError('');
      } catch (error) {
        clearAllAuthData();
        localStorage.removeItem('active_loginid');
        localStorage.removeItem('account_type');
        DerivWSAccountsService.clearStoredAccounts();
        DerivWSAccountsService.clearCache();
        cleanupUrl(window.location.origin);
        const message = error instanceof Error ? error.message : 'Unable to complete Deriv login.';
        setAuthError(message);
      }
    };

    function restartLogin(message: string) {
      if (loginRedirectInProgress) return;
      loginRedirectInProgress = true;
      setIsRetrying(true);
      setAuthError(message);
      void (async () => {
        try {
          clearAllAuthData();
          localStorage.removeItem('active_loginid');
          localStorage.removeItem('account_type');
          DerivWSAccountsService.clearStoredAccounts();
          DerivWSAccountsService.clearCache();
          const url = await generateOAuthURL();
          window.location.replace(url);
        } catch (error) {
          loginRedirectInProgress = false;
          setIsRetrying(false);
          setAuthError(error instanceof Error ? error.message : message);
        }
      })();
    }

    if (isOAuthCallback) void handleCallback();
    else void restartIfExpired();

    return () => {
      window.removeEventListener('vintel:auth-error', showAuthError);
      window.removeEventListener('vintel:auth-expired', handleExpiredSession);
    };
  }, []);

  const retryLogin = async () => {
    if (loginRedirectInProgress) return;
    loginRedirectInProgress = true;
    setIsRetrying(true);
    try {
      const url = await generateOAuthURL();
      window.location.assign(url);
    } catch (error) {
      loginRedirectInProgress = false;
      setIsRetrying(false);
      setAuthError(error instanceof Error ? error.message : 'Could not start Deriv login.');
    }
  };

  return (
    <>
      {authError && (
        <div role='alert' aria-live='assertive' style={{ position: 'fixed', zIndex: 10000, top: 12, left: 12, right: 12, padding: 12, background: 'var(--general-section-1, #fff)', color: 'var(--text-general, #222)', border: '1px solid var(--border-normal, #ccc)', borderRadius: 8 }}>
          <div>{authError}</div>
          <button type='button' onClick={retryLogin} disabled={isRetrying} style={{ marginTop: 8 }}>
            {isRetrying ? 'Connecting to Deriv…' : 'Retry Deriv login'}
          </button>
        </div>
      )}
      <RouterProvider router={router} />
    </>
  );
}

export default App;
