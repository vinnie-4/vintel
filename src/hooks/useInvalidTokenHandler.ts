import { useCallback, useEffect } from 'react';
import { clearAllAuthData } from '@/external/deriv-core';
import { observer as globalObserver } from '@/external/bot-skeleton/utils/observer';
import { DerivWSAccountsService } from '@/services/derivws-accounts.service';
import { ErrorLogger } from '@/utils/error-logger';
import { replaceUrl } from '@/utils/navigation-utils';
import { generateOAuthURL } from '@/components/shared';

let recoveryInProgress = false;

export const useInvalidTokenHandler = (): { unregisterHandler: () => void } => {
  const handleInvalidToken = useCallback(async () => {
    if (recoveryInProgress) return;
    recoveryInProgress = true;
    try {
      clearAllAuthData();
      localStorage.removeItem('active_loginid');
      localStorage.removeItem('account_type');
      localStorage.removeItem('accountsList');
      localStorage.removeItem('authToken');
      localStorage.removeItem('clientAccounts');
      DerivWSAccountsService.clearStoredAccounts();
      DerivWSAccountsService.clearCache();

      const oauthUrl = await generateOAuthURL();
      if (!oauthUrl) throw new Error('Deriv App ID is not configured for this deployment.');
      replaceUrl(oauthUrl);
    } catch (error) {
      recoveryInProgress = false;
      ErrorLogger.error('InvalidToken', 'Could not restart Deriv OAuth login', error);
      window.dispatchEvent(new CustomEvent('vintel:auth-error', {
        detail: { message: error instanceof Error ? error.message : 'Authentication recovery failed.' },
      }));
    }
  }, []);

  useEffect(() => {
    globalObserver.register('InvalidToken', handleInvalidToken);
    return () => globalObserver.unregister('InvalidToken', handleInvalidToken);
  }, [handleInvalidToken]);

  return { unregisterHandler: () => globalObserver.unregister('InvalidToken', handleInvalidToken) };
};

export default useInvalidTokenHandler;
