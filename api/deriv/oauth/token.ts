/**
 * Vercel serverless endpoint for Deriv's Authorization Code + PKCE exchange.
 * Never log or return authorization codes, PKCE verifiers, or access tokens.
 */
type ApiRequest = {
  method?: string;
  headers?: Record<string, string | string[] | undefined>;
  body?: unknown;
};
type ApiResponse = {
  status: (code: number) => ApiResponse;
  json: (body: unknown) => void;
  setHeader: (name: string, value: string) => void;
};

type OAuthErrorPayload = {
  error?: unknown;
  error_description?: unknown;
  message?: unknown;
};

const asHeader = (value: string | string[] | undefined): string =>
  Array.isArray(value) ? value[0] || '' : value || '';

const asText = (value: unknown): string | undefined =>
  typeof value === 'string' && value.trim() ? value.trim() : undefined;

function sendError(res: ApiResponse, status: number, error: string, description: string): void {
  res.status(status).json({ error, error_description: description });
}

export default async function handler(req: ApiRequest, res: ApiResponse): Promise<void> {
  res.setHeader('Cache-Control', 'no-store, max-age=0');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Content-Type', 'application/json; charset=utf-8');

  try {
    if (req.method !== 'POST') {
      res.setHeader('Allow', 'POST');
      sendError(res, 405, 'method_not_allowed', 'Use POST for the Deriv token exchange.');
      return;
    }

    const appId = process.env.NEXT_PUBLIC_DERIV_APP_ID?.trim();
    if (!appId) {
      sendError(res, 503, 'server_misconfigured', 'NEXT_PUBLIC_DERIV_APP_ID is missing from this Vercel project’s Production environment.');
      return;
    }

    let body: unknown = req.body;
    if (typeof body === 'string') {
      try {
        body = JSON.parse(body);
      } catch {
        sendError(res, 400, 'invalid_json', 'The token exchange request body is not valid JSON.');
        return;
      }
    }
    if (!body || typeof body !== 'object' || Array.isArray(body)) {
      sendError(res, 400, 'invalid_request', 'A JSON object with the OAuth callback parameters is required.');
      return;
    }

    const fields = body as Record<string, unknown>;
    const code = asText(fields.code);
    const clientId = asText(fields.client_id);
    const redirectUri = asText(fields.redirect_uri);
    const codeVerifier = asText(fields.code_verifier);

    if (!code || !clientId || !redirectUri || !codeVerifier ||
        code.length > 4096 || codeVerifier.length < 43 || codeVerifier.length > 128) {
      sendError(res, 400, 'invalid_request', 'Missing or invalid OAuth callback parameters. Start a fresh Deriv login.');
      return;
    }
    if (clientId !== appId) {
      sendError(res, 400, 'invalid_client', 'The OAuth client ID does not match the App ID configured on this Vercel project.');
      return;
    }

    let callback: URL;
    try {
      callback = new URL(redirectUri);
    } catch {
      sendError(res, 400, 'invalid_redirect_uri', 'The OAuth callback URL is invalid.');
      return;
    }

    const requestHost = asHeader(req.headers?.['x-forwarded-host']) || asHeader(req.headers?.host);
    const requestProto = asHeader(req.headers?.['x-forwarded-proto']) || 'https';
    const requestOrigin = requestHost ? `${requestProto}://${requestHost}` : '';
    const originHeader = asHeader(req.headers?.origin);
    const configuredRedirect = process.env.DERIV_OAUTH_REDIRECT_URI?.trim();
    let expectedRedirect = '';

    if (configuredRedirect) {
      try {
        const allowed = new URL(configuredRedirect);
        expectedRedirect = allowed.origin + allowed.pathname;
      } catch {
        sendError(res, 503, 'server_misconfigured', 'DERIV_OAUTH_REDIRECT_URI is not a valid URL in the Vercel environment.');
        return;
      }
    }

    const callbackPath = callback.origin + callback.pathname;
    const originMismatch = Boolean(originHeader && requestOrigin && originHeader !== requestOrigin);
    const redirectMismatch = configuredRedirect
      ? callbackPath !== expectedRedirect
      : Boolean(requestOrigin && callback.origin !== requestOrigin);
    const insecureRedirect = callback.protocol !== 'https:' &&
      callback.hostname !== 'localhost' && callback.hostname !== '127.0.0.1';

    if (originMismatch || redirectMismatch || insecureRedirect) {
      sendError(res, 400, 'redirect_uri_mismatch', 'The callback URL does not match the OAuth redirect URI allowed for this deployment.');
      return;
    }

    let tokenResponse: Response;
    try {
      tokenResponse = await fetch('https://auth.deriv.com/oauth2/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          client_id: appId,
          code,
          redirect_uri: redirectUri,
          code_verifier: codeVerifier,
        }).toString(),
        signal: AbortSignal.timeout(15000),
      });
    } catch (error) {
      const errorName = error instanceof Error ? error.name : 'UnknownError';
      console.error('[deriv-oauth-token] Deriv request failed', { errorName });
      sendError(res, 502, 'deriv_unavailable', 'The server could not reach Deriv authentication. Please start a fresh login and retry.');
      return;
    }

    const payload = await tokenResponse.json().catch(() => ({})) as OAuthErrorPayload & {
      access_token?: unknown;
      token_type?: unknown;
      expires_in?: unknown;
      scope?: unknown;
    };

    if (!tokenResponse.ok) {
      const providerError = asText(payload.error) || 'token_exchange_failed';
      const providerDescription = asText(payload.error_description) || asText(payload.message);
      console.error('[deriv-oauth-token] Deriv rejected token exchange', {
        status: tokenResponse.status,
        error: providerError,
      });
      sendError(
        res,
        tokenResponse.status >= 500 ? 502 : tokenResponse.status,
        providerError,
        providerDescription || 'Deriv rejected the authorization code. It may be expired, already used, or registered to a different redirect URI. Start a fresh login.'
      );
      return;
    }

    if (typeof payload.access_token !== 'string' || !payload.access_token ||
        !Number.isFinite(Number(payload.expires_in))) {
      console.error('[deriv-oauth-token] Deriv returned an incomplete token payload');
      sendError(res, 502, 'invalid_token_response', 'Deriv returned an incomplete access-token response.');
      return;
    }

    res.status(200).json({
      access_token: payload.access_token,
      token_type: asText(payload.token_type) || 'Bearer',
      expires_in: Number(payload.expires_in),
      scope: asText(payload.scope) || 'trade',
    });
  } catch (error) {
    // Catch unexpected handler errors so Vercel does not replace them with its
    // opaque "A server error has occurred" response.
    const errorName = error instanceof Error ? error.name : 'UnknownError';
    console.error('[deriv-oauth-token] Unexpected handler failure', { errorName });
    sendError(res, 500, 'oauth_handler_failed', 'The Deriv token service encountered an unexpected error. Check the Vercel function logs.');
  }
}
