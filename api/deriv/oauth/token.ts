/**
 * Vercel serverless endpoint for Deriv's Authorization Code + PKCE exchange.
 * The browser never sends the authorization code directly to Deriv's token
 * endpoint. No client secret is needed for the PKCE public-client flow.
 */
type ApiRequest = {
  method?: string;
  headers: Record<string, string | string[] | undefined>;
  body?: unknown;
};
type ApiResponse = {
  status: (code: number) => ApiResponse;
  json: (body: unknown) => void;
  setHeader: (name: string, value: string) => void;
};

export default async function handler(req: ApiRequest, res: ApiResponse): Promise<void> {
  res.setHeader('Cache-Control', 'no-store, max-age=0');
  res.setHeader('X-Content-Type-Options', 'nosniff');

  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    res.status(405).json({ error: 'method_not_allowed' });
    return;
  }

  const appId = process.env.NEXT_PUBLIC_DERIV_APP_ID?.trim();
  if (!appId) {
    res.status(503).json({ error: 'server_misconfigured', error_description: 'Deriv registered App ID is not configured.' });
    return;
  }

  let body: unknown;
  try {
    body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
  } catch {
    res.status(400).json({ error: 'invalid_json' });
    return;
  }
  const { code, client_id: clientId, redirect_uri: redirectUri, code_verifier: codeVerifier } =
    (body || {}) as Record<string, string>;

  if (!code || !clientId || !redirectUri || !codeVerifier ||
      code.length > 4096 || codeVerifier.length < 43 || codeVerifier.length > 128) {
    res.status(400).json({ error: 'invalid_request', error_description: 'Missing or invalid OAuth callback parameters.' });
    return;
  }
  if (clientId !== appId) {
    res.status(400).json({ error: 'invalid_client', error_description: 'The OAuth client ID does not match this deployment.' });
    return;
  }

  let callback: URL;
  try {
    callback = new URL(redirectUri);
  } catch {
    res.status(400).json({ error: 'invalid_redirect_uri' });
    return;
  }

  const forwardedHost = req.headers['x-forwarded-host'] || req.headers.host || '';
  const forwardedProto = req.headers['x-forwarded-proto'] || 'https';
  const requestOrigin = `${Array.isArray(forwardedProto) ? forwardedProto[0] : forwardedProto}://${Array.isArray(forwardedHost) ? forwardedHost[0] : forwardedHost}`;
  const configuredRedirect = process.env.DERIV_OAUTH_REDIRECT_URI?.trim();
  const expectedRedirect = configuredRedirect
    ? (() => {
        try {
          const allowed = new URL(configuredRedirect);
          return allowed.origin + allowed.pathname;
        } catch {
          return '';
        }
      })()
    : '';

  const requestOriginHeader = req.headers.origin;
  const requestOriginValue = Array.isArray(requestOriginHeader) ? requestOriginHeader[0] : requestOriginHeader;
  if ((requestOriginValue && requestOriginValue !== requestOrigin) ||
      (configuredRedirect && callback.origin + callback.pathname !== expectedRedirect) ||
      (!configuredRedirect && callback.origin !== requestOrigin) ||
      (callback.protocol !== 'https:' && callback.hostname !== 'localhost' && callback.hostname !== '127.0.0.1')) {
    res.status(400).json({ error: 'redirect_uri_mismatch', error_description: 'The callback URL is not allowed for this deployment.' });
    return;
  }

  try {
    const tokenResponse = await fetch('https://auth.deriv.com/oauth2/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        client_id: appId,
        code,
        redirect_uri: redirectUri,
        code_verifier: codeVerifier,
      }).toString(),
    });

    const payload = await tokenResponse.json().catch(() => ({}));
    if (!tokenResponse.ok) {
      res.status(tokenResponse.status >= 500 ? 502 : tokenResponse.status).json({
        error: payload.error || 'token_exchange_failed',
        error_description: payload.error_description || 'Deriv could not exchange this authorization code. Start login again.',
      });
      return;
    }
    if (!payload.access_token || !Number.isFinite(Number(payload.expires_in))) {
      res.status(502).json({ error: 'invalid_token_response', error_description: 'Deriv returned an incomplete token response.' });
      return;
    }

    // Return only the short-lived access token metadata. Deriv does not issue
    // refresh tokens to third-party OAuth apps.
    res.status(200).json({
      access_token: payload.access_token,
      token_type: payload.token_type || 'Bearer',
      expires_in: Number(payload.expires_in),
      scope: payload.scope || 'trade',
    });
  } catch {
    res.status(502).json({ error: 'deriv_unavailable', error_description: 'Could not reach Deriv authentication. Please retry.' });
  }
}
