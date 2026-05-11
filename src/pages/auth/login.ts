import {
  buildAuthorizeUrl,
  createCodeChallenge,
  createCodeVerifier,
  createPendingAuthCookieValue,
  isPendingAuthFresh,
  getCookieDomain,
  getCookieOptions,
  KEYCLOAK_AUTH_COOKIE,
  normalizeReturnTo,
  readPendingAuthCookieValue,
} from '../../lib/keycloak-server';

export const prerender = false;

export const GET = async ({ cookies, url }: any) => {
  const returnTo = normalizeReturnTo(url.searchParams.get('returnTo'));
  const existingPending = await readPendingAuthCookieValue(cookies.get(KEYCLOAK_AUTH_COOKIE)?.value);
  const pending = existingPending && isPendingAuthFresh(existingPending)
    ? existingPending
    : {
        state: crypto.randomUUID(),
        verifier: createCodeVerifier(),
        returnTo,
        createdAt: Date.now(),
      };

  const challenge = await createCodeChallenge(pending.verifier);
  const redirectUri = new URL('/auth/callback', url.origin).toString();
  const authorizeUrl = buildAuthorizeUrl({
    redirectUri,
    state: pending.state,
    codeChallenge: challenge,
  });

  const cookieValue = await createPendingAuthCookieValue(pending);
  const maxAge = 10 * 60; // seconds
  const secure = url.protocol === 'https:';
  const domain = getCookieDomain(url);

  const setCookie = [
    `${KEYCLOAK_AUTH_COOKIE}=${encodeURIComponent(cookieValue)}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Lax',
    secure ? 'Secure' : null,
    domain ? `Domain=${domain}` : null,
    `Max-Age=${maxAge}`,
  ]
    .filter(Boolean)
    .join('; ');

  return new Response(null, {
    status: 302,
    headers: {
      Location: authorizeUrl,
      'Set-Cookie': setCookie,
    },
  });
};