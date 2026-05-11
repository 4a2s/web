import {
  buildAuthorizeUrl,
  createCodeChallenge,
  createCodeVerifier,
  createPendingAuthCookieValue,
  getCookieOptions,
  KEYCLOAK_AUTH_COOKIE,
  normalizeReturnTo,
} from '../../lib/keycloak-server';

export const prerender = false;

export const GET = async ({ cookies, url }: any) => {
  const returnTo = normalizeReturnTo(url.searchParams.get('returnTo'));
  const state = crypto.randomUUID();
  const verifier = createCodeVerifier();
  const challenge = await createCodeChallenge(verifier);
  const redirectUri = new URL('/auth/callback', url.origin).toString();
  const authorizeUrl = buildAuthorizeUrl({
    redirectUri,
    state,
    codeChallenge: challenge,
  });

  const cookieValue = await createPendingAuthCookieValue({ state, verifier, returnTo });
  const maxAge = 10 * 60; // seconds
  const secure = url.protocol === 'https:';

  const setCookie = `${KEYCLOAK_AUTH_COOKIE}=${encodeURIComponent(cookieValue)}; Path=/; HttpOnly; SameSite=Lax; ${
    secure ? 'Secure; ' : ''
  }Max-Age=${maxAge}`;

  return new Response(null, {
    status: 302,
    headers: {
      Location: authorizeUrl,
      'Set-Cookie': setCookie,
    },
  });
};