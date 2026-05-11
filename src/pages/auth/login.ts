import {
  buildAuthorizeUrl,
  createCodeChallenge,
  createCodeVerifier,
  createPendingAuthCookieValue,
  getAppOrigin,
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
  const redirectUri = new URL('/auth/callback', getAppOrigin()).toString();
  const authorizeUrl = buildAuthorizeUrl({
    redirectUri,
    state,
    codeChallenge: challenge,
  });

  cookies.set(
    KEYCLOAK_AUTH_COOKIE,
    await createPendingAuthCookieValue({ state, verifier, returnTo }),
    getCookieOptions(url, 10 * 60),
  );

  return Response.redirect(authorizeUrl, 302);
};