import {
  buildSessionFromTokens,
  createSessionCookieValue,
  exchangeCodeForTokens,
  getCookieOptions,
  KEYCLOAK_AUTH_COOKIE,
  KEYCLOAK_SESSION_COOKIE,
  readPendingAuthCookieValue,
} from '../../lib/keycloak-server';

export const GET = async ({ cookies, url }: any) => {
  const code = url.searchParams.get('code');
  const returnedState = url.searchParams.get('state');

  if (!code || !returnedState) {
    cookies.delete(KEYCLOAK_AUTH_COOKIE, { path: '/' });
    return new Response('Réponse Keycloak incomplète.', { status: 400 });
  }

  const pending = await readPendingAuthCookieValue(cookies.get(KEYCLOAK_AUTH_COOKIE)?.value);

  if (!pending || pending.state !== returnedState) {
    cookies.delete(KEYCLOAK_AUTH_COOKIE, { path: '/' });
    return new Response('L’état OAuth2 ne correspond pas à la demande initiale.', { status: 400 });
  }

  try {
    const tokens = await exchangeCodeForTokens({
      code,
      codeVerifier: pending.verifier,
      redirectUri: new URL('/auth/callback', url).toString(),
    });

    const session = buildSessionFromTokens(tokens);

    cookies.set(
      KEYCLOAK_SESSION_COOKIE,
      await createSessionCookieValue(session),
      getCookieOptions(url, Math.max(60, tokens.expires_in)),
    );
    cookies.delete(KEYCLOAK_AUTH_COOKIE, { path: '/' });

    return Response.redirect(new URL(pending.returnTo, url).toString(), 302);
  } catch (error) {
    cookies.delete(KEYCLOAK_AUTH_COOKIE, { path: '/' });
    cookies.delete(KEYCLOAK_SESSION_COOKIE, { path: '/' });

    const message = error instanceof Error ? error.message : 'Impossible de finaliser la session.';
    return new Response(message, { status: 502 });
  }
};