import {
  buildSessionFromTokens,
  createSessionCookieValue,
  exchangeCodeForTokens,
  getCookieOptions,
  KEYCLOAK_AUTH_COOKIE,
  KEYCLOAK_SESSION_COOKIE,
  readPendingAuthCookieValue,
} from '../../lib/keycloak-server';

export const prerender = false;

export const GET = async ({ cookies, url }: any) => {
  const code = url.searchParams.get('code');
  const returnedState = url.searchParams.get('state');

  if (!code || !returnedState) {
    return new Response('Réponse Keycloak incomplète.', { status: 400 });
  }

  const pending = await readPendingAuthCookieValue(cookies.get(KEYCLOAK_AUTH_COOKIE)?.value);

  if (!pending || pending.state !== returnedState) {
    return new Response('L’état OAuth2 ne correspond pas à la demande initiale.', { status: 400 });
  }

  try {
    const tokens = await exchangeCodeForTokens({
      code,
      codeVerifier: pending.verifier,
      redirectUri: new URL('/auth/callback', url.origin).toString(),
    });

    const session = buildSessionFromTokens(tokens);

    const sessionValue = await createSessionCookieValue(session);
    const maxAge = Math.max(60, tokens.expires_in);
    const secure = url.protocol === 'https:';

    const setSession = `${KEYCLOAK_SESSION_COOKIE}=${encodeURIComponent(
      sessionValue,
    )}; Path=/; HttpOnly; SameSite=Lax; ${secure ? 'Secure; ' : ''}Max-Age=${maxAge}`;
    const clearAuth = `${KEYCLOAK_AUTH_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; ${
      secure ? 'Secure; ' : ''
    }Max-Age=0`;

    return new Response(null, {
      status: 302,
      headers: {
        Location: new URL(pending.returnTo, url.origin).toString(),
        'Set-Cookie': `${setSession}; ${clearAuth}`,
      },
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Impossible de finaliser la session.';
    return new Response(message, { status: 502 });
  }
};