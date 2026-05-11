import {
  buildLogoutUrl,
  KEYCLOAK_SESSION_COOKIE,
  readSessionCookieValue,
} from '../../lib/keycloak-server';

export const prerender = false;

export const GET = async ({ cookies, url }: any) => {
  const session = await readSessionCookieValue(cookies.get(KEYCLOAK_SESSION_COOKIE)?.value);
  const redirectUri = new URL('/', url.origin).toString();
  const secure = url.protocol === 'https:';
  const clearSession = `${KEYCLOAK_SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; ${
    secure ? 'Secure; ' : ''
  }Max-Age=0`;

  return new Response(null, {
    status: 302,
    headers: {
      Location: buildLogoutUrl({ idTokenHint: session?.idToken, postLogoutRedirectUri: redirectUri }),
      'Set-Cookie': clearSession,
    },
  });
};