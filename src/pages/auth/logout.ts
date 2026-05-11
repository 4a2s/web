import {
  buildLogoutUrl,
  KEYCLOAK_SESSION_COOKIE,
  readSessionCookieValue,
} from '../../lib/keycloak-server';

export const prerender = false;

export const GET = async ({ cookies, url }: any) => {
  const session = await readSessionCookieValue(cookies.get(KEYCLOAK_SESSION_COOKIE)?.value);
  const redirectUri = new URL('/', url).toString();

  cookies.delete(KEYCLOAK_SESSION_COOKIE, { path: '/' });

  return Response.redirect(
    buildLogoutUrl({ idTokenHint: session?.idToken, postLogoutRedirectUri: redirectUri }),
    302,
  );
};