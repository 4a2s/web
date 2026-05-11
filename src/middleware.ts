import { defineMiddleware } from 'astro:middleware';

import {
  DEFAULT_RETURN_TO,
  getAppOrigin,
  KEYCLOAK_AUTH_COOKIE,
  KEYCLOAK_SESSION_COOKIE,
  isSessionValid,
  normalizeReturnTo,
  readSessionCookieValue,
} from './lib/keycloak-server';

export const onRequest = defineMiddleware(async (context, next) => {
  const { pathname, search } = context.url;

  if (pathname === '/private' || pathname.startsWith('/private/')) {
    const session = await readSessionCookieValue(context.cookies.get(KEYCLOAK_SESSION_COOKIE)?.value);

    if (!isSessionValid(session)) {
      context.cookies.delete(KEYCLOAK_SESSION_COOKIE, { path: '/' });
      context.cookies.delete(KEYCLOAK_AUTH_COOKIE, { path: '/' });

      const returnTo = normalizeReturnTo(`${pathname}${search}`);
      const loginUrl = new URL('/auth/login', getAppOrigin());

      loginUrl.searchParams.set('returnTo', returnTo || DEFAULT_RETURN_TO);

      return Response.redirect(loginUrl.toString(), 302);
    }

    context.locals.session = session;
  }

  return next();
});