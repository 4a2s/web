export interface KeycloakTokens {
  access_token: string;
  expires_in: number;
  refresh_token?: string;
  id_token?: string;
  token_type?: string;
  scope?: string;
}

export interface StoredKeycloakSession {
  accessToken: string;
  refreshToken?: string;
  idToken?: string;
  tokenType?: string;
  scope?: string;
  expiresAt: number;
}

export const KEYCLOAK_STORAGE_KEYS = {
  session: 'portal:keycloak:session',
  state: 'portal:keycloak:state',
  verifier: 'portal:keycloak:verifier',
  returnTo: 'portal:keycloak:returnTo',
} as const;

function getRequiredConfig() {
  const issuer = 'https://auth.4a2s.ch/realms/master';
  const clientId = import.meta.env.PUBLIC_KEYCLOAK_CLIENT_ID;

  if (!clientId) {
    throw new Error(
      'Missing Keycloak config. Define PUBLIC_KEYCLOAK_CLIENT_ID in your environment.',
    );
  }

  return { issuer, clientId };
}

export function getKeycloakIssuer() {
  return getRequiredConfig().issuer;
}

export function getKeycloakClientId() {
  return getRequiredConfig().clientId;
}

export function buildAuthorizeUrl(params: {
  redirectUri: string;
  state: string;
  codeChallenge: string;
  scope?: string;
}) {
  const { issuer, clientId } = getRequiredConfig();
  const url = new URL(`${issuer}/protocol/openid-connect/auth`);

  url.searchParams.set('client_id', clientId);
  url.searchParams.set('redirect_uri', params.redirectUri);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('scope', params.scope ?? 'openid profile email');
  url.searchParams.set('state', params.state);
  url.searchParams.set('code_challenge', params.codeChallenge);
  url.searchParams.set('code_challenge_method', 'S256');

  return url.toString();
}

export function buildTokenEndpoint() {
  return `${getRequiredConfig().issuer}/protocol/openid-connect/token`;
}

export function buildLogoutUrl(params: { idTokenHint?: string; postLogoutRedirectUri: string }) {
  const url = new URL(`${getRequiredConfig().issuer}/protocol/openid-connect/logout`);

  if (params.idTokenHint) {
    url.searchParams.set('id_token_hint', params.idTokenHint);
  }

  url.searchParams.set('post_logout_redirect_uri', params.postLogoutRedirectUri);

  return url.toString();
}

export function createCodeVerifier() {
  const bytes = new Uint8Array(96);
  crypto.getRandomValues(bytes);

  return base64UrlEncode(bytes);
}

export async function createCodeChallenge(verifier: string) {
  const data = new TextEncoder().encode(verifier);
  const hash = await crypto.subtle.digest('SHA-256', data);

  return base64UrlEncode(new Uint8Array(hash));
}

export function storePendingAuthState(params: {
  state: string;
  verifier: string;
  returnTo: string;
}) {
  sessionStorage.setItem(KEYCLOAK_STORAGE_KEYS.state, params.state);
  sessionStorage.setItem(KEYCLOAK_STORAGE_KEYS.verifier, params.verifier);
  sessionStorage.setItem(KEYCLOAK_STORAGE_KEYS.returnTo, params.returnTo);
}

export function readPendingAuthState() {
  return {
    state: sessionStorage.getItem(KEYCLOAK_STORAGE_KEYS.state),
    verifier: sessionStorage.getItem(KEYCLOAK_STORAGE_KEYS.verifier),
    returnTo: sessionStorage.getItem(KEYCLOAK_STORAGE_KEYS.returnTo) ?? '/private/service',
  };
}

export function clearPendingAuthState() {
  sessionStorage.removeItem(KEYCLOAK_STORAGE_KEYS.state);
  sessionStorage.removeItem(KEYCLOAK_STORAGE_KEYS.verifier);
  sessionStorage.removeItem(KEYCLOAK_STORAGE_KEYS.returnTo);
}

export function saveSession(tokens: KeycloakTokens) {
  const session: StoredKeycloakSession = {
    accessToken: tokens.access_token,
    refreshToken: tokens.refresh_token,
    idToken: tokens.id_token,
    tokenType: tokens.token_type,
    scope: tokens.scope,
    expiresAt: Date.now() + tokens.expires_in * 1000,
  };

  localStorage.setItem(KEYCLOAK_STORAGE_KEYS.session, JSON.stringify(session));
}

export function readSession() {
  const rawSession = localStorage.getItem(KEYCLOAK_STORAGE_KEYS.session);

  if (!rawSession) {
    return null;
  }

  try {
    return JSON.parse(rawSession) as StoredKeycloakSession;
  } catch {
    return null;
  }
}

export function clearSession() {
  localStorage.removeItem(KEYCLOAK_STORAGE_KEYS.session);
}

export function isSessionValid(session: StoredKeycloakSession | null) {
  return Boolean(session && session.expiresAt > Date.now() + 30_000);
}

export async function exchangeCodeForTokens(params: {
  code: string;
  codeVerifier: string;
  redirectUri: string;
}) {
  const response = await fetch(buildTokenEndpoint(), {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      client_id: getKeycloakClientId(),
      code: params.code,
      code_verifier: params.codeVerifier,
      redirect_uri: params.redirectUri,
    }),
  });

  if (!response.ok) {
    throw new Error(`Keycloak token exchange failed: ${response.status} ${response.statusText}`);
  }

  return (await response.json()) as KeycloakTokens;
}

function base64UrlEncode(value: Uint8Array) {
  let output = '';

  for (const byte of value) {
    output += String.fromCharCode(byte);
  }

  return btoa(output).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}