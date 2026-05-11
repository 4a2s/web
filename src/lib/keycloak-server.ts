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

export interface PendingAuthState {
  state: string;
  verifier: string;
  returnTo: string;
  createdAt: number;
}

export const KEYCLOAK_AUTH_COOKIE = 'portal:keycloak:auth';
export const KEYCLOAK_SESSION_COOKIE = 'portal:keycloak:session';
export const DEFAULT_RETURN_TO = '/private/service';

const DEFAULT_ISSUER = 'https://auth.4a2s.ch/realms/master';
const DEFAULT_APP_ORIGIN = 'https://4a2s.ch';

function getAppOriginConfig() {
  return import.meta.env.KEYCLOAK_APP_ORIGIN ?? DEFAULT_APP_ORIGIN;
}

function getRequiredConfig() {
  const issuer = import.meta.env.KEYCLOAK_ISSUER ?? DEFAULT_ISSUER;
  const clientId = import.meta.env.KEYCLOAK_CLIENT_ID;
  const clientSecret = import.meta.env.KEYCLOAK_CLIENT_SECRET;
  const cookieSecret = import.meta.env.KEYCLOAK_COOKIE_SECRET;

  if (!clientId) {
    throw new Error('Missing Keycloak config. Define KEYCLOAK_CLIENT_ID in your environment.');
  }

  if (!clientSecret) {
    throw new Error(
      'Missing Keycloak config. Define KEYCLOAK_CLIENT_SECRET in your environment.',
    );
  }

  if (!cookieSecret) {
    throw new Error('Missing Keycloak config. Define KEYCLOAK_COOKIE_SECRET in your environment.');
  }

  return { issuer, clientId, clientSecret, cookieSecret };
}

export function getKeycloakIssuer() {
  return getRequiredConfig().issuer;
}

export function getKeycloakClientId() {
  return getRequiredConfig().clientId;
}

export function getKeycloakClientSecret() {
  return getRequiredConfig().clientSecret;
}

export function getKeycloakCookieSecret() {
  return getRequiredConfig().cookieSecret;
}

export function getAppOrigin() {
  return getAppOriginConfig();
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

export function normalizeReturnTo(value: string | null | undefined) {
  if (!value) {
    return DEFAULT_RETURN_TO;
  }

  try {
    const parsed = new URL(value, 'https://example.invalid');

    if (parsed.origin !== 'https://example.invalid') {
      return DEFAULT_RETURN_TO;
    }

    if (!parsed.pathname.startsWith('/')) {
      return DEFAULT_RETURN_TO;
    }

    return `${parsed.pathname}${parsed.search}${parsed.hash}` || DEFAULT_RETURN_TO;
  } catch {
    return DEFAULT_RETURN_TO;
  }
}

export function isSessionValid(session: StoredKeycloakSession | null) {
  return Boolean(session && session.expiresAt > Date.now() + 30_000);
}

export function buildSessionFromTokens(tokens: KeycloakTokens): StoredKeycloakSession {
  return {
    accessToken: tokens.access_token,
    refreshToken: tokens.refresh_token,
    idToken: tokens.id_token,
    tokenType: tokens.token_type,
    scope: tokens.scope,
    expiresAt: Date.now() + tokens.expires_in * 1000,
  };
}

export async function createPendingAuthCookieValue(params: {
  state: string;
  verifier: string;
  returnTo: string;
}) {
  return encryptCookieValue({
    state: params.state,
    verifier: params.verifier,
    returnTo: normalizeReturnTo(params.returnTo),
    createdAt: Date.now(),
  } satisfies PendingAuthState);
}

export async function readPendingAuthCookieValue(rawValue: string | null | undefined) {
  if (!rawValue) {
    return null;
  }

  const value = await decryptCookieValue<PendingAuthState>(rawValue);

  if (!value || typeof value.state !== 'string' || typeof value.verifier !== 'string') {
    return null;
  }

  return {
    state: value.state,
    verifier: value.verifier,
    returnTo: normalizeReturnTo(value.returnTo),
    createdAt: typeof value.createdAt === 'number' ? value.createdAt : Date.now(),
  } satisfies PendingAuthState;
}

export async function createSessionCookieValue(session: StoredKeycloakSession) {
  return encryptCookieValue(session);
}

export async function readSessionCookieValue(rawValue: string | null | undefined) {
  if (!rawValue) {
    return null;
  }

  const value = await decryptCookieValue<StoredKeycloakSession>(rawValue);

  if (!value || typeof value.accessToken !== 'string' || typeof value.expiresAt !== 'number') {
    return null;
  }

  return value;
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
      client_secret: getKeycloakClientSecret(),
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

export function getCookieOptions(url: URL, maxAgeSeconds?: number) {
  return {
    httpOnly: true,
    secure: url.protocol === 'https:',
    sameSite: 'lax' as const,
    path: '/',
    maxAge: maxAgeSeconds,
  };
}

function base64UrlEncode(value: Uint8Array) {
  let output = '';

  for (const byte of value) {
    output += String.fromCharCode(byte);
  }

  return btoa(output).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function base64UrlDecode(value: string) {
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
  const padded = normalized + '='.repeat((4 - (normalized.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);

  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }

  return bytes;
}

async function encryptCookieValue<T>(value: T) {
  const key = await getCookieCryptoKey();
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = new TextEncoder().encode(JSON.stringify(value));
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plaintext);

  return `${base64UrlEncode(iv)}.${base64UrlEncode(new Uint8Array(ciphertext))}`;
}

async function decryptCookieValue<T>(rawValue: string) {
  const [ivValue, ciphertextValue] = rawValue.split('.');

  if (!ivValue || !ciphertextValue) {
    return null;
  }

  try {
    const key = await getCookieCryptoKey();
    const plaintext = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: base64UrlDecode(ivValue) },
      key,
      base64UrlDecode(ciphertextValue),
    );

    return JSON.parse(new TextDecoder().decode(plaintext)) as T;
  } catch {
    return null;
  }
}

async function getCookieCryptoKey() {
  const secret = getKeycloakCookieSecret();
  const secretBytes = new TextEncoder().encode(secret);
  const hash = await crypto.subtle.digest('SHA-256', secretBytes);

  return crypto.subtle.importKey('raw', hash, 'AES-GCM', false, ['encrypt', 'decrypt']);
}