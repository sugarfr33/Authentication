// Example for a CONSUMING application: a Vue SPA on another domain that signs its users in through Central Auth
// with the authorization code flow and PKCE (docs/authorization-code-pkce.md). Copy it into the app; it is not
// part of the Central Auth SPA bundle. It uses only vue and vue-router, which such an app already has.
//
// Client requirements it implements (docs/authorization-code-pkce.md sections 6-7):
// - S256 PKCE; `state` is random, kept in sessionStorage for this tab only, and a callback whose state this tab
//   did not create is refused (login CSRF). The verifier and state are deleted as soon as the callback is read.
// - The access token AND the refresh token are kept in memory only (never localStorage, sessionStorage or a
//   cookie). After a reload the app starts /authorize again: the Central Auth cookie session makes it a quick
//   bounce, not a sign-in form.
// - Refresh rotates the refresh token; one refresh at a time (single flight).
// - The page to return to is a same-origin path only (no open redirect).
import { computed, shallowRef, type ComputedRef } from 'vue';
import type { NavigationGuardReturn, RouteLocationNormalized } from 'vue-router';

export interface CentralAuthOptions {
  /** Central Auth API origin, for example "https://auth.example.com". */
  issuer: string;
  clientId: string;
  /** Registered redirect URI of this app, matched character for character by the server. */
  redirectUri: string;
  /** Seconds before expiry at which the access token is refreshed (default 60). */
  refreshLeewaySeconds?: number;
  // Injection points for tests.
  fetch?: typeof fetch;
  storage?: Pick<Storage, 'getItem' | 'setItem' | 'removeItem'>;
  crypto?: Crypto;
  navigate?: (url: string) => void;
  now?: () => number;
  appOrigin?: string;
}

export interface CentralAuth {
  readonly isAuthenticated: ComputedRef<boolean>;
  /** Sends the browser to Central Auth; returns to `returnPath` (same-origin path) after the callback. */
  signIn(returnPath?: string): Promise<void>;
  /** Call on the redirect URI page. Returns the safe path to continue to. Throws CentralAuthError on a bad callback. */
  handleCallback(callbackUrl: string): Promise<string>;
  /** A valid access token (refreshed when close to expiry), or null when signed out. */
  getAccessToken(): Promise<string | null>;
  /** fetch() for this app's own API with the Bearer token. */
  authFetch(input: string, init?: RequestInit): Promise<Response>;
  /** Forgets the tokens in this tab. (Ending the Central Auth session is /oauth/logout, not shown here.) */
  signOut(): void;
}

export class CentralAuthError extends Error {
  constructor(readonly code: 'state_mismatch' | 'authorization_failed' | 'token_failed') {
    super(code);
    this.name = 'CentralAuthError';
  }
}

interface TokenSet {
  accessToken: string;
  refreshToken: string;
  expiresAt: number;
}

const PENDING_KEY = 'central-auth:pending';
const UNRESERVED = /^[A-Za-z0-9\-._~]{43,128}$/;

function base64Url(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** A same-origin path, or "/" (no open redirect). */
export function safeReturnPath(raw: unknown, origin: string): string {
  if (typeof raw !== 'string' || !raw.startsWith('/') || raw.startsWith('//') || raw.includes('\\')) return '/';
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f\s]/.test(raw)) return '/';
  try {
    const url = new URL(raw, origin);
    return url.origin === new URL(origin).origin ? `${url.pathname}${url.search}${url.hash}` : '/';
  } catch {
    return '/';
  }
}

export function createCentralAuth(options: CentralAuthOptions): CentralAuth {
  const doFetch = options.fetch ?? globalThis.fetch.bind(globalThis);
  const storage = options.storage ?? window.sessionStorage;
  const crypto = options.crypto ?? globalThis.crypto;
  const navigate = options.navigate ?? ((url: string) => window.location.assign(url));
  const now = options.now ?? Date.now;
  const appOrigin = options.appOrigin ?? window.location.origin;
  const leewayMs = (options.refreshLeewaySeconds ?? 60) * 1000;
  const issuer = new URL(options.issuer).origin;

  // Memory only.
  const tokens = shallowRef<TokenSet | null>(null);
  let refreshing: Promise<TokenSet | null> | null = null;

  function randomString(byteLength: number): string {
    return base64Url(crypto.getRandomValues(new Uint8Array(byteLength)));
  }

  async function challengeFor(verifier: string): Promise<string> {
    const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
    return base64Url(new Uint8Array(digest));
  }

  async function tokenRequest(body: Record<string, string>): Promise<TokenSet> {
    const response = await doFetch(`${issuer}/api/v1/oauth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams(body).toString(),
      credentials: 'omit',
      cache: 'no-store',
      redirect: 'error',
    });
    if (!response.ok) throw new CentralAuthError('token_failed');
    const json = (await response.json()) as Record<string, unknown>;
    const { access_token: accessToken, refresh_token: refreshToken, expires_in: expiresIn } = json;
    if (typeof accessToken !== 'string' || typeof refreshToken !== 'string' || typeof expiresIn !== 'number') {
      throw new CentralAuthError('token_failed');
    }
    return { accessToken, refreshToken, expiresAt: now() + expiresIn * 1000 };
  }

  async function signIn(returnPath = '/'): Promise<void> {
    const verifier = randomString(32);
    const state = randomString(32);
    storage.setItem(PENDING_KEY, JSON.stringify({ state, verifier, returnPath: safeReturnPath(returnPath, appOrigin) }));
    const url = new URL('/api/v1/oauth/authorize', issuer);
    url.search = new URLSearchParams({
      response_type: 'code',
      client_id: options.clientId,
      redirect_uri: options.redirectUri,
      code_challenge: await challengeFor(verifier),
      code_challenge_method: 'S256',
      state,
    }).toString();
    navigate(url.href);
  }

  async function handleCallback(callbackUrl: string): Promise<string> {
    const params = new URL(callbackUrl).searchParams;
    const raw = storage.getItem(PENDING_KEY);
    storage.removeItem(PENDING_KEY);
    let pending: { state?: unknown; verifier?: unknown; returnPath?: unknown } = {};
    try {
      pending = raw ? (JSON.parse(raw) as typeof pending) : {};
    } catch {
      pending = {};
    }
    const state = params.get('state');
    if (typeof pending.state !== 'string' || state === null || state !== pending.state) {
      throw new CentralAuthError('state_mismatch');
    }
    const code = params.get('code');
    if (params.has('error') || code === null || typeof pending.verifier !== 'string' || !UNRESERVED.test(pending.verifier)) {
      throw new CentralAuthError('authorization_failed');
    }
    tokens.value = await tokenRequest({
      grant_type: 'authorization_code',
      code,
      redirect_uri: options.redirectUri,
      client_id: options.clientId,
      code_verifier: pending.verifier,
    });
    return safeReturnPath(pending.returnPath, appOrigin);
  }

  function refresh(current: TokenSet): Promise<TokenSet | null> {
    refreshing ??= tokenRequest({ grant_type: 'refresh_token', refresh_token: current.refreshToken, client_id: options.clientId })
      .catch(() => null)
      .then((next) => {
        tokens.value = next;
        return next;
      })
      .finally(() => {
        refreshing = null;
      });
    return refreshing;
  }

  async function getAccessToken(): Promise<string | null> {
    const current = tokens.value;
    if (current === null) return null;
    if (current.expiresAt - leewayMs > now()) return current.accessToken;
    return (await refresh(current))?.accessToken ?? null;
  }

  async function authFetch(input: string, init: RequestInit = {}): Promise<Response> {
    const token = await getAccessToken();
    const headers = new Headers(init.headers);
    if (token) headers.set('Authorization', `Bearer ${token}`);
    return doFetch(input, { ...init, headers });
  }

  function signOut(): void {
    tokens.value = null;
  }

  return {
    isAuthenticated: computed(() => tokens.value !== null),
    signIn,
    handleCallback,
    getAccessToken,
    authFetch,
    signOut,
  };
}

/**
 * Route guard for the consuming app: pages with meta.requiresAuth start the sign-in when there is no token in
 * memory (also right after a reload), returning to the page afterwards.
 *   router.beforeEach(createCentralAuthGuard(auth));
 */
export function createCentralAuthGuard(auth: Pick<CentralAuth, 'isAuthenticated' | 'signIn'>) {
  return async (to: RouteLocationNormalized): Promise<NavigationGuardReturn> => {
    if (!to.meta.requiresAuth || auth.isAuthenticated.value) return true;
    await auth.signIn(to.fullPath);
    return false;
  };
}
