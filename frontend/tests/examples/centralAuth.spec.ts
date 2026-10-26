// T24: the consuming-app example (OAuth code + PKCE, tokens in memory, state check, safe return path, guard).
import { describe, expect, it, vi } from 'vitest';
import { webcrypto } from 'node:crypto';
import {
  CentralAuthError,
  createCentralAuth,
  createCentralAuthGuard,
  safeReturnPath,
  type CentralAuthOptions,
} from '../../examples/consuming-app/centralAuth';

const ORIGIN = 'https://app.example.org';

function memoryStorage() {
  const map = new Map<string, string>();
  return {
    map,
    getItem: (k: string) => map.get(k) ?? null,
    setItem: (k: string, v: string) => void map.set(k, v),
    removeItem: (k: string) => void map.delete(k),
  };
}

function tokenResponse(n: number, expiresIn = 900): Response {
  return new Response(JSON.stringify({ access_token: `access-${n}`, token_type: 'Bearer', expires_in: expiresIn, refresh_token: `refresh-${n}` }), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  });
}

function setup(overrides: Partial<CentralAuthOptions> = {}) {
  const storage = memoryStorage();
  const navigate = vi.fn<(url: string) => void>();
  let clock = 1_000_000;
  const fetch = vi.fn<typeof globalThis.fetch>();
  const auth = createCentralAuth({
    issuer: 'https://auth.example.com',
    clientId: 'my-app',
    redirectUri: `${ORIGIN}/callback`,
    fetch,
    storage,
    navigate,
    crypto: webcrypto,
    now: () => clock,
    appOrigin: ORIGIN,
    apiOrigins: ['https://api.example.org'],
    ...overrides,
  });
  return { auth, storage, navigate, fetch, advance: (ms: number) => (clock += ms) };
}

async function signedIn() {
  const ctx = setup();
  await ctx.auth.signIn('/orders/7?tab=2');
  const authorize = new URL(ctx.navigate.mock.calls[0]![0]);
  ctx.fetch.mockResolvedValueOnce(tokenResponse(1));
  const back = await ctx.auth.handleCallback(`${ORIGIN}/callback?code=c1&state=${authorize.searchParams.get('state')}`);
  return { ...ctx, authorize, back };
}

describe('consuming-app example', () => {
  it('starts /authorize with S256 PKCE and a random state', async () => {
    const { authorize, storage } = await signedIn();
    expect(authorize.origin + authorize.pathname).toBe('https://auth.example.com/api/v1/oauth/authorize');
    const p = authorize.searchParams;
    expect(p.get('response_type')).toBe('code');
    expect(p.get('client_id')).toBe('my-app');
    expect(p.get('redirect_uri')).toBe(`${ORIGIN}/callback`);
    expect(p.get('code_challenge_method')).toBe('S256');
    expect(p.get('code_challenge')).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(p.get('state')).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(storage.map.size).toBe(0); // pending state removed once the callback is read
  });

  it('exchanges the code with the verifier that matches the challenge, and returns to the saved path', async () => {
    const { authorize, fetch, back, auth } = await signedIn();
    const [url, init] = fetch.mock.calls[0]!;
    expect(url).toBe('https://auth.example.com/api/v1/oauth/token');
    expect(init?.credentials).toBe('omit');
    const body = new URLSearchParams(String(init?.body));
    expect(body.get('grant_type')).toBe('authorization_code');
    expect(body.get('code')).toBe('c1');
    const digest = await webcrypto.subtle.digest('SHA-256', new TextEncoder().encode(body.get('code_verifier')!));
    const challenge = btoa(String.fromCharCode(...new Uint8Array(digest))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    expect(challenge).toBe(authorize.searchParams.get('code_challenge'));
    expect(back).toBe('/orders/7?tab=2');
    expect(auth.isAuthenticated.value).toBe(true);
    expect(await auth.getAccessToken()).toBe('access-1');
  });

  it('refuses a callback whose state this tab did not create (login CSRF)', async () => {
    const { auth, fetch } = setup();
    await auth.signIn('/');
    await expect(auth.handleCallback(`${ORIGIN}/callback?code=attacker&state=forged`)).rejects.toEqual(new CentralAuthError('state_mismatch'));
    await expect(auth.handleCallback(`${ORIGIN}/callback?code=attacker&state=forged`)).rejects.toBeInstanceOf(CentralAuthError);
    expect(fetch).not.toHaveBeenCalled();
  });

  it('keeps tokens in memory only', async () => {
    const { storage } = await signedIn();
    const local = window.localStorage.length;
    expect(window.sessionStorage.length).toBe(0);
    expect(local).toBe(0);
    expect([...storage.map.values()].join()).not.toContain('access-1');
    expect(document.cookie).not.toContain('access-1');
  });

  it('refreshes once near expiry (single flight) and rotates the refresh token', async () => {
    const { auth, fetch, advance } = await signedIn();
    advance(900_000 - 30_000);
    let release!: (r: Response) => void;
    fetch.mockImplementationOnce(() => new Promise((resolve) => (release = resolve)));
    const a = auth.getAccessToken();
    const b = auth.getAccessToken();
    await Promise.resolve();
    release(tokenResponse(2));
    expect(await a).toBe('access-2');
    expect(await b).toBe('access-2');
    expect(fetch).toHaveBeenCalledTimes(2);
    const body = new URLSearchParams(String(fetch.mock.calls[1]![1]?.body));
    expect(body.get('grant_type')).toBe('refresh_token');
    expect(body.get('refresh_token')).toBe('refresh-1');
  });

  it('signs out locally when the refresh is refused', async () => {
    const { auth, fetch, advance } = await signedIn();
    advance(900_000);
    fetch.mockResolvedValueOnce(new Response('{"error":"invalid_grant"}', { status: 400 }));
    expect(await auth.getAccessToken()).toBeNull();
    expect(auth.isAuthenticated.value).toBe(false);
  });

  it('authFetch adds the Bearer token', async () => {
    const { auth, fetch } = await signedIn();
    fetch.mockResolvedValueOnce(new Response('ok'));
    await auth.authFetch('https://api.example.org/orders');
    const headers = new Headers(fetch.mock.calls[1]![1]?.headers);
    expect(headers.get('Authorization')).toBe('Bearer access-1');
  });

  it('authFetch refuses any origin outside apiOrigins, before reading the token', async () => {
    const { auth, fetch } = await signedIn();
    for (const url of ['https://evil.example/collect', 'https://api.example.org.evil.example/x', '//evil.example/x', 'http://api.example.org/x']) {
      await expect(auth.authFetch(url)).rejects.toEqual(new CentralAuthError('origin_not_allowed'));
    }
    expect(fetch).toHaveBeenCalledTimes(1); // only the code exchange
  });

  it('refuses a callback from another issuer (iss)', async () => {
    const { auth, fetch, navigate } = setup();
    await auth.signIn('/');
    const state = new URL(navigate.mock.calls[0]![0]).searchParams.get('state');
    await expect(auth.handleCallback(`${ORIGIN}/callback?code=c&state=${state}&iss=https%3A%2F%2Fevil.example`)).rejects.toEqual(
      new CentralAuthError('issuer_mismatch'),
    );
    expect(fetch).not.toHaveBeenCalled();
  });

  it('only returns to same-origin paths', () => {
    expect(safeReturnPath('/orders?x=1', ORIGIN)).toBe('/orders?x=1');
    for (const bad of ['/.//evil.com', '/..//evil.com', '/a/..//evil.com', '/%2e//evil.com', '/%2E%2E//evil.com', 'https://evil.example', '//evil.example', '/\\evil.example', 'javascript:alert(1)', '/\n/x', 42]) {
      expect(safeReturnPath(bad, ORIGIN)).toBe('/');
    }
  });

  it('the guard starts the sign-in for protected routes without a token', async () => {
    const { auth, navigate } = setup();
    const guard = createCentralAuthGuard(auth);
    expect(await guard({ meta: {}, fullPath: '/' } as never)).toBe(true);
    expect(await guard({ meta: { requiresAuth: true }, fullPath: '/orders' } as never)).toBe(false);
    expect(navigate).toHaveBeenCalledTimes(1);
  });
});
