// An in-memory stand-in for Auth.Api's session endpoints, faithful to the rules the SPA depends on
// (docs/sign-in-and-sessions.md, docs/browser-security.md):
// - GET under /api issues an XSRF pair bound to the current identity (user or anonymous);
// - every unsafe request needs X-XSRF-TOKEN equal to the cookie AND bound to the current identity,
//   otherwise 400 "Missing or invalid antiforgery token.";
// - /refresh rotates (204) while the refresh token is live, else 401; optionally 409 for a lost race.
// The cookie jar is shared, like a browser's, so several clients ("tabs") can use one server.

import type { LockManagerLike } from '@/api/http';

export const PROFILE = {
  id: '00000000-0000-0000-0000-000000000001',
  email: 'ada@example.com',
  emailVerified: true,
  displayName: 'Ada',
  mfaEnabled: false,
  roles: ['User'],
  permissions: [],
};

/** Strings that would be a leak if they ever showed up in script-visible state. */
export const SECRET_ACCESS_TOKEN = 'eyJhbGciOiJFUzI1NiJ9.SECRET-ACCESS.sig';
export const SECRET_REFRESH_TOKEN = 'SECRET-REFRESH-TOKEN-0123456789';

export interface Call {
  method: string;
  path: string;
  credentials: RequestCredentials | undefined;
  xsrfHeader: string | null;
}

export interface FakeAuthServerOptions {
  accessValid?: boolean;
  refreshLive?: boolean;
  /** Answer the next refresh with 409 (lost race) after making the session valid, as the winner would. */
  loseNextRefreshRace?: boolean;
  /** Simulated latency per request, in macrotasks. */
  latencyTicks?: number;
  /** Extra macrotasks AFTER the answer is decided, per path: a response that is already on its way. */
  slowResponsePaths?: Record<string, number>;
  /** Also write XSRF-TOKEN into document.cookie (for the app-wide client, which reads the real cookie). */
  mirrorXsrfToDocument?: boolean;
}

function json(status: number, body: unknown, extraHeaders: Record<string, string> = {}): Response {
  return new Response(body === undefined ? null : JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', ...extraHeaders },
  });
}

function problem(status: number, title: string): Response {
  return json(status, { type: 'about:blank', title, status, traceId: '00-abc-01' }, { 'Content-Type': 'application/problem+json' });
}

export function createFakeAuthServer(options: FakeAuthServerOptions = {}) {
  const state = {
    accessValid: options.accessValid ?? true,
    refreshLive: options.refreshLive ?? true,
    loseNextRefreshRace: options.loseNextRefreshRace ?? false,
    xsrfGeneration: 0,
    xsrfIdentity: 'none' as 'none' | 'user' | 'anon',
    refreshCount: 0,
  };
  const jar = new Map<string, string>();
  const calls: Call[] = [];
  const latency = options.latencyTicks ?? 1;

  function issueXsrf(): void {
    state.xsrfGeneration++;
    state.xsrfIdentity = state.accessValid ? 'user' : 'anon';
    const value = `${state.xsrfIdentity}-${state.xsrfGeneration}`;
    jar.set('XSRF-TOKEN', value);
    if (options.mirrorXsrfToDocument) document.cookie = `XSRF-TOKEN=${value}; path=/`;
  }

  function antiforgeryOk(header: string | null): boolean {
    const cookie = jar.get('XSRF-TOKEN');
    if (!header || header !== cookie) return false;
    const identity = state.accessValid ? 'user' : 'anon';
    return header.startsWith(`${identity}-`);
  }

  const tick = () => new Promise((resolve) => setTimeout(resolve, 0));

  const fetch: typeof globalThis.fetch = async (input, init) => {
    for (let i = 0; i < latency; i++) await tick();
    const response = handle(input, init);
    const path = new URL(typeof input === 'string' ? input : input instanceof URL ? input.href : input.url, 'http://localhost').pathname.replace(/^\/api\/v1/, '');
    for (let i = 0; i < (options.slowResponsePaths?.[path] ?? 0); i++) await tick();
    return response;
  };

  function handle(input: Parameters<typeof globalThis.fetch>[0], init: Parameters<typeof globalThis.fetch>[1]): Response {
    const url = new URL(typeof input === 'string' ? input : input instanceof URL ? input.href : input.url, 'http://localhost');
    const method = (init?.method ?? 'GET').toUpperCase();
    const headers = new Headers(init?.headers);
    const xsrfHeader = headers.get('X-XSRF-TOKEN');
    const path = url.pathname.replace(/^\/api\/v1/, '');
    calls.push({ method, path, credentials: init?.credentials, xsrfHeader });

    if (method === 'GET') issueXsrf();
    else if (!antiforgeryOk(xsrfHeader)) return problem(400, 'Missing or invalid antiforgery token.');

    switch (`${method} ${path}`) {
      case 'GET /auth/me':
        return state.accessValid ? json(200, PROFILE) : problem(401, 'Authentication required.');
      case 'GET /auth/sessions':
        return state.accessValid
          ? json(200, [
              {
                familyId: 'f1',
                ip: '203.0.113.7',
                userAgent: '<script>alert(1)</script>',
                createdUtc: '2026-10-01T10:00:00Z',
                lastUsedUtc: '2026-10-26T03:00:00Z',
                isCurrent: true,
              },
            ])
          : problem(401, 'Authentication required.');
      case 'POST /auth/logout-all':
        if (!state.accessValid) return problem(401, 'Authentication required.');
        state.accessValid = false;
        state.refreshLive = false;
        issueXsrf();
        return new Response(null, { status: 204 });
      case 'POST /auth/refresh':
        if (state.loseNextRefreshRace) {
          state.loseNextRefreshRace = false;
          state.accessValid = true; // the winner rotated the shared cookies
          return problem(409, 'The session was refreshed by another request.');
        }
        if (!state.refreshLive) return problem(401, 'Authentication required.');
        state.refreshCount++;
        state.accessValid = true;
        issueXsrf();
        return new Response(null, {
          status: 204,
          // A real browser keeps these HttpOnly cookies away from script; the SPA must never read them.
          headers: {
            'Set-Cookie': `__Host-access=${SECRET_ACCESS_TOKEN}; HttpOnly; Secure; SameSite=Strict; Path=/`,
          },
        });
      case 'POST /auth/login':
        state.accessValid = true;
        state.refreshLive = true;
        issueXsrf();
        // Deliberately includes a token-like field: the API layer must drop anything it does not know.
        return json(200, { ...PROFILE, accessToken: SECRET_ACCESS_TOKEN, refreshToken: SECRET_REFRESH_TOKEN });
      case 'POST /auth/logout':
        state.accessValid = false;
        state.refreshLive = false;
        issueXsrf();
        return new Response(null, { status: 204 });
      default:
        return problem(404, 'Not found.');
    }
  }

  return {
    state,
    jar,
    calls,
    fetch,
    readCookie: (name: string) => jar.get(name) ?? null,
    /** Lets the access cookie expire (the browser drops it). */
    expireAccess(): void {
      state.accessValid = false;
    },
    count(method: string, path: string): number {
      return calls.filter((c) => c.method === method && c.path === path).length;
    },
  };
}

/** A Web Locks stand-in: exclusive, FIFO, shared by every client given the same instance (= one browser). */
export function createFakeLocks(): LockManagerLike & { grants: number } {
  let tail: Promise<unknown> = Promise.resolve();
  const locks = {
    grants: 0,
    request<T>(_name: string, callback: () => Promise<T>): Promise<T> {
      const run = tail.then(() => {
        locks.grants++;
        return callback();
      });
      tail = run.catch(() => undefined);
      return run;
    },
  };
  return locks;
}
