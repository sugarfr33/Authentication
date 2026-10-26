import { describe, expect, it, vi } from 'vitest';
import { createAuthApi } from '@/api/auth';
import { ApiError } from '@/api/errors';
import { createHttpClient, type LockManagerLike } from '@/api/http';
import { createFakeAuthServer, createFakeLocks } from '../helpers/fakeAuthServer';

function setup(serverOptions: Parameters<typeof createFakeAuthServer>[0] = {}, locks: LockManagerLike | null = null) {
  const server = createFakeAuthServer(serverOptions);
  const onSessionExpired = vi.fn();
  const http = createHttpClient({ fetch: server.fetch, readCookie: server.readCookie, locks, onSessionExpired });
  return { server, http, api: createAuthApi(http), onSessionExpired };
}

describe('silent refresh (T23 acceptance: concurrent 401s -> exactly one refresh, then retry)', () => {
  it('runs exactly one refresh for many concurrent 401s and retries every call', async () => {
    const { server, api, onSessionExpired } = setup();
    await api.getProfile(); // signed in, XSRF pair issued
    server.expireAccess();
    server.calls.length = 0;

    const results = await Promise.all([
      api.listSessions(),
      api.listSessions(),
      api.getProfile(),
      api.listSessions(),
      api.getProfile(),
    ]);

    expect(server.count('POST', '/auth/refresh')).toBe(1);
    expect(server.state.refreshCount).toBe(1);
    expect(results).toHaveLength(5);
    expect(results[0]).toEqual([expect.objectContaining({ familyId: 'f1', isCurrent: true })]);
    // each call: one 401 and one retry
    expect(server.count('GET', '/auth/sessions')).toBe(6);
    expect(onSessionExpired).not.toHaveBeenCalled();
  });

  it('does a GET first so the refresh POST carries an anonymous XSRF pair (stale user pair would be 400)', async () => {
    const { server, api } = setup();
    await api.getProfile();
    const userXsrf = server.jar.get('XSRF-TOKEN');
    server.expireAccess();
    server.calls.length = 0;

    await api.listSessions();

    const refreshIndex = server.calls.findIndex((c) => c.method === 'POST' && c.path === '/auth/refresh');
    const probeIndex = server.calls.findIndex((c) => c.method === 'GET' && c.path === '/auth/me');
    expect(probeIndex).toBeGreaterThanOrEqual(0);
    expect(probeIndex).toBeLessThan(refreshIndex);
    const refreshCall = server.calls[refreshIndex];
    expect(refreshCall?.xsrfHeader).toMatch(/^anon-/);
    expect(refreshCall?.xsrfHeader).not.toBe(userXsrf);
  });

  it('serialises refresh across tabs: the second tab finds the session already refreshed', async () => {
    const server = createFakeAuthServer();
    const locks = createFakeLocks(); // one browser = one lock manager, shared by both tabs
    const tabA = createAuthApi(createHttpClient({ fetch: server.fetch, readCookie: server.readCookie, locks }));
    const tabB = createAuthApi(createHttpClient({ fetch: server.fetch, readCookie: server.readCookie, locks }));
    await tabA.getProfile();
    server.expireAccess();

    await Promise.all([tabA.listSessions(), tabB.listSessions(), tabA.getProfile(), tabB.getProfile()]);

    expect(server.count('POST', '/auth/refresh')).toBe(1);
    expect(locks.grants).toBe(2); // one recovery per tab, one after the other
  });

  it('recovers an unsafe call that failed on a stale XSRF pair, with one refresh', async () => {
    const { server, api } = setup();
    await api.getProfile(); // user-bound pair
    server.expireAccess(); // now anonymous: the user pair no longer fits

    await api.logoutAll();

    expect(server.count('POST', '/auth/refresh')).toBe(1);
    const logoutAll = server.calls.filter((c) => c.path === '/auth/logout-all');
    expect(logoutAll).toHaveLength(2);
    expect(logoutAll[1]?.xsrfHeader).toMatch(/^user-/);
  });

  it('treats a 409 (lost refresh race) as success when the session is live', async () => {
    const { server, api, onSessionExpired } = setup({ loseNextRefreshRace: true });
    await api.getProfile();
    server.expireAccess();

    await expect(api.listSessions()).resolves.toHaveLength(1);
    expect(server.state.refreshCount).toBe(0);
    expect(onSessionExpired).not.toHaveBeenCalled();
  });

  it('when the refresh token is dead: every waiting call fails with 401 and the app is told once', async () => {
    const { server, api, onSessionExpired } = setup({ refreshLive: false });
    await api.getProfile().catch(() => undefined);
    server.expireAccess();

    const outcomes = await Promise.allSettled([api.listSessions(), api.getProfile(), api.listSessions()]);

    expect(server.count('POST', '/auth/refresh')).toBe(1);
    expect(onSessionExpired).toHaveBeenCalledTimes(1);
    for (const outcome of outcomes) {
      expect(outcome.status).toBe('rejected');
      const reason = (outcome as PromiseRejectedResult).reason as ApiError;
      expect(reason).toBeInstanceOf(ApiError);
      expect(reason.status).toBe(401);
    }
  });

  it('never refreshes for anonymous calls (sign-in style endpoints)', async () => {
    const { server, http } = setup({ accessValid: false });
    const error = (await http.request('/auth/logout-all', { method: 'POST', auth: 'anonymous' }).catch((e: unknown) => e)) as ApiError;
    expect(error.status).toBe(401);
    expect(server.count('POST', '/auth/refresh')).toBe(0);
  });

  it('starts a new refresh for a later expiry (single flight is per episode, not forever)', async () => {
    const { server, api } = setup();
    await api.getProfile();
    server.expireAccess();
    await api.getProfile();
    server.expireAccess();
    await api.getProfile();
    expect(server.count('POST', '/auth/refresh')).toBe(2);
  });

  it('a network failure is status 0 and does not end the session', async () => {
    const onSessionExpired = vi.fn();
    const http = createHttpClient({
      fetch: () => Promise.reject(new TypeError('Failed to fetch')),
      readCookie: () => null,
      locks: null,
      onSessionExpired,
    });
    const error = await createAuthApi(http).getProfile().catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ApiError);
    expect((error as ApiError).isNetworkError).toBe(true);
    expect(onSessionExpired).not.toHaveBeenCalled();
  });
});

describe('request basics', () => {
  it('always sends credentials: include, and X-XSRF-TOKEN on unsafe requests only', async () => {
    const { server, api } = setup();
    await api.getProfile();
    await api.logoutAll();

    expect(server.calls.every((c) => c.credentials === 'include')).toBe(true);
    for (const call of server.calls) {
      if (call.method === 'GET') expect(call.xsrfHeader).toBeNull();
      else expect(call.xsrfHeader).toBe('user-1');
    }
  });

  it('primes an XSRF pair with a GET before the first unsafe request', async () => {
    const { server, api } = setup({ accessValid: false });
    await api.login('ada@example.com', 'correct horse battery staple');
    expect(server.calls.map((c) => `${c.method} ${c.path}`)).toEqual(['GET /auth/me', 'POST /auth/login']);
  });

  it('maps ProblemDetails, validation errors and Retry-After into ApiError', async () => {
    const http = createHttpClient({
      locks: null,
      readCookie: () => 'anon-1',
      fetch: async () =>
        new Response(
          JSON.stringify({ title: 'The registration request is invalid.', errors: { password: ['Too short.'] }, traceId: 't-1' }),
          { status: 429, headers: { 'Content-Type': 'application/problem+json', 'Retry-After': '30' } },
        ),
    });
    const error = (await http.request('/auth/register', { method: 'POST', auth: 'anonymous' }).catch((e: unknown) => e)) as ApiError;
    expect(error.status).toBe(429);
    expect(error.title).toBe('The registration request is invalid.');
    expect(error.fieldErrors).toEqual({ password: ['Too short.'] });
    expect(error.retryAfterSeconds).toBe(30);
    expect(error.traceId).toBe('t-1');
  });
});
