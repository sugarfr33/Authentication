// T32: RP-initiated logout page. It validates first (GET /oauth/logout), never signs out on page load, and on the
// user's confirmation ends the application's sessions (POST /oauth/logout) and then the Central Auth browser
// session (POST /auth/logout), before going to the server-built redirect_to (registered post-logout URI only).
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ApiError, authApi, type UserProfile } from '@/api';
import { createAuthApi } from '@/api/auth';
import { createHttpClient } from '@/api/http';
import { format, messages } from '@/i18n/messages';
import { browserNavigation } from '@/router/returnTo';
import { button, mountApp, settle, type MountedApp } from '../helpers/app';

const PROFILE: UserProfile = {
  id: 'u1',
  email: 'ana@example.com',
  emailVerified: true,
  displayName: 'Ana',
  mfaEnabled: false,
  roles: [],
  permissions: [],
};
const BACK = 'https://192.168.0.109/signed-out';
const LINK = `/logout?client_id=suki-rewards&post_logout_redirect_uri=${encodeURIComponent(BACK)}&state=s1`;
const PARAMS = { clientId: 'suki-rewards', postLogoutRedirectUri: BACK, state: 's1' };
const TARGET = { clientId: 'suki-rewards', redirectTo: `${BACK}?state=s1` };

let app: MountedApp | null = null;
let order: string[] = [];

beforeEach(() => {
  order = [];
  vi.spyOn(authApi, 'getProfile').mockResolvedValue(PROFILE);
  vi.spyOn(authApi, 'describeLogout').mockResolvedValue(TARGET);
  vi.spyOn(authApi, 'confirmLogout').mockImplementation(async () => {
    order.push('oauth/logout');
    return TARGET;
  });
  vi.spyOn(authApi, 'logout').mockImplementation(async () => {
    order.push('auth/logout');
  });
  vi.spyOn(browserNavigation, 'assign').mockImplementation(() => undefined);
});

afterEach(() => {
  app?.unmount();
  app = null;
  vi.restoreAllMocks();
});

const text = () => app!.root.textContent ?? '';

async function confirm(): Promise<void> {
  button(app!.root, messages.logout.submit).click();
  await settle();
}

describe('sign-out page', () => {
  it('asks first: nothing is ended on page load', async () => {
    app = await mountApp(LINK);
    expect(authApi.describeLogout).toHaveBeenCalledWith(PARAMS);
    expect(text()).toContain(format(messages.logout.intro, { app: 'suki-rewards' }));
    expect(authApi.confirmLogout).not.toHaveBeenCalled();
    expect(authApi.logout).not.toHaveBeenCalled();
    expect(browserNavigation.assign).not.toHaveBeenCalled();
  });

  it('on confirm ends the app sessions, then the Central Auth session, then returns to the app', async () => {
    app = await mountApp(LINK);
    await confirm();
    expect(authApi.confirmLogout).toHaveBeenCalledWith(PARAMS);
    expect(order).toEqual(['oauth/logout', 'auth/logout']);
    expect(app.session.isAuthenticated).toBe(false);
    expect(browserNavigation.assign).toHaveBeenCalledWith(TARGET.redirectTo);
    expect(text()).toContain(messages.logout.signedOutTitle);
  });

  it('a double click signs out once', async () => {
    app = await mountApp(LINK);
    const submitButton = button(app.root, messages.logout.submit);
    submitButton.click();
    submitButton.click();
    await settle();
    expect(authApi.confirmLogout).toHaveBeenCalledTimes(1);
    expect(authApi.logout).toHaveBeenCalledTimes(1);
    expect(browserNavigation.assign).toHaveBeenCalledTimes(1);
  });

  it('still ends the browser session when the app sessions were already gone (401)', async () => {
    vi.mocked(authApi.confirmLogout).mockRejectedValue(new ApiError({ status: 401 }));
    app = await mountApp(LINK);
    await confirm();
    expect(authApi.logout).toHaveBeenCalled();
    expect(browserNavigation.assign).toHaveBeenCalledWith(TARGET.redirectTo);
  });

  it('changes nothing else when ending the app sessions fails, and lets the user retry', async () => {
    vi.mocked(authApi.confirmLogout).mockRejectedValue(new ApiError({ status: 500 }));
    app = await mountApp(LINK);
    await confirm();
    expect(authApi.logout).not.toHaveBeenCalled();
    expect(browserNavigation.assign).not.toHaveBeenCalled();
    expect(text()).toContain(messages.errors.unexpected);
    expect(button(app.root, messages.logout.submit)).toBeTruthy();
  });

  it('refuses an unknown client (400 from the API): no sign-out button', async () => {
    vi.mocked(authApi.describeLogout).mockRejectedValue(new ApiError({ status: 400 }));
    app = await mountApp(LINK);
    expect(text()).toContain(messages.logout.invalid);
    expect(() => button(app!.root, messages.logout.submit)).toThrow();
  });

  it.each([
    ['no client_id', '/logout'],
    ['a repeated parameter', '/logout?client_id=suki-rewards&state=a&state=b'],
  ])('refuses %s without asking the API', async (_name, path) => {
    app = await mountApp(path);
    expect(authApi.describeLogout).not.toHaveBeenCalled();
    expect(text()).toContain(messages.logout.invalid);
  });

  it('when not signed in, says so and links back to the app without posting anything', async () => {
    vi.mocked(authApi.getProfile).mockRejectedValue(new ApiError({ status: 401 }));
    app = await mountApp(LINK);
    expect(text()).toContain(messages.logout.signedOutBody);
    expect(app.root.querySelector('a[href^="https:"]')?.getAttribute('href')).toBe(TARGET.redirectTo);
    expect(authApi.confirmLogout).not.toHaveBeenCalled();
    expect(browserNavigation.assign).not.toHaveBeenCalled();
  });

  it.each(['javascript:alert(1)', 'http://evil.example/x', 'https://user:pw@evil.example/'])(
    'never navigates to an unsafe redirect_to (%s), even from the server',
    async (redirectTo) => {
      vi.mocked(authApi.confirmLogout).mockResolvedValue({ clientId: 'suki-rewards', redirectTo });
      app = await mountApp(LINK);
      await confirm();
      expect(authApi.logout).toHaveBeenCalled();
      expect(browserNavigation.assign).not.toHaveBeenCalled();
      expect(text()).toContain(messages.logout.signedOutBody);
      expect(app.root.innerHTML).not.toContain(redirectTo);
    },
  );

  it('stays on this site when the API gives no redirect_to (unregistered URI)', async () => {
    vi.mocked(authApi.confirmLogout).mockResolvedValue({ clientId: 'suki-rewards', redirectTo: null });
    app = await mountApp(LINK);
    await confirm();
    expect(browserNavigation.assign).not.toHaveBeenCalled();
    expect(text()).toContain(messages.logout.signIn);
  });
});

describe('/oauth/logout calls', () => {
  function stub(answer: unknown) {
    const calls: { url: string; init: RequestInit | undefined }[] = [];
    const fetch: typeof globalThis.fetch = async (input, init) => {
      calls.push({ url: String(input), init });
      return new Response(JSON.stringify(answer), { status: 200, headers: { 'Content-Type': 'application/json' } });
    };
    const api = createAuthApi(createHttpClient({ fetch, readCookie: () => 'xsrf-1', locks: null }));
    return { api, calls };
  }

  it('GET sends the parameters in the query (absent ones left out) and reads the answer', async () => {
    const { api, calls } = stub({ client_id: 'suki-rewards', redirect_to: null });
    const target = await api.describeLogout({ clientId: 'suki-rewards', postLogoutRedirectUri: 'https://a.example/x?y=1&z' });
    expect(target).toEqual({ clientId: 'suki-rewards', redirectTo: null });
    const url = new URL(calls[0]!.url, 'https://auth.example');
    expect(url.pathname).toBe('/api/v1/oauth/logout');
    expect([...url.searchParams.entries()]).toEqual([
      ['client_id', 'suki-rewards'],
      ['post_logout_redirect_uri', 'https://a.example/x?y=1&z'],
    ]);
  });

  it('POST sends JSON with the wire names, the XSRF header and the session cookie', async () => {
    const { api, calls } = stub({ client_id: 'suki-rewards', redirect_to: 'https://a.example/x?state=s' });
    await api.confirmLogout(PARAMS);
    const init = calls[0]!.init!;
    expect(init.method).toBe('POST');
    expect(init.credentials).toBe('include');
    expect(new Headers(init.headers).get('X-XSRF-TOKEN')).toBe('xsrf-1');
    expect(JSON.parse(String(init.body))).toEqual({ client_id: 'suki-rewards', post_logout_redirect_uri: BACK, state: 's1' });
  });

  it('rejects an answer of the wrong shape', async () => {
    const { api } = stub({ client_id: 'suki-rewards', redirect_to: 42 });
    await expect(api.describeLogout({ clientId: 'suki-rewards' })).rejects.toThrow();
  });
});
