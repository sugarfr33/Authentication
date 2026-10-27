// A stubbed Central Auth API for the browser tests: same paths, status codes and body shapes as the real one
// (docs/admin-api.md, docs/sign-in-and-sessions.md), no backend and no database. Unsafe requests must carry the
// X-XSRF-TOKEN header, as the real antiforgery check requires. A call the stub does not know is answered 404 and
// recorded, and the fixture fails the test.
import type { Page, Route } from '@playwright/test';

export const XSRF_TOKEN = 'e2e-xsrf-token';
export const PASSWORD = 'Correct horse 42';
export const MFA_USER = { email: 'grace@example.test', password: PASSWORD } as const;
export const TOTP_CODE = '123456';
export const RESET_TOKEN = 'e2e-reset-token';

export const PROFILE = {
  id: '00000000-0000-4000-8000-000000000001',
  email: MFA_USER.email,
  emailVerified: true,
  displayName: 'Grace Hopper',
  mfaEnabled: true,
  roles: ['User'],
  permissions: [],
} as const;

export interface MockApi {
  /** "METHOD /path" of every API call, in order. */
  readonly calls: string[];
  /** Calls the stub does not implement, and requests to any other origin (aborted). */
  readonly unexpected: string[];
  signedIn: boolean;
}

function json(route: Route, status: number, body: unknown): Promise<void> {
  return route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
}

function problem(route: Route, status: number, title: string): Promise<void> {
  return route.fulfill({
    status,
    contentType: 'application/problem+json',
    body: JSON.stringify({ type: 'about:blank', title, status }),
  });
}

function field(body: unknown, key: string): unknown {
  return typeof body === 'object' && body !== null ? (body as Record<string, unknown>)[key] : undefined;
}

export async function installMockApi(page: Page, baseURL: string): Promise<MockApi> {
  const api: MockApi = { calls: [], unexpected: [], signedIn: false };
  const origin = new URL(baseURL).origin;

  // Script-readable antiforgery cookie, as the API hands out on any GET.
  await page.context().addCookies([{ name: 'XSRF-TOKEN', value: XSRF_TOKEN, url: origin }]);

  // Only the dev server may be reached: no real API, no CDN, nothing else.
  await page.context().route('**/*', (route) => {
    const url = new URL(route.request().url());
    if (url.origin === origin) return route.continue();
    api.unexpected.push(`${route.request().method()} ${url.href}`);
    return route.abort('blockedbyclient');
  });

  await page.route(`${origin}/api/**`, (route) => {
    const request = route.request();
    const method = request.method();
    const path = new URL(request.url()).pathname;
    const key = `${method} ${path}`;
    api.calls.push(key);

    if (method !== 'GET' && request.headers()['x-xsrf-token'] !== XSRF_TOKEN) {
      return problem(route, 400, 'Missing or invalid antiforgery token.');
    }
    const body: unknown = method === 'GET' ? null : request.postDataJSON();

    switch (key) {
      case 'GET /api/v1/auth/me':
        return api.signedIn ? json(route, 200, PROFILE) : problem(route, 401, 'Unauthorized');
      case 'POST /api/v1/auth/refresh':
        return problem(route, 401, 'Unauthorized');
      case 'POST /api/v1/auth/login':
        // Only the MFA user exists; every other combination gets the one generic 401.
        return field(body, 'email') === MFA_USER.email && field(body, 'password') === MFA_USER.password
          ? json(route, 202, { mfa_required: true })
          : problem(route, 401, 'Unauthorized');
      case 'POST /api/v1/auth/mfa/verify':
        if (field(body, 'code') === TOTP_CODE && field(body, 'isRecoveryCode') === false) {
          api.signedIn = true;
          return json(route, 200, PROFILE);
        }
        return problem(route, 401, 'Unauthorized');
      case 'POST /api/v1/auth/register':
      case 'POST /api/v1/auth/forgot-password':
        return json(route, 202, {});
      case 'POST /api/v1/auth/reset-password':
        return field(body, 'token') === RESET_TOKEN ? route.fulfill({ status: 204 }) : problem(route, 400, 'Invalid or expired token.');
      case 'GET /api/v1/auth/sessions':
        return json(route, 200, []);
      case 'POST /api/v1/auth/logout':
        api.signedIn = false;
        return route.fulfill({ status: 204 });
      default:
        api.unexpected.push(key);
        return problem(route, 404, 'Not Found');
    }
  });

  return api;
}
