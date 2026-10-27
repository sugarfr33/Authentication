// A stubbed Central Auth API for the browser tests: same paths, status codes, problem titles and body shapes as the
// real one (backend Auth.Api endpoints and Auth.Contracts; contract.e2e.ts checks them against the C# source), no
// backend and no database. Unsafe requests must carry the X-XSRF-TOKEN header, as the real antiforgery check
// requires. A call the stub does not know is answered 404 and recorded, and the fixture fails the test.
import type { Page, Route } from '@playwright/test';

export const XSRF_TOKEN = 'e2e-xsrf-token';
export const PASSWORD = 'Correct horse 42';
/** Has two-step verification: login answers 202 {mfa_required:true}. */
export const MFA_USER = { email: 'grace@example.test', password: PASSWORD } as const;
/** No two-step verification: login answers 200 with the profile. */
export const PLAIN_USER = { email: 'alan@example.test', password: PASSWORD } as const;
export const TOTP_CODE = '123456';
export const RECOVERY_CODE = 'ABCDEFGH23'; // 10 characters of the API's recovery-code alphabet
export const RESET_TOKEN = 'e2e-reset-token';
export const EXPIRED_RESET_TOKEN = 'e2e-expired-reset-token';
/** Register answers 400 ValidationProblem for this password, as the real policy does for a common one. */
export const COMMON_PASSWORD = 'password1234';

/** Problem titles and messages copied from the API (contract.e2e.ts keeps them in step). */
export const API_TEXT = {
  invalidCredentials: 'Invalid email or password.',
  invalidFactor: 'Invalid or expired verification.',
  authenticationRequired: 'Authentication required.',
  resetLinkInvalid: 'The reset link is invalid or has expired.',
  registerInvalid: 'The registration request is invalid.',
  passwordCommon: 'Password is too common; choose a less predictable one.',
  registerAccepted: 'Check your inbox: we sent you an email to finish signing up.',
  forgotAccepted: 'If an account can reset its password with this address, we sent it an email with a link.',
  tooManyRequests: 'Too many requests.',
} as const;

/** UserProfileResponse (Auth.Contracts), camelCase as the API writes it. */
export interface Profile {
  readonly id: string;
  readonly email: string;
  readonly emailVerified: boolean;
  readonly displayName: string;
  readonly mfaEnabled: boolean;
  readonly roles: readonly string[];
  readonly permissions: readonly string[];
}

export const PROFILE: Profile = {
  id: '00000000-0000-4000-8000-000000000001',
  email: MFA_USER.email,
  emailVerified: true,
  displayName: 'Grace Hopper',
  mfaEnabled: true,
  roles: ['User'],
  permissions: [],
};

export const PLAIN_PROFILE: Profile = {
  id: '00000000-0000-4000-8000-000000000002',
  email: PLAIN_USER.email,
  emailVerified: true,
  displayName: 'Alan Turing',
  mfaEnabled: false,
  roles: ['User'],
  permissions: [],
};

/** A one-off failure for the next call to an endpoint: an HTTP problem, or the connection failing. */
export type Fault = { readonly status: number; readonly title: string; readonly retryAfterSeconds?: number } | 'network';

export interface MockApi {
  /** "METHOD /path" of every API call, in order. */
  readonly calls: string[];
  /** Calls the stub does not implement, and requests to any other origin (aborted). */
  readonly unexpected: string[];
  /** Who /me answers for; null when signed out. */
  signedIn: Profile | null;
  /** When true, POST /refresh succeeds (204) and signs PROFILE in, as a valid refresh cookie would. */
  refreshable: boolean;
  /** Answers the next call to `key` ("METHOD /api/...") with this fault instead of the normal answer. */
  failNext(key: string, fault: Fault): void;
}

function json(route: Route, status: number, body: unknown): Promise<void> {
  return route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
}

function problem(route: Route, status: number, title: string, headers: Record<string, string> = {}): Promise<void> {
  return route.fulfill({
    status,
    headers,
    contentType: 'application/problem+json',
    body: JSON.stringify({ type: 'about:blank', title, status }),
  });
}

/** ASP.NET Core ValidationProblem: `errors` maps a field to its messages. */
function validationProblem(route: Route, title: string, errors: Record<string, string[]>): Promise<void> {
  return route.fulfill({
    status: 400,
    contentType: 'application/problem+json',
    body: JSON.stringify({ type: 'https://tools.ietf.org/html/rfc9110#section-15.5.1', title, status: 400, errors }),
  });
}

function field(body: unknown, key: string): unknown {
  return typeof body === 'object' && body !== null ? (body as Record<string, unknown>)[key] : undefined;
}

export async function installMockApi(page: Page, baseURL: string): Promise<MockApi> {
  const faults = new Map<string, Fault>();
  const api: MockApi = {
    calls: [],
    unexpected: [],
    signedIn: null,
    refreshable: false,
    failNext(key, fault) {
      faults.set(key, fault);
    },
  };
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

    const fault = faults.get(key);
    if (fault !== undefined) {
      faults.delete(key);
      if (fault === 'network') return route.abort('failed');
      const headers: Record<string, string> = fault.retryAfterSeconds === undefined ? {} : { 'Retry-After': String(fault.retryAfterSeconds) };
      return problem(route, fault.status, fault.title, headers);
    }

    const body: unknown = method === 'GET' ? null : request.postDataJSON();

    switch (key) {
      case 'GET /api/v1/auth/me':
        return api.signedIn ? json(route, 200, api.signedIn) : problem(route, 401, API_TEXT.authenticationRequired);
      case 'POST /api/v1/auth/refresh':
        if (api.refreshable) {
          api.signedIn = PROFILE;
          return route.fulfill({ status: 204 });
        }
        return problem(route, 401, API_TEXT.authenticationRequired);
      case 'POST /api/v1/auth/login': {
        // One generic 401 for every wrong combination, whether or not the account exists.
        const email = field(body, 'email');
        if (field(body, 'password') !== PASSWORD) return problem(route, 401, API_TEXT.invalidCredentials);
        if (email === MFA_USER.email) return json(route, 202, { mfa_required: true });
        if (email === PLAIN_USER.email) {
          api.signedIn = PLAIN_PROFILE;
          return json(route, 200, PLAIN_PROFILE);
        }
        return problem(route, 401, API_TEXT.invalidCredentials);
      }
      case 'POST /api/v1/auth/mfa/verify': {
        const code = field(body, 'code');
        const recovery = field(body, 'isRecoveryCode');
        if ((code === TOTP_CODE && recovery === false) || (code === RECOVERY_CODE && recovery === true)) {
          api.signedIn = PROFILE;
          return json(route, 200, PROFILE);
        }
        return problem(route, 401, API_TEXT.invalidFactor);
      }
      case 'POST /api/v1/auth/register':
        return field(body, 'password') === COMMON_PASSWORD
          ? validationProblem(route, API_TEXT.registerInvalid, { password: [API_TEXT.passwordCommon] })
          : json(route, 202, { message: API_TEXT.registerAccepted });
      case 'POST /api/v1/auth/forgot-password':
        return json(route, 202, { message: API_TEXT.forgotAccepted });
      case 'POST /api/v1/auth/reset-password':
        // An expired token and an unknown one get the same answer, as in the API.
        return field(body, 'token') === RESET_TOKEN ? route.fulfill({ status: 204 }) : problem(route, 400, API_TEXT.resetLinkInvalid);
      case 'GET /api/v1/auth/sessions':
        return json(route, 200, []);
      case 'POST /api/v1/auth/logout':
        api.signedIn = null;
        return route.fulfill({ status: 204 });
      default:
        api.unexpected.push(key);
        return problem(route, 404, 'Not Found');
    }
  });

  return api;
}

/** A 429 as the API's rate limiter writes it (ProblemDetails plus Retry-After). */
export function tooManyRequests(retryAfterSeconds: number): Fault {
  return { status: 429, title: API_TEXT.tooManyRequests, retryAfterSeconds };
}
