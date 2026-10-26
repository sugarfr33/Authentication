// The only place the SPA talks to the network (enforced by tests/architecture/api-boundary.spec.ts).
//
// Session model (docs/sign-in-and-sessions.md, docs/browser-security.md):
// - Tokens live only in HttpOnly cookies; this module never sees, reads or stores one.
// - Every unsafe request sends X-XSRF-TOKEN with the value of the script-readable XSRF-TOKEN cookie.
//   Antiforgery tokens are bound to the user, so after the session changes a fresh pair is needed:
//   any GET under /api issues one.
// - Silent refresh (T15 SPA flow): GET /auth/me first (it answers 200 if the session is fine, or another
//   tab already refreshed, and otherwise hands out an anonymous XSRF pair), then POST /auth/refresh.
//   Refresh is single flight inside a tab and serialised across tabs with a Web Lock, because two tabs
//   refreshing outside the server's grace window look like token reuse and end the session.

import { ANTIFORGERY_FAILURE_TITLE, ApiError, parseProblem, parseRetryAfter } from './errors';

export type HttpMethod = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';

/** The part of the Web Locks API we use (navigator.locks). */
export interface LockManagerLike {
  request<T>(name: string, callback: () => Promise<T>): Promise<T>;
}

/**
 * - `active`: the session is fine (nothing to do, or another tab refreshed first).
 * - `refreshed`: this tab rotated the session.
 * - `expired`: the session is over; the user must sign in again.
 * - `unavailable`: the API could not be reached or failed; the session state is unknown.
 */
export type RecoveryOutcome = 'active' | 'refreshed' | 'expired' | 'unavailable';

export interface RequestOptions {
  method?: HttpMethod;
  /** Sent as JSON. */
  body?: unknown;
  /**
   * `session` (default): the call needs the signed-in session, so a 401 triggers one silent refresh and
   * one retry. `anonymous`: sign-in style calls that must never trigger a refresh.
   */
  auth?: 'session' | 'anonymous';
  signal?: AbortSignal;
}

export interface HttpClient {
  request<T>(path: string, options?: RequestOptions): Promise<T>;
  /** Single-flight, cross-tab-serialised session recovery. */
  recoverSession(): Promise<RecoveryOutcome>;
  /** Called once per recovery that ends in `expired`. */
  setSessionExpiredHandler(handler: (() => void) | null): void;
}

export interface HttpClientOptions {
  /** API origin, e.g. https://auth.example.com. Empty: same origin. */
  baseUrl?: string;
  fetch?: typeof fetch;
  /** Web Locks implementation; `null` disables cross-tab serialisation. Defaults to navigator.locks. */
  locks?: LockManagerLike | null;
  readCookie?: (name: string) => string | null;
  onSessionExpired?: () => void;
  /**
   * Each request made during session recovery (the /auth/me probe, /auth/refresh) is aborted after this long
   * and the recovery ends as `unavailable`, so a hung request cannot hold the refresh lock and block every
   * later 401 in this tab and the others. Default 15 s.
   */
  recoveryTimeoutMs?: number;
}

export const API_PREFIX = '/api/v1';
export const XSRF_COOKIE = 'XSRF-TOKEN';
export const XSRF_HEADER = 'X-XSRF-TOKEN';
export const REFRESH_LOCK_NAME = 'central-auth:session-refresh';
const PROBE_PATH = '/auth/me';
const REFRESH_PATH = '/auth/refresh';
export const DEFAULT_RECOVERY_TIMEOUT_MS = 15_000;

interface RawResponse {
  readonly status: number;
  readonly ok: boolean;
  readonly headers: Headers;
  readonly body: unknown;
}

/** Reads one cookie that script is allowed to see (only XSRF-TOKEN is ever asked for). */
export function readDocumentCookie(name: string): string | null {
  if (typeof document === 'undefined') return null;
  for (const part of document.cookie.split(';')) {
    const eq = part.indexOf('=');
    if (eq < 0 || part.slice(0, eq).trim() !== name) continue;
    const value = part.slice(eq + 1).trim();
    try {
      return decodeURIComponent(value);
    } catch {
      return value;
    }
  }
  return null;
}

function defaultLocks(): LockManagerLike | null {
  if (typeof navigator === 'undefined' || !('locks' in navigator) || !navigator.locks) return null;
  const manager = navigator.locks;
  return { request: (name, callback) => manager.request(name, () => callback()) };
}

async function readBody(response: Response): Promise<unknown> {
  if (response.status === 204) return undefined;
  const text = await response.text();
  if (text.length === 0) return undefined;
  const contentType = response.headers.get('Content-Type') ?? '';
  if (!contentType.includes('json')) return undefined;
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return undefined;
  }
}

function isAntiforgeryFailure(response: RawResponse): boolean {
  return response.status === 400 && parseProblem(response.body).title === ANTIFORGERY_FAILURE_TITLE;
}

function toApiError(response: RawResponse): ApiError {
  const problem = parseProblem(response.body);
  return new ApiError({
    status: response.status,
    title: problem.title,
    detail: problem.detail,
    fieldErrors: problem.fieldErrors,
    traceId: problem.traceId,
    retryAfterSeconds: parseRetryAfter(response.headers.get('Retry-After')),
  });
}

export function createHttpClient(options: HttpClientOptions = {}): HttpClient {
  const baseUrl = (options.baseUrl ?? '').replace(/\/+$/, '') + API_PREFIX;
  const doFetch: typeof fetch = options.fetch ?? ((input, init) => globalThis.fetch(input, init));
  const locks = options.locks === undefined ? defaultLocks() : options.locks;
  const readCookie = options.readCookie ?? readDocumentCookie;
  let onExpired: (() => void) | null = options.onSessionExpired ?? null;
  let inflight: Promise<RecoveryOutcome> | null = null;
  const recoveryTimeoutMs = options.recoveryTimeoutMs ?? DEFAULT_RECOVERY_TIMEOUT_MS;

  async function send(path: string, method: HttpMethod, body?: unknown, signal?: AbortSignal): Promise<RawResponse> {
    const headers: Record<string, string> = { Accept: 'application/json' };
    let payload: string | undefined;
    if (body !== undefined) {
      headers['Content-Type'] = 'application/json';
      payload = JSON.stringify(body);
    }
    if (method !== 'GET') {
      const xsrf = readCookie(XSRF_COOKIE);
      if (xsrf !== null) headers[XSRF_HEADER] = xsrf;
    }

    let response: Response;
    try {
      const init: RequestInit = {
        method,
        headers,
        credentials: 'include',
        cache: 'no-store',
        redirect: 'error',
      };
      if (payload !== undefined) init.body = payload;
      if (signal !== undefined) init.signal = signal;
      response = await doFetch(baseUrl + path, init);
    } catch (error) {
      if (signal?.aborted) throw error;
      throw new ApiError({ status: 0 });
    }
    return { status: response.status, ok: response.ok, headers: response.headers, body: await readBody(response) };
  }

  /** Like send, but bounded by recoveryTimeoutMs; a network failure or timeout is `null` instead of an exception. */
  async function trySend(path: string, method: HttpMethod): Promise<RawResponse | null> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), recoveryTimeoutMs);
    try {
      return await send(path, method, undefined, controller.signal);
    } catch {
      return null;
    } finally {
      clearTimeout(timer);
    }
  }

  /** Any GET under /api hands out an XSRF pair that fits the browser's current identity. */
  async function primeAntiforgery(): Promise<RawResponse | null> {
    return trySend(PROBE_PATH, 'GET');
  }

  async function attemptRecovery(): Promise<RecoveryOutcome> {
    const probe = await primeAntiforgery();
    if (probe === null) return 'unavailable';
    if (probe.status === 200) return 'active';
    if (probe.status !== 401) return 'unavailable';

    // Anonymous now, holding an anonymous XSRF pair: refresh. One retry after a stale-pair 400.
    for (let attempt = 0; attempt < 2; attempt++) {
      const refresh = await trySend(REFRESH_PATH, 'POST');
      if (refresh === null) return 'unavailable';
      if (refresh.ok) return 'refreshed';
      if (refresh.status === 401) return 'expired';
      if (refresh.status === 409) {
        // Lost a concurrent refresh; the winner's cookies are already in the shared cookie jar.
        const check = await primeAntiforgery();
        if (check?.status === 200) return 'active';
        return check?.status === 401 ? 'expired' : 'unavailable';
      }
      if (attempt === 0 && isAntiforgeryFailure(refresh)) {
        const check = await primeAntiforgery();
        if (check?.status === 200) return 'active';
        continue;
      }
      return 'unavailable';
    }
    return 'unavailable';
  }

  async function recoverExclusively(): Promise<RecoveryOutcome> {
    const outcome = locks ? await locks.request(REFRESH_LOCK_NAME, attemptRecovery) : await attemptRecovery();
    if (outcome === 'expired') onExpired?.();
    return outcome;
  }

  function recoverSession(): Promise<RecoveryOutcome> {
    if (inflight === null) {
      inflight = recoverExclusively().finally(() => {
        inflight = null;
      });
    }
    return inflight;
  }

  async function request<T>(path: string, requestOptions: RequestOptions = {}): Promise<T> {
    const method = requestOptions.method ?? 'GET';
    const auth = requestOptions.auth ?? 'session';
    const signal = requestOptions.signal;
    const unsafe = method !== 'GET';

    if (unsafe && readCookie(XSRF_COOKIE) === null) await primeAntiforgery();

    // Replaying the request once (same body) is safe because both triggers mean the server did NOT run the
    // endpoint: the antiforgery 400 comes from BrowserProtectionMiddleware and the 401 from authentication,
    // both before any handler. If an endpoint ever answers 400/401 AFTER doing work, it must not be called
    // with auth 'session' through this path, or it needs an idempotency key (docs/ui-kit.md, audit L3).
    let response = await send(path, method, requestOptions.body, signal);
    let retried = false;

    if (unsafe && isAntiforgeryFailure(response)) {
      // The XSRF pair was issued to another identity (session ended, refreshed or changed elsewhere).
      if (auth === 'session') {
        const outcome = await recoverSession();
        if (outcome === 'expired') throw new ApiError({ status: 401 });
        if (outcome === 'unavailable') throw toApiError(response);
      } else {
        await primeAntiforgery();
      }
      response = await send(path, method, requestOptions.body, signal);
      retried = true;
    }

    if (response.status === 401 && auth === 'session' && !retried) {
      const outcome = await recoverSession();
      if (outcome === 'active' || outcome === 'refreshed') {
        response = await send(path, method, requestOptions.body, signal);
      }
    }

    if (!response.ok) throw toApiError(response);
    return response.body as T;
  }

  return {
    request,
    recoverSession,
    setSessionExpiredHandler(handler) {
      onExpired = handler;
    },
  };
}
