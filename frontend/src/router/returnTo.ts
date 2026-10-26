// Where to go after signing in. Only same-origin paths are followed (no open redirect):
// - an app path on this SPA's origin ("/account/mfa?x=1"), via the router;
// - the API's own OAuth resume path, which the server puts in `returnTo` when /oauth/authorize finds no session
//   (docs/authorization-code-pkce.md): it must be the authorize path plus a query, and is opened as a full
//   navigation on the API origin; the server re-validates every parameter when the browser comes back.
// Anything else (absolute URLs, "//host", backslashes, control characters, other /api paths, sign-in pages) is
// ignored and the user lands on the account page.
import type { Router } from 'vue-router';
import { apiBaseUrl, OAUTH_AUTHORIZE_PATH } from '@/api';

export type ReturnTarget = { readonly kind: 'app'; readonly path: string } | { readonly kind: 'oauth'; readonly url: string };

export const OAUTH_RESUME_PREFIX = `${OAUTH_AUTHORIZE_PATH}?`;
const MAX_LENGTH = 4096;
/** Pages that make no sense as a destination after signing in (and could loop). */
const NOT_A_DESTINATION = ['/login', '/register', '/forgot-password', '/reset-password', '/verify-email'];

function currentOrigin(): string {
  return window.location.origin;
}

function apiOrigin(): string {
  return apiBaseUrl === '' ? currentOrigin() : apiBaseUrl;
}

/** Returns a safe target, or null when the value must be ignored. */
export function parseReturnTo(raw: unknown, appOrigin: string = currentOrigin(), oauthOrigin: string = apiOrigin()): ReturnTarget | null {
  const value = Array.isArray(raw) ? raw[0] : raw;
  if (typeof value !== 'string' || value.length === 0 || value.length > MAX_LENGTH) return null;
  // A relative path only: one leading slash, then no second slash or backslash that browsers read as a host.
  if (!value.startsWith('/') || value.startsWith('//') || value.includes('\\')) return null;
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f\s]/.test(value)) return null;

  if (value.startsWith(OAUTH_RESUME_PREFIX)) {
    const url = new URL(value, oauthOrigin);
    if (url.origin !== new URL(oauthOrigin).origin || url.pathname !== OAUTH_AUTHORIZE_PATH) return null;
    return { kind: 'oauth', url: url.href };
  }

  let url: URL;
  try {
    url = new URL(value, appOrigin);
  } catch {
    return null;
  }
  if (url.origin !== new URL(appOrigin).origin) return null;
  if (url.pathname.startsWith('/api/')) return null;
  if (NOT_A_DESTINATION.some((page) => url.pathname === page || url.pathname.startsWith(`${page}/`))) return null;
  return { kind: 'app', path: `${url.pathname}${url.search}${url.hash}` };
}

/** Keeps a valid returnTo when moving between sign-in pages (login -> MFA). */
export function returnToQuery(raw: unknown): { returnTo?: string } {
  const value = Array.isArray(raw) ? raw[0] : raw;
  return typeof value === 'string' && parseReturnTo(value) !== null ? { returnTo: value } : {};
}

/** Full-page navigation, kept in one place so tests can observe it. */
export const browserNavigation = {
  assign(url: string): void {
    window.location.assign(url);
  },
};

export async function continueAfterSignIn(router: Router, raw: unknown): Promise<void> {
  const target = parseReturnTo(raw);
  if (target?.kind === 'oauth') {
    browserNavigation.assign(target.url);
    return;
  }
  await router.replace(target?.path ?? '/');
}
