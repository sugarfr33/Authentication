// Email links carry their one-time token in the URL fragment (#token=...), so it never reaches a server log,
// a proxy or a Referer header (docs/registration-and-email-verification.md, docs/password-reset-and-change.md).
// The page reads it once, keeps it in memory, and removes it from the address bar and history entry.
import type { RouteLocationNormalizedLoaded, Router } from 'vue-router';

const MAX_TOKEN_LENGTH = 1024;

export function readFragmentToken(hash: string): string | null {
  const token = new URLSearchParams(hash.replace(/^#/, '')).get('token')?.trim();
  return token && token.length <= MAX_TOKEN_LENGTH ? token : null;
}

/** Reads the token and replaces the current history entry with the same URL minus the fragment. */
export async function takeFragmentToken(route: RouteLocationNormalizedLoaded, router: Router): Promise<string | null> {
  const token = readFragmentToken(route.hash);
  if (route.hash) await router.replace({ path: route.path, query: route.query, hash: '' });
  return token;
}
