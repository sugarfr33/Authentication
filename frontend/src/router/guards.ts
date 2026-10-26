// Route guards. They decide what to SHOW; the API decides what is ALLOWED (every endpoint re-checks the session).
// - meta.requiresAuth: an anonymous visitor goes to sign-in with returnTo = the page they asked for.
// - meta.guestOnly: a signed-in visitor skips the sign-in pages (to a safe returnTo, else the account page).
// The session is loaded once (GET /auth/me, with the silent refresh inside the API layer) before the first decision.
import type { NavigationGuardReturn, RouteLocationNormalized, Router } from 'vue-router';
import { browserNavigation, parseReturnTo } from './returnTo';

declare module 'vue-router' {
  interface RouteMeta {
    requiresAuth?: boolean;
    guestOnly?: boolean;
  }
}

/** The part of the session store the guard needs (keeps it testable without Pinia). */
export interface GuardSession {
  readonly status: 'unknown' | 'loading' | 'authenticated' | 'anonymous';
  readonly isAuthenticated: boolean;
  load(): Promise<void>;
}

export const LOGIN_ROUTE = 'login';

export function loginRedirect(to: Pick<RouteLocationNormalized, 'fullPath'>) {
  return { name: LOGIN_ROUTE, query: { returnTo: to.fullPath } } as const;
}

async function ensureLoaded(session: GuardSession): Promise<void> {
  // 'loading': another caller started the check; load() returns that same request.
  if (session.status !== 'unknown' && session.status !== 'loading') return;
  try {
    await session.load();
  } catch {
    // Network or server trouble: status stays 'unknown'. Protected pages then send the user to sign-in,
    // which works without a session; guest pages simply render.
  }
}

export function createAuthGuard(session: GuardSession) {
  return async function authGuard(to: RouteLocationNormalized): Promise<NavigationGuardReturn> {
    if (!to.meta.requiresAuth && !to.meta.guestOnly) return true;
    await ensureLoaded(session);

    if (to.meta.requiresAuth && !session.isAuthenticated) return loginRedirect(to);

    if (to.meta.guestOnly && session.isAuthenticated) {
      const target = parseReturnTo(to.query.returnTo);
      if (target?.kind === 'oauth') {
        browserNavigation.assign(target.url);
        return false;
      }
      return target?.path ?? '/';
    }
    return true;
  };
}

export function installAuthGuard(router: Router, session: GuardSession): void {
  router.beforeEach(createAuthGuard(session));
}

/** After a silent refresh found the session over: leave a protected page for sign-in, keeping the way back. */
export async function leaveProtectedPage(router: Router): Promise<void> {
  const current = router.currentRoute.value;
  if (current.meta.requiresAuth) await router.replace(loginRedirect(current));
}
