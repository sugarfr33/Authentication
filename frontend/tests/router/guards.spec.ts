// T24: the guard sends unauthenticated users to sign-in (with a safe way back) and skips sign-in pages when signed in.
import { afterEach, describe, expect, it, vi } from 'vitest';
import { ApiError, authApi, type UserProfile } from '@/api';
import { browserNavigation } from '@/router/returnTo';
import { mountApp, type MountedApp } from '../helpers/app';

const PROFILE: UserProfile = {
  id: 'u1',
  email: 'ana@example.com',
  emailVerified: true,
  displayName: 'Ana',
  mfaEnabled: false,
  roles: [],
  permissions: [],
};

let app: MountedApp | null = null;
afterEach(() => {
  app?.unmount();
  app = null;
});

describe('auth guard', () => {
  it('redirects an anonymous visitor of a protected page to sign-in with returnTo', async () => {
    vi.spyOn(authApi, 'getProfile').mockRejectedValue(new ApiError({ status: 401 }));
    app = await mountApp('/account/mfa?x=1');
    expect(app.router.currentRoute.value.name).toBe('login');
    expect(app.router.currentRoute.value.query.returnTo).toBe('/account/mfa?x=1');
    expect(app.root.querySelector('h1')?.textContent).toContain('Sign in');
  });

  it('also redirects when the session cannot be checked (network), without throwing', async () => {
    vi.spyOn(authApi, 'getProfile').mockRejectedValue(new ApiError({ status: 0 }));
    app = await mountApp('/');
    expect(app.router.currentRoute.value.name).toBe('login');
  });

  it('lets a signed-in user through', async () => {
    vi.spyOn(authApi, 'getProfile').mockResolvedValue(PROFILE);
    app = await mountApp('/account/mfa');
    expect(app.router.currentRoute.value.name).toBe('mfa-enroll');
  });

  it('sends a signed-in user away from sign-in pages, to a safe returnTo only', async () => {
    vi.spyOn(authApi, 'getProfile').mockResolvedValue(PROFILE);
    app = await mountApp('/login?returnTo=%2Faccount%2Fmfa');
    expect(app.router.currentRoute.value.fullPath).toBe('/account/mfa');
    await app.router.push('/register?returnTo=https%3A%2F%2Fevil.example');
    expect(app.router.currentRoute.value.fullPath).toBe('/');
  });

  it('resumes an OAuth authorization with a full navigation', async () => {
    vi.spyOn(authApi, 'getProfile').mockResolvedValue(PROFILE);
    const assign = vi.spyOn(browserNavigation, 'assign').mockImplementation(() => undefined);
    app = await mountApp('/');
    await app.router.push('/login?returnTo=' + encodeURIComponent('/api/v1/oauth/authorize?client_id=a&state=s'));
    expect(app.router.currentRoute.value.name).toBe('home');
    expect(assign).toHaveBeenCalledWith(`${window.location.origin}/api/v1/oauth/authorize?client_id=a&state=s`);
  });

  it('reset and verify pages are open to everyone', async () => {
    vi.spyOn(authApi, 'getProfile').mockRejectedValue(new ApiError({ status: 401 }));
    app = await mountApp('/reset-password');
    expect(app.router.currentRoute.value.name).toBe('reset-password');
    await app.router.push('/verify-email');
    expect(app.router.currentRoute.value.name).toBe('verify-email');
  });
});
