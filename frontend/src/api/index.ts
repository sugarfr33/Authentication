import { createAuthApi } from './auth';
import { resolveApiBaseUrl } from './config';
import { createHttpClient } from './http';

/** The app-wide client. Same origin by default (the Vite dev server proxies /api). */
export const http = createHttpClient({
  baseUrl: resolveApiBaseUrl(import.meta.env.VITE_API_BASE_URL, import.meta.env.PROD),
});

export const authApi = createAuthApi(http);

/** Lets the app react (clear the profile, go to sign-in) when a silent refresh finds the session over. */
export function onSessionExpired(handler: (() => void) | null): void {
  http.setSessionExpiredHandler(handler);
}

export { ApiError, isApiError } from './errors';
export type { AuthApi } from './auth';
export type { ActiveSession, LoginResult, MfaEnrollment, RegisterInput, UserProfile } from './types';
