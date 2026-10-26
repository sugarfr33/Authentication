// Holds the signed-in user's PROFILE only. No token, cookie or secret ever goes in here (tested):
// the session itself lives in HttpOnly cookies the browser manages.

import { defineStore } from 'pinia';
import { computed, ref } from 'vue';
import { authApi, isApiError } from '@/api';
import type { LoginResult, UserProfile } from '@/api';

export type SessionStatus = 'unknown' | 'loading' | 'authenticated' | 'anonymous';

export const useSessionStore = defineStore('session', () => {
  const profile = ref<UserProfile | null>(null);
  const status = ref<SessionStatus>('unknown');

  const isAuthenticated = computed(() => status.value === 'authenticated' && profile.value !== null);

  function setProfile(next: UserProfile): void {
    profile.value = next;
    status.value = 'authenticated';
  }

  function clear(): void {
    profile.value = null;
    status.value = 'anonymous';
  }

  let inFlight: Promise<void> | null = null;

  /**
   * Asks the API who is signed in (a silent refresh happens inside the API layer when needed).
   * Concurrent callers (a guard and a page, two navigations) share one request.
   */
  function load(): Promise<void> {
    inFlight ??= doLoad().finally(() => {
      inFlight = null;
    });
    return inFlight;
  }

  async function doLoad(): Promise<void> {
    status.value = 'loading';
    try {
      setProfile(await authApi.getProfile());
    } catch (error) {
      if (isApiError(error) && error.isUnauthorized) {
        clear();
        return;
      }
      status.value = 'unknown';
      throw error;
    }
  }

  async function signIn(email: string, password: string): Promise<LoginResult> {
    const result = await authApi.login(email, password);
    if (result.kind === 'signed-in') setProfile(result.profile);
    return result;
  }

  async function completeMfa(code: string, isRecoveryCode: boolean): Promise<void> {
    setProfile(await authApi.verifyMfa(code, isRecoveryCode));
  }

  /** Always clears the local profile, even when the API call fails (the server also always expires the cookies). */
  async function signOut(): Promise<void> {
    try {
      await authApi.logout();
    } finally {
      clear();
    }
  }

  return { profile, status, isAuthenticated, setProfile, clear, load, signIn, completeMfa, signOut };
});
