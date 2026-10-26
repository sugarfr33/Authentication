// T23 acceptance: no token in localStorage, sessionStorage or the store.
import { createPinia, setActivePinia } from 'pinia';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { http } from '@/api';
import { useSessionStore } from '@/stores/session';
import { readSources } from '../helpers/sources';
import { createFakeAuthServer, SECRET_ACCESS_TOKEN, SECRET_REFRESH_TOKEN } from '../helpers/fakeAuthServer';

const sources = Object.fromEntries(readSources(['.ts', '.vue']));

function scriptVisibleState(store: ReturnType<typeof useSessionStore>): string {
  const storage: Record<string, string | null> = {};
  for (const area of [localStorage, sessionStorage]) {
    for (let i = 0; i < area.length; i++) {
      const key = area.key(i);
      if (key !== null) storage[key] = area.getItem(key);
    }
  }
  return JSON.stringify({ state: store.$state, storage, cookie: document.cookie });
}

describe('no token in storage or store', () => {
  let server: ReturnType<typeof createFakeAuthServer>;

  beforeEach(() => {
    localStorage.clear();
    sessionStorage.clear();
    setActivePinia(createPinia());
    server = createFakeAuthServer({ accessValid: false, mirrorXsrfToDocument: true });
    vi.stubGlobal('fetch', server.fetch);
    // jsdom has no Web Locks; the app client then serialises within the tab only.
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    http.setSessionExpiredHandler(null);
  });

  it('keeps tokens out of localStorage, sessionStorage, cookies visible to script and the store through sign-in, refresh and sign-out', async () => {
    const store = useSessionStore();

    await store.signIn('ada@example.com', 'correct horse battery staple');
    expect(store.isAuthenticated).toBe(true);
    let visible = scriptVisibleState(store);
    expect(visible).not.toContain(SECRET_ACCESS_TOKEN);
    expect(visible).not.toContain(SECRET_REFRESH_TOKEN);

    server.expireAccess();
    await store.load(); // 401 -> silent refresh (response carries Set-Cookie with the access token) -> retry
    expect(server.state.refreshCount).toBe(1);
    visible = scriptVisibleState(store);
    expect(visible).not.toContain(SECRET_ACCESS_TOKEN);
    expect(visible).not.toContain(SECRET_REFRESH_TOKEN);

    await store.signOut();
    expect(store.profile).toBeNull();
    expect(localStorage.length).toBe(0);
    expect(sessionStorage.length).toBe(0);
  });

  it('drops unknown fields from API responses, so a token-shaped field never reaches the store', async () => {
    const store = useSessionStore();
    await store.signIn('ada@example.com', 'pw-pw-pw-pw-pw');
    expect(Object.keys(store.profile ?? {}).sort()).toEqual(
      ['displayName', 'email', 'emailVerified', 'id', 'mfaEnabled', 'permissions', 'roles'].sort(),
    );
  });

  it('the store holds the profile and a status flag, nothing else', () => {
    const store = useSessionStore();
    expect(Object.keys(store.$state).sort()).toEqual(['profile', 'status']);
  });

  it('no source file uses web storage, IndexedDB or writes document.cookie', () => {
    const offenders = Object.entries(sources)
      .filter(([, text]) => /\b(localStorage|sessionStorage|indexedDB)\b|document\.cookie\s*=(?!=)/.test(text))
      .map(([file]) => file);
    expect(offenders).toEqual([]);
  });
});
