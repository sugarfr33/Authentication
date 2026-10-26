# Consuming-app example: sign in with Central Auth

`centralAuth.ts` is a copy-in example for a Vue SPA **on another domain** that signs its users in through Central
Auth with the authorization code flow and PKCE (`docs/authorization-code-pkce.md`). It is not part of the Central
Auth SPA build. The tests are in `tests/examples/centralAuth.spec.ts`.

## Setup

1. Register the app (`docs/client-applications.md`) with its origin and its exact redirect URI, for example
   `https://app.example.org/callback`.
2. Create one instance and the guard. **Replace every example value** (`issuer`, `clientId`, `redirectUri`,
   `apiOrigins`) with your own: `redirectUri` must be exactly the registered callback URL, character for character.

```ts
// src/auth.ts in the consuming app
import { createCentralAuth, createCentralAuthGuard } from './centralAuth';

export const auth = createCentralAuth({
  issuer: 'https://auth.example.com',
  clientId: 'my-app',
  redirectUri: 'https://app.example.org/callback',
  apiOrigins: ['https://api.example.org'], // authFetch sends the token here and nowhere else
});

// router setup
router.beforeEach(createCentralAuthGuard(auth));
```

3. Add a callback route at the redirect URI. `handleCallback` checks `state` (and `iss` when present) before it
   exchanges the code; on any error show a retry, never the raw query:

```vue
<script setup lang="ts">
import { onMounted, ref } from 'vue';
import { useRouter } from 'vue-router';
import { auth } from '@/auth';

const router = useRouter();
const failed = ref(false);

onMounted(async () => {
  try {
    await router.replace(await auth.handleCallback(window.location.href));
  } catch {
    failed.value = true; // show "Sign-in did not complete. Try again." with a button that calls auth.signIn()
  }
});
</script>
```

4. Mark protected routes with `meta: { requiresAuth: true }`, and call your own API with `auth.authFetch(url)`.

## What it does for you

| Requirement | How |
|---|---|
| PKCE S256 | a 32-byte random verifier, SHA-256 challenge |
| Login CSRF | a random `state` per sign-in, kept for this tab only (sessionStorage) and checked on the callback; the stored state and verifier are deleted when the callback is read |
| Tokens | access and refresh tokens in memory only; nothing in localStorage, sessionStorage or cookies |
| Refresh | rotated with `grant_type=refresh_token`, one at a time, 60 s before expiry |
| After a reload | memory is empty, so the guard starts `/authorize` again; the Central Auth session makes it a quick redirect |
| Return path | same-origin path only (also after dot-segment normalisation, so `/.//evil.com` is refused); anything else becomes `/` |
| Mix-up | a callback whose `iss` is not the configured issuer is refused (RFC 9207) |
| Token leaks | `authFetch` refuses any URL outside `apiOrigins` |

## Also required in the app

- **Content-Security-Policy header**: tokens in memory are only as safe as the page's scripts. Send at least
  `default-src 'self'; script-src 'self'; connect-src 'self' https://auth.example.com https://api.example.org;
  frame-ancestors 'none'; base-uri 'none'; form-action 'self'` (adapt the origins), and no inline scripts.
- No third-party scripts on pages that hold tokens, and never log `getAccessToken()` results.

The app's own API validates the access token (audience = the app's audience, `app:{clientId}:{role}` roles); see
`docs/t22-client-extension.md` for the .NET side.
