# Central Auth frontend

Vue 3 (`<script setup>`, TypeScript strict), Vite, Pinia and Vue Router. There is no UI library: the kit
and tokens are described in [docs/ui-kit.md](../docs/ui-kit.md).

```sh
npm ci             # lockfile install; .npmrc sets ignore-scripts and exact versions
npm run dev        # http://localhost:5173, /api proxied to Auth.Api (http://localhost:5094)
npm test           # Vitest (jsdom)
npm run build      # vue-tsc strict type-check, then a production build that fails if dev-only code ships
```

## Dev setup against the API

- Start Auth.Api with its `http` profile (port 5094), or set `VITE_DEV_API_TARGET` in `.env.local`.
- The proxy keeps the browser's `Origin` (`http://localhost:5173`), so add it to the API's
  `BrowserProtection:TrustedOrigins` for Development (user secrets or `appsettings.Development.json`).
  Otherwise POSTs get 403.
- Outside dev, set `VITE_API_BASE_URL` to the API origin, or serve the SPA from the same origin.
- The UI kit gallery is at `/dev/gallery` (dev server only).

## Rules the code follows (and tests enforce)

| Rule | Where | Test |
|---|---|---|
| Network calls only in `src/api`, always `credentials: 'include'` | `src/api/http.ts` | `tests/architecture/api-boundary.spec.ts` |
| No token in localStorage, sessionStorage, script-visible cookies or the store; the store holds the profile only | `src/stores/session.ts`, `src/api/auth.ts` (copies known fields only) | `tests/security/no-token-storage.spec.ts` |
| Silent refresh: GET `/auth/me` first, then POST `/auth/refresh`; single flight per tab; serialised across tabs with a Web Lock (`navigator.locks`); 409 and stale-XSRF 400 handled | `src/api/http.ts` | `tests/api/refresh.spec.ts` |
| `X-XSRF-TOKEN` on every unsafe request; a fresh pair is fetched when missing or stale | `src/api/http.ts` | `tests/api/refresh.spec.ts` |
| IP and user agent rendered as text, never as HTML | `BaseTable` | `tests/ui/kit.spec.ts`, `tests/styles/tokens.spec.ts` (no raw HTML) |
| Tokens only, contrast AA in light and dark | `src/styles/tokens.css` | `tests/styles/tokens.spec.ts` |

Browsers without Web Locks still get single-flight refresh within the tab, but not across tabs.
