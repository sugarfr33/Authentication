import { fileURLToPath } from 'node:url';
import { defineConfig, loadEnv } from 'vite';
import vue from '@vitejs/plugin-vue';

// Dev only: /api is proxied to Auth.Api's https profile so the SPA and the API share an origin in the
// browser (cookies are SameSite=Strict). It must be https: in Development the API answers plain http with
// 500, because its antiforgery cookie requires SSL (T26 GAP-2, T29). The proxy keeps the browser's Origin
// header, so the API must list the dev origin in BrowserProtection:TrustedOrigins (see frontend/README.md).
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, '.', '');
  const apiTarget = env.VITE_DEV_API_TARGET || 'https://localhost:7090';

  return {
    plugins: [vue()],
    resolve: {
      alias: { '@': fileURLToPath(new URL('./src', import.meta.url)) },
    },
    server: {
      port: 5173,
      strictPort: true,
      proxy: {
        '/api': { target: apiTarget, changeOrigin: false, secure: false },
      },
    },
    build: {
      target: 'es2022',
      sourcemap: false,
    },
    test: {
      environment: 'jsdom',
      include: ['tests/**/*.spec.ts'],
      restoreMocks: true,
      // Let the token tests read the real stylesheets (?raw); Vitest blanks CSS by default.
      css: { include: [/[\\/]src[\\/]styles[\\/].+\.css/] },
    },
  };
});
