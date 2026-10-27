// End-to-end and accessibility suite (T-PW). Run with `npm run e2e`; it is not part of `npm test` or `npm run build`.
// - Starts its own Vite dev server on E2E_PORT (default 5179), never 5173.
// - No backend and no database: every /api call is answered by e2e/support/mockApi.ts, and any request to
//   another origin is aborted and fails the test.
// - Screenshots and axe results go to E2E_EVIDENCE_DIR (default frontend/test-results/e2e-evidence, git-ignored).
// - Chromium only, installed once with `npx playwright install chromium` (downloads from Microsoft's CDN into
//   %LOCALAPPDATA%\ms-playwright or ~/.cache/ms-playwright, outside the repository).
import { fileURLToPath } from 'node:url';
import { defineConfig, devices } from '@playwright/test';

const port = Number(process.env.E2E_PORT ?? '5179');
const frontendDir = fileURLToPath(new URL('..', import.meta.url));

export default defineConfig({
  testDir: '.',
  testMatch: '**/*.e2e.ts',
  outputDir: '../test-results/e2e',
  fullyParallel: true,
  forbidOnly: true,
  retries: 0,
  reporter: [['list']],
  globalSetup: './global-setup.ts',
  globalTeardown: './global-teardown.ts',
  use: {
    baseURL: `http://localhost:${port}`,
    trace: 'retain-on-failure',
    serviceWorkers: 'block',
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
  webServer: {
    command: `npx vite --port ${port} --strictPort --mode development`,
    cwd: frontendDir,
    url: `http://localhost:${port}/login`,
    reuseExistingServer: false,
    timeout: 60_000,
  },
});
