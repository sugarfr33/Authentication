// Every page, light and dark, at 320px and 1280px: it renders its heading, does not scroll sideways, and axe finds
// no WCAG 2.2 A/AA violation. Plus, per page: every Tab stop shows a focus indicator and Tab never gets trapped.
import { RESET_TOKEN } from './support/mockApi';
import { expect, focusStop, scanAxe, tabStops, test } from './support/fixtures';
import { screenshot, writeJson } from './support/evidence';

const pages = [
  { name: 'login', path: '/login', heading: 'Sign in' },
  { name: 'register', path: '/register', heading: 'Create an account' },
  { name: 'forgot', path: '/forgot-password', heading: 'Reset your password' },
  { name: 'reset', path: `/reset-password#token=${RESET_TOKEN}`, heading: 'Choose a new password' },
  { name: 'mfa-challenge', path: '/login/verify', heading: 'Two-step verification' },
  { name: 'not-found', path: '/no/such/page', heading: 'Page not found' },
  { name: 'gallery', path: '/dev/gallery', heading: 'UI kit gallery' },
] as const;

const themes = ['light', 'dark'] as const;
const widths = [320, 1280] as const;

for (const p of pages) {
  test.describe(p.name, () => {
    for (const theme of themes) {
      for (const width of widths) {
        test(`${theme} ${width}px: renders, no sideways scroll, axe WCAG 2.2 AA clean`, async ({ page }) => {
          await page.setViewportSize({ width, height: 900 });
          await page.emulateMedia({ colorScheme: theme });
          await page.goto(p.path);
          await expect(page.getByRole('heading', { level: 1, name: p.heading })).toBeVisible();

          const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
          const scan = `${p.name}-${theme}-${width}`;
          const axe = await scanAxe(page, scan);
          await screenshot(page, scan);

          expect.soft(overflow, 'horizontal overflow in px').toBeLessThanOrEqual(0);
          expect.soft(axe.violations.map((v) => `${v.id} (${v.impact}): ${v.targets.join(' | ')}`)).toEqual([]);
        });
      }
    }

    test('keyboard: every Tab stop shows focus, no trap, skip link first', async ({ page }) => {
      await page.setViewportSize({ width: 1280, height: 900 });
      await page.goto(p.path);
      await expect(page.getByRole('heading', { level: 1, name: p.heading })).toBeVisible();

      // After an in-app navigation (the reset page drops its token with router.replace) focus is on <main>, so the
      // first Tab lands inside the page; otherwise it starts at the skip link.
      const start = await focusStop(page);
      const stops = await tabStops(page);
      writeJson(`focus-order-${p.name}`, { start, stops });

      if (start?.description.startsWith('main:')) expect(stops.length).toBeGreaterThan(0);
      else expect(stops[0]?.description).toBe('a:Skip to main content');
      expect.soft(stops.filter((s) => !s.visibleIndicator).map((s) => s.description), 'stops without a visible focus indicator').toEqual([]);
    });
  });
}
