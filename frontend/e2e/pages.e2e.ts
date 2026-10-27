// Every page, light and dark, at 320px and 1280px: it renders its heading and title, does not scroll sideways, and
// axe finds no violation of the WCAG 2.2 A/AA rules it can check automatically. Axe covers only part of WCAG: what
// it cannot judge is listed under "NOT TESTED" in docs/test-matrix.md, so 0 violations here is not conformance.
// Plus, per page and theme: every Tab stop shows a focus ring with 3:1 contrast that nothing covers, and Tab never
// gets trapped. Gallery states (open dialogs, toasts), forced colours, text spacing and 200% text are scanned too.
import { RESET_TOKEN } from './support/mockApi';
import { expect, expectAxeClean, focusStop, scanAxe, tabStops, test } from './support/fixtures';
import { screenshot, writeJson } from './support/evidence';
import type { Page } from '@playwright/test';

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

function horizontalOverflow(page: Page): Promise<number> {
  return page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
}

for (const p of pages) {
  test.describe(p.name, () => {
    for (const theme of themes) {
      for (const width of widths) {
        test(`${theme} ${width}px: renders with its title, no sideways scroll, axe (automated subset) finds nothing`, async ({ page }) => {
          await page.setViewportSize({ width, height: 900 });
          await page.emulateMedia({ colorScheme: theme });
          await page.goto(p.path);
          await expect(page.getByRole('heading', { level: 1, name: p.heading })).toBeVisible();
          // WCAG 2.4.2: every route names itself in the tab title (the title is the page heading).
          await expect(page).toHaveTitle(`${p.heading} · Central Auth`);
          // UX review m5 (T31-FIX): no empty role=alert on the page; some screen readers announce one on load.
          const emptyAlerts = await page.evaluate(
            () => [...document.querySelectorAll('[role="alert"]')].filter((el) => (el.textContent ?? '').trim() === '').length,
          );
          expect(emptyAlerts, 'empty role=alert regions').toBe(0);

          const overflow = await horizontalOverflow(page);
          const scan = `${p.name}-${theme}-${width}`;
          const axe = await scanAxe(page, scan);
          await screenshot(page, scan);

          expect.soft(overflow, 'horizontal overflow in px').toBeLessThanOrEqual(0);
          expect.soft(axe.violations.map((v) => `${v.id} (${v.impact}): ${v.targets.join(' | ')}`)).toEqual([]);
        });
      }

      test(`keyboard, ${theme}: every Tab stop shows a 3:1 focus ring nothing covers, no trap, skip link first`, async ({ page }) => {
        await page.setViewportSize({ width: 1280, height: 900 });
        await page.emulateMedia({ colorScheme: theme });
        await page.goto(p.path);
        await expect(page.getByRole('heading', { level: 1, name: p.heading })).toBeVisible();

        // After an in-app navigation (the reset page drops its token with router.replace) focus is on <main>, so the
        // first Tab lands inside the page; otherwise it starts at the skip link.
        const start = await focusStop(page);
        const stops = await tabStops(page);
        writeJson(`focus-order-${p.name}-${theme}`, { start, stops });

        if (start?.description.startsWith('main:')) expect(stops.length).toBeGreaterThan(0);
        else expect(stops[0]?.description).toBe('a:Skip to main content');
        expect
          .soft(
            stops.filter((s) => !s.visibleIndicator).map((s) => `${s.description} (contrast ${s.ringContrast}, obscured ${s.obscured})`),
            'stops without a visible focus ring',
          )
          .toEqual([]);

        // Evidence of the ring itself, per theme: the first form control (or the first stop).
        await page.keyboard.press('Tab');
        await screenshot(page, `focus-ring-${p.name}-${theme}`);
      });
    }
  });
}

test.describe('gallery states (UX review M1)', () => {
  for (const theme of themes) {
    test(`${theme}: open dialogs and every toast pass axe (automated subset)`, async ({ page }) => {
      await page.emulateMedia({ colorScheme: theme });
      await page.goto('/dev/gallery');
      await expect(page.getByRole('heading', { level: 1, name: 'UI kit gallery' })).toBeVisible();

      await page.getByRole('button', { name: 'Open dialog' }).click();
      await expect(page.getByRole('dialog', { name: 'Save changes?' })).toBeVisible();
      await expectAxeClean(page, `gallery-dialog-${theme}`);
      await screenshot(page, `gallery-dialog-${theme}`);
      await page.keyboard.press('Escape');
      await expect(page.getByRole('dialog')).toHaveCount(0);

      await page.getByRole('button', { name: 'Sign out everywhere' }).click();
      await expect(page.getByRole('dialog', { name: 'Sign out all other sessions?' })).toBeVisible();
      await expectAxeClean(page, `gallery-danger-dialog-${theme}`);
      await page.keyboard.press('Escape');

      for (const tone of ['info', 'success', 'warning', 'danger'] as const) {
        await page.getByRole('button', { name: `Show ${tone} toast` }).click();
        await expect(page.getByText(`A ${tone} notification.`)).toBeVisible();
      }
      await expectAxeClean(page, `gallery-toasts-${theme}`);
      await screenshot(page, `gallery-toasts-${theme}`);
    });
  }
});

test.describe('forced colours and more contrast (UX review E1)', () => {
  for (const p of pages.filter((x) => x.name === 'login' || x.name === 'register')) {
    test(`${p.name}: renders, focus ring still drawn, axe (automated subset) finds nothing`, async ({ page }) => {
      await page.emulateMedia({ forcedColors: 'active', contrast: 'more' });
      await page.goto(p.path);
      await expect(page.getByRole('heading', { level: 1, name: p.heading })).toBeVisible();
      await expectAxeClean(page, `${p.name}-forced-colors`);

      // In forced colours, box-shadow rings vanish; the kit uses outlines, which stay.
      await page.locator('input[name="email"]').focus();
      const outline = await page.evaluate(() => {
        const style = getComputedStyle(document.activeElement as Element);
        return { style: style.outlineStyle, width: parseFloat(style.outlineWidth) };
      });
      expect(outline.style).not.toBe('none');
      expect(outline.width).toBeGreaterThan(0);
      await screenshot(page, `${p.name}-forced-colors`);
    });
  }
});

/** WCAG 1.4.12 text spacing (the bookmarklet values) and 1.4.4 resize text: injected over the page's own CSS. */
const TEXT_SPACING = `* { line-height: 1.5 !important; letter-spacing: 0.12em !important; word-spacing: 0.16em !important; }
p { margin-block-end: 2em !important; }`;

test.describe('text spacing and 200% text (UX review E2)', () => {
  for (const p of pages.filter((x) => x.name !== 'gallery')) {
    test(`${p.name}: no clipped text or sideways scroll with WCAG text spacing at 320px, nor with 200% text at 1280px`, async ({ page }) => {
      const clipped = () =>
        page.evaluate(() =>
          [...document.querySelectorAll<HTMLElement>('body *')]
            .filter((el) => {
              const style = getComputedStyle(el);
              const clips = ['hidden', 'clip'].includes(style.overflowX) || ['hidden', 'clip'].includes(style.overflowY);
              const hiddenOnPurpose = el.classList.contains('visually-hidden') || el.closest('.visually-hidden') !== null;
              return clips && !hiddenOnPurpose && el.offsetParent !== null && (el.scrollWidth > el.clientWidth + 1 || el.scrollHeight > el.clientHeight + 1);
            })
            .map((el) => `${el.tagName.toLowerCase()}.${el.className}`),
        );

      await page.setViewportSize({ width: 320, height: 900 });
      await page.goto(p.path);
      await expect(page.getByRole('heading', { level: 1, name: p.heading })).toBeVisible();
      await page.addStyleTag({ content: TEXT_SPACING });
      const spacing = { overflow: await horizontalOverflow(page), clipped: await clipped() };
      await screenshot(page, `${p.name}-text-spacing`);

      await page.setViewportSize({ width: 1280, height: 900 });
      await page.reload();
      await expect(page.getByRole('heading', { level: 1, name: p.heading })).toBeVisible();
      await page.addStyleTag({ content: 'html { font-size: 200% !important; }' });
      const doubled = { overflow: await horizontalOverflow(page), clipped: await clipped() };
      await screenshot(page, `${p.name}-text-200`);
      writeJson(`text-resize-${p.name}`, { spacing, doubled });

      expect.soft(spacing.overflow, 'sideways scroll with text spacing').toBeLessThanOrEqual(0);
      expect.soft(spacing.clipped, 'clipped with text spacing').toEqual([]);
      expect.soft(doubled.overflow, 'sideways scroll with 200% text').toBeLessThanOrEqual(0);
      expect.soft(doubled.clipped, 'clipped with 200% text').toEqual([]);
    });
  }
});
