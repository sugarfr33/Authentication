import AxeBuilder from '@axe-core/playwright';
import { test as base, expect, type Page } from '@playwright/test';
import { installMockApi, type MockApi } from './mockApi';
import { writeJson } from './evidence';

/** WCAG 2.0, 2.1 and 2.2, levels A and AA. Axe checks only the automatable part of these (see docs/test-matrix.md). */
export const AXE_TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa'];

/**
 * Console output that is not a defect: the browser logs every non-2xx API answer and every aborted API call
 * ("Failed to load resource"), and the tests make the API fail on purpose.
 */
function expectedConsoleError(text: string, url: string): boolean {
  return text.startsWith('Failed to load resource') && url !== '' && new URL(url).pathname.startsWith('/api/');
}

export const test = base.extend<{ api: MockApi; consoleProblems: string[] }>({
  api: [
    async ({ page, baseURL }, use) => {
      const api = await installMockApi(page, baseURL ?? 'http://localhost:5179');
      await use(api);
      expect(api.unexpected, 'requests the stub does not answer, or to another origin').toEqual([]);
    },
    { auto: true },
  ],
  // T31 (UX review E6): a console error, a Vue warning or an uncaught exception fails the test.
  consoleProblems: [
    async ({ page }, use) => {
      const problems: string[] = [];
      page.on('pageerror', (error) => problems.push(`pageerror: ${error.message}`));
      page.on('console', (message) => {
        const text = message.text();
        if (message.type() === 'error' && !expectedConsoleError(text, message.location().url)) problems.push(`console.error: ${text}`);
        if (message.type() === 'warning' && text.includes('[Vue warn]')) problems.push(`vue: ${text}`);
      });
      await use(problems);
      expect(problems, 'console errors, Vue warnings or uncaught exceptions').toEqual([]);
    },
    { auto: true },
  ],
});

export { expect };

export interface AxeSummary {
  readonly scan: string;
  readonly url: string;
  readonly violations: { id: string; impact: string | null; help: string; tags: string[]; targets: string[] }[];
  readonly incomplete: string[];
  readonly passes: number;
}

/** Runs axe on the current page, saves the result as evidence and returns it. */
export async function scanAxe(page: Page, scan: string): Promise<AxeSummary> {
  const results = await new AxeBuilder({ page }).withTags(AXE_TAGS).analyze();
  const summary: AxeSummary = {
    scan,
    url: page.url(),
    violations: results.violations.map((v) => ({
      id: v.id,
      impact: v.impact ?? null,
      help: v.help,
      tags: v.tags.filter((t) => t.startsWith('wcag')),
      targets: v.nodes.map((n) => n.target.join(' ')),
    })),
    incomplete: results.incomplete.map((v) => v.id),
    passes: results.passes.length,
  };
  writeJson(`axe-${scan}`, summary);
  return summary;
}

/** Scans and asserts no violation; for states reached in a flow (T31, UX review M1). */
export async function expectAxeClean(page: Page, scan: string): Promise<void> {
  const axe = await scanAxe(page, scan);
  expect.soft(axe.violations.map((v) => `${v.id} (${v.impact}): ${v.targets.join(' | ')}`), `axe ${scan}`).toEqual([]);
}

export interface FocusStop {
  readonly description: string;
  /** A ring is drawn, at least 3:1 against the background beside it, and nothing covers the control. */
  readonly visibleIndicator: boolean;
  /** Contrast of the ring colour against the nearest opaque background behind it; null when there is no ring. */
  readonly ringContrast: number | null;
  /** Another element is on top of the control's centre (WCAG 2.4.11). */
  readonly obscured: boolean;
  /** Focus is on an element already visited since tabStops started (Tab wrapped). */
  readonly repeated: boolean;
}

/**
 * Describes the focused element and checks its focus indicator (T31, UX review m8): not just "an outline exists",
 * but a ring colour with at least 3:1 contrast against the background beside it (1.4.11), and the control not hidden
 * under another element (2.4.11). The ring sits outside the control (outline-offset), so the background compared is
 * the nearest opaque one of its ancestors.
 */
export function focusStop(page: Page): Promise<FocusStop | null> {
  return page.evaluate(() => {
    const el = document.activeElement as HTMLElement | null;
    if (!el || el === document.body) return null;

    type Rgba = [number, number, number, number];
    const parse = (colour: string): Rgba | null => {
      const m = /rgba?\(([\d.]+)[ ,]+([\d.]+)[ ,]+([\d.]+)(?:[ ,/]+([\d.]+%?))?\)/.exec(colour);
      if (!m) return null;
      const a = m[4];
      const alpha = a === undefined ? 1 : a.endsWith('%') ? parseFloat(a) / 100 : parseFloat(a);
      return [Number(m[1]), Number(m[2]), Number(m[3]), alpha];
    };
    const luminance = ([r, g, b]: Rgba): number => {
      const [lr, lg, lb] = [r, g, b].map((v) => {
        const s = v / 255;
        return s <= 0.03928 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4;
      });
      return 0.2126 * (lr ?? 0) + 0.7152 * (lg ?? 0) + 0.0722 * (lb ?? 0);
    };
    const backgroundBehind = (start: Element | null): Rgba => {
      for (let node = start; node; node = node.parentElement) {
        const bg = parse(getComputedStyle(node).backgroundColor);
        if (bg && bg[3] >= 0.99) return bg;
      }
      return parse(getComputedStyle(document.documentElement).backgroundColor) ?? [255, 255, 255, 1];
    };

    const style = getComputedStyle(el);
    const hasOutline = style.outlineStyle !== 'none' && parseFloat(style.outlineWidth) > 0;
    const hasShadow = style.boxShadow !== 'none' && style.boxShadow !== '';
    const ring = hasOutline ? parse(style.outlineColor) : hasShadow ? parse(style.boxShadow) : null;
    let ringContrast: number | null = null;
    if (ring && ring[3] >= 0.99) {
      const a = luminance(ring);
      const b = luminance(backgroundBehind(el.parentElement));
      ringContrast = Math.round(((Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05)) * 100) / 100;
    }

    const box = el.getBoundingClientRect();
    const x = Math.min(Math.max(box.left + box.width / 2, 0), window.innerWidth - 1);
    const y = Math.min(Math.max(box.top + box.height / 2, 0), window.innerHeight - 1);
    const hit = document.elementFromPoint(x, y);
    const obscured = hit !== null && hit !== el && !el.contains(hit) && !(hit instanceof HTMLLabelElement && hit.control === el);

    const w = window as unknown as { __e2eSeen?: Set<Element> };
    const repeated = w.__e2eSeen?.has(el) ?? false;
    w.__e2eSeen?.add(el);

    const label = el.getAttribute('aria-label') ?? el.getAttribute('name') ?? (el.textContent ?? '').trim().replace(/\s+/g, ' ').slice(0, 40);
    return {
      description: `${el.tagName.toLowerCase()}:${label}`,
      visibleIndicator: (hasOutline || hasShadow) && ringContrast !== null && ringContrast >= 3 && !obscured,
      ringContrast,
      obscured,
      repeated,
    };
  });
}

/** Presses Tab until the element with this name attribute is focused (keyboard only, no clicks). */
export async function tabTo(page: Page, name: string, maxStops = 30): Promise<void> {
  for (let i = 0; i < maxStops; i += 1) {
    await page.keyboard.press('Tab');
    if (await page.evaluate((n) => document.activeElement?.getAttribute('name') === n, name)) return;
  }
  throw new Error(`Tab never reached [name="${name}"]`);
}

/**
 * Every Tab stop from the current focus until focus comes back to an element already visited or leaves the document.
 * Elements are told apart by identity, so two controls with the same name do not end the walk early (T31).
 */
export async function tabStops(page: Page, maxStops = 60): Promise<FocusStop[]> {
  await page.evaluate(() => {
    (window as unknown as { __e2eSeen?: Set<Element> }).__e2eSeen = new Set();
  });
  const stops: FocusStop[] = [];
  for (let i = 0; i < maxStops; i += 1) {
    await page.keyboard.press('Tab');
    const stop = await focusStop(page);
    if (stop === null || stop.repeated) return stops;
    stops.push(stop);
  }
  throw new Error(`More than ${maxStops} tab stops: possible keyboard trap`);
}

/** The text of the focused element, or null when focus is on <body> (lost). */
export function focusedText(page: Page): Promise<string | null> {
  return page.evaluate(() => {
    const el = document.activeElement;
    return !el || el === document.body ? null : (el.textContent ?? '').trim().replace(/\s+/g, ' ');
  });
}
