import AxeBuilder from '@axe-core/playwright';
import { test as base, expect, type Page } from '@playwright/test';
import { installMockApi, type MockApi } from './mockApi';
import { writeJson } from './evidence';

/** WCAG 2.0, 2.1 and 2.2, levels A and AA. */
export const AXE_TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa'];

export const test = base.extend<{ api: MockApi }>({
  api: [
    async ({ page, baseURL }, use) => {
      const api = await installMockApi(page, baseURL ?? 'http://localhost:5179');
      await use(api);
      expect(api.unexpected, 'requests the stub does not answer, or to another origin').toEqual([]);
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

export interface FocusStop {
  readonly description: string;
  readonly visibleIndicator: boolean;
}

/** Describes the focused element and whether it shows a focus indicator (outline or box-shadow). */
export function focusStop(page: Page): Promise<FocusStop | null> {
  return page.evaluate(() => {
    const el = document.activeElement as HTMLElement | null;
    if (!el || el === document.body) return null;
    const style = getComputedStyle(el);
    const outline = style.outlineStyle !== 'none' && parseFloat(style.outlineWidth) > 0;
    const shadow = style.boxShadow !== 'none' && style.boxShadow !== '';
    const label = el.getAttribute('aria-label') ?? el.getAttribute('name') ?? (el.textContent ?? '').trim().replace(/\s+/g, ' ').slice(0, 40);
    return { description: `${el.tagName.toLowerCase()}:${label}`, visibleIndicator: outline || shadow };
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

/** Every Tab stop from the top of the page until focus wraps back to the start or leaves the document. */
export async function tabStops(page: Page, maxStops = 60): Promise<FocusStop[]> {
  const stops: FocusStop[] = [];
  for (let i = 0; i < maxStops; i += 1) {
    await page.keyboard.press('Tab');
    const stop = await focusStop(page);
    if (stop === null || (stops.length > 0 && stop.description === stops[0]?.description)) return stops;
    stops.push(stop);
  }
  throw new Error(`More than ${maxStops} tab stops: possible keyboard trap`);
}
