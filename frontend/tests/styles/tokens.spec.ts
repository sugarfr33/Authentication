// Design tokens: WCAG contrast of the semantic colour pairs (light and dark), dark blocks in sync,
// and the kit/pages using tokens only (no hard-coded colours or pixel sizes, no primitives).
import { describe, expect, it } from 'vitest';
import tokensCss from '@/styles/tokens.css?raw';

import { readSources } from '../helpers/sources';

const vueFiles = Object.fromEntries(readSources(['.vue']));
const cssFiles = Object.fromEntries(readSources(['.css']));

function block(css: string, selector: string): string {
  const start = css.indexOf(selector);
  if (start < 0) throw new Error(`selector not found: ${selector}`);
  let depth = 0;
  const open = css.indexOf('{', start);
  for (let i = open; i < css.length; i++) {
    if (css[i] === '{') depth++;
    else if (css[i] === '}') {
      depth--;
      if (depth === 0) return css.slice(open + 1, i);
    }
  }
  throw new Error(`unbalanced block: ${selector}`);
}

function declarations(text: string): Map<string, string> {
  const map = new Map<string, string>();
  for (const match of text.matchAll(/(--[\w-]+)\s*:\s*([^;]+);/g)) {
    map.set(match[1] as string, (match[2] as string).trim());
  }
  return map;
}

const primitives = declarations(block(tokensCss, '/* ---------- 1. Primitive ---------- */'));
const light = declarations(block(tokensCss, '/* ---------- 2. Semantic: light (default) ---------- */'));
const darkMediaBlock = block(block(tokensCss, '@media (prefers-color-scheme: dark)'), ":root:not([data-theme='light'])");
const darkOverrideBlock = block(tokensCss, ":root[data-theme='dark']");
const dark = declarations(darkMediaBlock);

function resolve(theme: Map<string, string>, name: string): string {
  let value = theme.get(name) ?? primitives.get(name);
  for (let guard = 0; value?.startsWith('var(') && guard < 10; guard++) {
    const ref = /^var\((--[\w-]+)\)$/.exec(value)?.[1];
    value = ref ? (theme.get(ref) ?? primitives.get(ref)) : undefined;
  }
  if (!value || !/^#[0-9a-f]{6}$/i.test(value)) throw new Error(`cannot resolve ${name} to a hex colour (got ${value})`);
  return value;
}

function luminance(hex: string): number {
  const channel = (offset: number) => {
    const c = Number.parseInt(hex.slice(offset, offset + 2), 16) / 255;
    return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
  };
  return 0.2126 * channel(1) + 0.7152 * channel(3) + 0.0722 * channel(5);
}

export function contrast(a: string, b: string): number {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x) as [number, number];
  return (hi + 0.05) / (lo + 0.05);
}

const TEXT = 4.5;
const UI = 3;

// [foreground, background, minimum]: every text and boundary pairing the kit uses.
const PAIRS: readonly [string, string, number][] = [
  ['--color-text', '--color-bg', TEXT],
  ['--color-text', '--color-surface', TEXT],
  ['--color-text', '--color-surface-raised', TEXT],
  ['--color-text', '--color-surface-sunken', TEXT],
  ['--color-text-muted', '--color-bg', TEXT],
  ['--color-text-muted', '--color-surface', TEXT],
  ['--color-text-muted', '--color-surface-raised', TEXT],
  ['--color-text-muted', '--color-surface-sunken', TEXT],
  ['--color-link', '--color-bg', TEXT],
  ['--color-link', '--color-surface', TEXT],
  ['--color-link', '--color-primary-subtle', TEXT],
  ['--color-on-primary', '--color-primary', TEXT],
  ['--color-on-primary', '--color-primary-hover', TEXT],
  ['--color-on-primary', '--color-primary-active', TEXT],
  ['--color-on-danger', '--color-danger', TEXT],
  ['--color-on-danger', '--color-danger-hover', TEXT],
  ['--color-danger-text', '--color-surface', TEXT],
  ['--color-danger-text', '--color-bg', TEXT],
  ['--color-danger-on-bg', '--color-danger-bg', TEXT],
  ['--color-success-on-bg', '--color-success-bg', TEXT],
  ['--color-warning-on-bg', '--color-warning-bg', TEXT],
  ['--color-info-on-bg', '--color-info-bg', TEXT],
  ['--color-primary', '--color-surface', TEXT],
  ['--color-primary', '--color-surface-raised', UI],
  ['--color-success-text', '--color-surface-raised', UI],
  ['--color-warning-text', '--color-surface-raised', UI],
  ['--color-danger-text', '--color-surface-raised', UI],
  ['--color-text-muted', '--color-surface-raised', UI],
  // non-text: input borders, focus ring, toggles
  ['--color-border-strong', '--color-surface', UI],
  ['--color-border-strong', '--color-bg', UI],
  ['--color-focus-ring', '--color-bg', UI],
  ['--color-focus-ring', '--color-surface', UI],
  ['--color-focus-ring', '--color-surface-raised', UI],
  ['--color-danger-text', '--color-surface', UI],
];

describe.each([
  ['light', light],
  ['dark', dark],
])('contrast (%s theme)', (_name, theme) => {
  it.each(PAIRS)('%s on %s >= %s:1', (fg, bg, min) => {
    const ratio = contrast(resolve(theme, fg), resolve(theme, bg));
    expect(ratio, `${fg} on ${bg} is ${ratio.toFixed(2)}:1`).toBeGreaterThanOrEqual(min);
  });
});

describe('token structure', () => {
  it('the explicit dark override matches the prefers-color-scheme dark block exactly', () => {
    expect([...declarations(darkOverrideBlock)]).toEqual([...dark]);
  });

  it('dark mode redefines every colour token of the light theme', () => {
    const lightColours = [...light.keys()].filter((k) => k.startsWith('--color-'));
    expect(lightColours.filter((k) => !dark.has(k))).toEqual([]);
  });

  it('reduced motion stops transitions but keeps loading indicators turning (slowly)', () => {
    const reduced = declarations(block(tokensCss, '@media (prefers-reduced-motion: reduce)'));
    expect(reduced.get('--duration-base')).toBe('0ms');
    expect(reduced.get('--duration-spin')).toBe('var(--p-duration-spin-reduced)');
    expect(primitives.get('--p-duration-spin-reduced')).not.toMatch(/^0/);
  });

  it('the WCAG formula is implemented correctly (black on white is 21:1)', () => {
    expect(contrast('#000000', '#ffffff')).toBeCloseTo(21, 5);
  });
});

function styleBlocks(source: string): string {
  return [...source.matchAll(/<style[^>]*>([\s\S]*?)<\/style>/g)].map((m) => m[1]).join('\n');
}

describe('kit and pages use tokens only', () => {
  it('no hard-coded colours or pixel sizes in component styles (1px only in the visually-hidden pattern)', () => {
    const offenders: string[] = [];
    for (const [file, source] of Object.entries(vueFiles)) {
      const css = styleBlocks(source).replace(/\/\*[\s\S]*?\*\//g, '');
      if (/#[0-9a-f]{3,8}\b/i.test(css)) offenders.push(`${file}: hex colour`);
      if (/\b(rgb|rgba|hsl|hsla)\(/i.test(css)) offenders.push(`${file}: colour function`);
      for (const px of css.matchAll(/(\d+(?:\.\d+)?)px\b/g)) {
        if (px[1] !== '1') offenders.push(`${file}: ${px[0]}`);
      }
    }
    expect(offenders).toEqual([]);
  });

  it('primitive tokens (--p-*) are used only inside tokens.css', () => {
    const offenders = [
      ...Object.entries(vueFiles).filter(([, s]) => /var\(--p-/.test(s)),
      ...Object.entries(cssFiles).filter(([file, s]) => !file.endsWith('/tokens.css') && /var\(--p-/.test(s)),
    ].map(([file]) => file);
    expect(offenders).toEqual([]);
  });

  it('pages (src/views, except the dev gallery) have no styles of their own', () => {
    const offenders = Object.entries(vueFiles)
      .filter(([file]) => file.startsWith('/src/views/') && !file.startsWith('/src/views/dev/'))
      .filter(([, source]) => /<style/.test(source) || /\sstyle=/.test(source))
      .map(([file]) => file);
    expect(offenders).toEqual([]);
  });

  it('nothing renders raw HTML (v-html / innerHTML): IP and user agent stay text', () => {
    const all = Object.fromEntries(readSources(['.ts', '.vue']));
    const offenders = Object.entries(all)
      .filter(([, s]) => /v-html|innerHTML|outerHTML|insertAdjacentHTML/.test(s))
      .map(([file]) => file);
    expect(offenders).toEqual([]);
  });
});
