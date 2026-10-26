// T23 acceptance: API calls only in /src/api.
import { describe, expect, it } from 'vitest';

const sources = import.meta.glob<string>('/src/**/*.{ts,vue}', { query: '?raw', import: 'default', eager: true });

const NETWORK_PATTERNS: readonly [string, RegExp][] = [
  ['fetch(', /\bfetch\s*\(/],
  ['XMLHttpRequest', /\bXMLHttpRequest\b/],
  ['sendBeacon', /\bsendBeacon\b/],
  ['WebSocket', /\bWebSocket\b/],
  ['EventSource', /\bEventSource\b/],
  ['/api/v1 URL', /['"`]\/api\/v1/],
];

function outsideApi(file: string): boolean {
  return !file.startsWith('/src/api/');
}

describe('API boundary', () => {
  it('finds the source files (sanity check of the scan)', () => {
    expect(Object.keys(sources)).toContain('/src/api/http.ts');
    expect(Object.keys(sources).length).toBeGreaterThan(20);
  });

  it('no network call or API URL outside src/api', () => {
    const offenders: string[] = [];
    for (const [file, text] of Object.entries(sources)) {
      if (!outsideApi(file)) continue;
      for (const [name, pattern] of NETWORK_PATTERNS) {
        if (pattern.test(text)) offenders.push(`${file}: ${name}`);
      }
    }
    expect(offenders).toEqual([]);
  });

  it('code outside src/api imports the API only through its public entry (@/api)', () => {
    const offenders = Object.entries(sources)
      .filter(([file, text]) => outsideApi(file) && /from\s+['"]@\/api\/(http|auth|errors|types)['"]/.test(text))
      .map(([file]) => file);
    expect(offenders).toEqual([]);
  });

  it('the network code in src/api always sends credentials: include', () => {
    expect(sources['/src/api/http.ts']).toContain("credentials: 'include'");
  });
});
