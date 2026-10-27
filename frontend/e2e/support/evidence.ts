// Where screenshots and axe results go. Files are prefixed "e2e-" so global-setup only ever clears its own.
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { Page } from '@playwright/test';

const here = dirname(fileURLToPath(import.meta.url));

export const EVIDENCE_PREFIX = 'e2e-';

export const evidenceDir: string = process.env.E2E_EVIDENCE_DIR
  ? resolve(process.env.E2E_EVIDENCE_DIR)
  : resolve(here, '..', '..', 'test-results', 'e2e-evidence');

export function evidenceFile(name: string): string {
  mkdirSync(evidenceDir, { recursive: true });
  return join(evidenceDir, EVIDENCE_PREFIX + name);
}

export async function screenshot(page: Page, name: string): Promise<void> {
  await page.screenshot({ path: evidenceFile(`${name}.png`), fullPage: true, animations: 'disabled' });
}

export function writeJson(name: string, value: unknown): void {
  writeFileSync(evidenceFile(`${name}.json`), JSON.stringify(value, null, 2));
}
