// Collects every axe result of the run into e2e-axe-summary.md next to the screenshots.
import { readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { EVIDENCE_PREFIX, evidenceDir } from './support/evidence';
import type { AxeSummary } from './support/fixtures';

export default function globalTeardown(): void {
  const scans: AxeSummary[] = readdirSync(evidenceDir)
    .filter((f) => f.startsWith(`${EVIDENCE_PREFIX}axe-`) && f.endsWith('.json'))
    .sort()
    .map((f) => JSON.parse(readFileSync(join(evidenceDir, f), 'utf8')) as AxeSummary);

  const byRule = new Map<string, { impact: string | null; help: string; tags: string[]; scans: string[]; nodes: number }>();
  for (const scan of scans) {
    for (const v of scan.violations) {
      const entry = byRule.get(v.id) ?? { impact: v.impact, help: v.help, tags: v.tags, scans: [], nodes: 0 };
      entry.scans.push(scan.scan);
      entry.nodes += v.targets.length;
      byRule.set(v.id, entry);
    }
  }

  const lines = [
    '# axe-core summary (WCAG 2.0/2.1/2.2 A and AA)',
    '',
    `Scans: ${scans.length}. Scans with violations: ${scans.filter((s) => s.violations.length > 0).length}. Distinct rules violated: ${byRule.size}.`,
    '',
  ];
  if (byRule.size > 0) {
    lines.push('| Rule | Impact | WCAG | Nodes | Scans | Help |', '|---|---|---|---|---|---|');
    for (const [id, e] of [...byRule].sort()) {
      lines.push(`| ${id} | ${e.impact ?? ''} | ${e.tags.join(' ')} | ${e.nodes} | ${e.scans.join(', ')} | ${e.help} |`);
    }
    lines.push('');
  }
  lines.push('| Scan | Violations | Incomplete (manual review) | Passed rules |', '|---|---|---|---|');
  for (const s of scans) {
    lines.push(`| ${s.scan} | ${s.violations.map((v) => v.id).join(', ') || '0'} | ${s.incomplete.join(', ') || '0'} | ${s.passes} |`);
  }
  writeFileSync(join(evidenceDir, `${EVIDENCE_PREFIX}axe-summary.md`), lines.join('\n') + '\n');
}
