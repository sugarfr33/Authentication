// Clears this suite's own evidence files (prefix "e2e-") from the previous run; nothing else in the folder.
import { mkdirSync, readdirSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { EVIDENCE_PREFIX, evidenceDir } from './support/evidence';

export default function globalSetup(): void {
  mkdirSync(evidenceDir, { recursive: true });
  for (const file of readdirSync(evidenceDir)) {
    if (file.startsWith(EVIDENCE_PREFIX)) rmSync(join(evidenceDir, file));
  }
}
