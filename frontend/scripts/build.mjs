// Production build that does not depend on the caller's environment.
// A shell with NODE_ENV=development (common under dev tooling) makes `vite build` produce a development
// bundle: Vue dev warnings, import.meta.env.DEV true, and the dev-only gallery route shipped. Force
// production, build, then fail if anything dev-only reached dist/.
import { readdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { build } from 'vite';

process.env.NODE_ENV = 'production';

await build({ mode: 'production' });

const DEV_ONLY_MARKERS = ['dev/gallery', 'GalleryView', 'UI kit gallery'];
const files = (await readdir('dist', { recursive: true })).filter((f) => /\.(js|css|html)$/.test(f));
const leaks = [];
for (const file of files) {
  const text = await readFile(join('dist', file), 'utf8');
  for (const marker of DEV_ONLY_MARKERS) if (text.includes(marker)) leaks.push(`${file}: ${marker}`);
}
if (leaks.length > 0) {
  console.error(`Dev-only code found in the production build:\n  ${leaks.join('\n  ')}`);
  process.exit(1);
}
console.log(`Checked ${files.length} files in dist/: no dev-only code.`);
