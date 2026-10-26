// Reads src/ from disk at test time (not import.meta.glob, which is resolved by the bundler and was shown
// to miss a newly added file). Every file under src/ with a matching extension is returned, tracked or not.
import { readdirSync, readFileSync } from 'node:fs';

// Vitest runs with the frontend folder as the working directory (package.json scripts, vite root).
const SRC = `${process.cwd().replace(/\\/g, '/')}/src/`;

/** Map of '/src/<relative path with forward slashes>' to file text. */
export function readSources(extensions: readonly string[] = ['.ts', '.vue', '.css']): Map<string, string> {
  const files = new Map<string, string>();
  for (const entry of readdirSync(SRC, { recursive: true })) {
    const relative = entry.replace(/\\/g, '/');
    if (!extensions.some((ext) => relative.endsWith(ext))) continue;
    files.set(`/src/${relative}`, readFileSync(SRC + relative, 'utf8'));
  }
  return files;
}
