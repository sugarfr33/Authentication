// The few Node APIs the e2e support code uses. @types/node is not a dependency of this project, and adding it
// for four functions is not worth a package; Playwright runs the files on Node, where these exist.
declare module 'node:fs' {
  export function mkdirSync(path: string, options?: { recursive?: boolean }): string | undefined;
  export function readdirSync(path: string): string[];
  export function readFileSync(path: string, encoding: 'utf8'): string;
  export function rmSync(path: string): void;
  export function writeFileSync(path: string, data: string): void;
}

declare module 'node:path' {
  export function dirname(path: string): string;
  export function join(...paths: string[]): string;
  export function resolve(...paths: string[]): string;
}

declare module 'node:url' {
  export function fileURLToPath(url: string | URL): string;
}

declare const process: { readonly env: Record<string, string | undefined> };
