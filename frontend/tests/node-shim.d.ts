// The few Node APIs the source-scanning tests use. Declared here so the tests need no @types/node.
declare module 'node:fs' {
  export function readdirSync(path: URL | string, options: { recursive: true }): string[];
  export function readFileSync(path: URL | string, encoding: 'utf8'): string;
}

declare const process: { cwd(): string };

declare module 'node:crypto' {
  export const webcrypto: Crypto;
}
