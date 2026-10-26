/// <reference types="vite/client" />

interface ImportMetaEnv {
  /** Origin of the auth API, e.g. https://auth.example.com. Empty means same origin (dev proxy). */
  readonly VITE_API_BASE_URL?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}

declare module '*.vue' {
  import type { DefineComponent } from 'vue';
  const component: DefineComponent<object, object, unknown>;
  export default component;
}
