// Mounts the real routes, guard and Pinia store in memory history, for page-level DOM tests.
import { createPinia, setActivePinia } from 'pinia';
import { createApp, defineComponent, h } from 'vue';
import { createMemoryHistory, createRouter, RouterView, type Router } from 'vue-router';
import { routes } from '@/router';
import { installAuthGuard } from '@/router/guards';
import { useSessionStore } from '@/stores/session';
import { flush } from './mount';

export interface MountedApp {
  root: HTMLElement;
  router: Router;
  session: ReturnType<typeof useSessionStore>;
  unmount(): void;
}

let preloaded: Promise<unknown> | null = null;

/** Imports every lazy route component once, so navigation in a test never waits on a cold module transform. */
function preloadRoutes(): Promise<unknown> {
  preloaded ??= Promise.all(routes.map((r) => (typeof r.component === 'function' ? (r.component as () => Promise<unknown>)() : null)));
  return preloaded;
}

export async function mountApp(path: string): Promise<MountedApp> {
  await preloadRoutes();
  const pinia = createPinia();
  setActivePinia(pinia);
  const session = useSessionStore(pinia);
  const router = createRouter({ history: createMemoryHistory(), routes });
  installAuthGuard(router, session);
  const root = document.createElement('div');
  document.body.appendChild(root);
  const app = createApp(defineComponent({ render: () => h(RouterView) }));
  app.use(pinia).use(router);
  await router.push(path);
  await router.isReady();
  app.mount(root);
  await settle();
  return {
    root,
    router,
    session,
    unmount() {
      app.unmount();
      root.remove();
    },
  };
}

/** Lets lazy route components, promises and re-renders finish. */
export async function settle(rounds = 6): Promise<void> {
  for (let i = 0; i < rounds; i += 1) {
    await flush();
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
}

export function input(root: ParentNode, label: string): HTMLInputElement {
  const labelEl = [...root.querySelectorAll('label')].find((l) => l.textContent?.trim().startsWith(label));
  if (!labelEl) throw new Error(`no label "${label}"`);
  const field = root.querySelector<HTMLInputElement>(`[id="${labelEl.htmlFor}"]`);
  if (!field) throw new Error(`label "${label}" points at nothing`);
  return field;
}

export async function type(field: HTMLInputElement, value: string): Promise<void> {
  field.value = value;
  field.dispatchEvent(new Event('input', { bubbles: true }));
  await flush();
}

export async function submit(root: ParentNode): Promise<void> {
  const form = root.querySelector('form');
  if (!form) throw new Error('no form');
  form.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }));
  await settle();
}

export function button(root: ParentNode, text: string): HTMLButtonElement {
  const found = [...root.querySelectorAll('button')].find((b) => b.textContent?.trim() === text);
  if (!found) throw new Error(`no button "${text}"`);
  return found;
}
