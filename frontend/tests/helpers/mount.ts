import { createApp, h, nextTick, reactive, type Component } from 'vue';

export interface Mounted<P extends Record<string, unknown>> {
  root: HTMLElement;
  props: P;
  unmount(): void;
}

/** Minimal mount without @vue/test-utils: props are reactive, so tests can change them. */
export function mount<P extends Record<string, unknown>>(
  component: Component,
  initialProps: P = {} as P,
  slots?: Record<string, (...args: never[]) => unknown>,
): Mounted<P> {
  const root = document.createElement('div');
  document.body.appendChild(root);
  const props = reactive({ ...initialProps }) as P;
  const app = createApp({ render: () => h(component, props, slots as never) });
  app.mount(root);
  return {
    root,
    props,
    unmount() {
      app.unmount();
      root.remove();
    },
  };
}

export async function flush(): Promise<void> {
  await nextTick();
  await Promise.resolve();
  await nextTick();
}

export function byRole(root: ParentNode, role: string): HTMLElement[] {
  return [...root.querySelectorAll<HTMLElement>(`[role="${role}"]`)];
}
