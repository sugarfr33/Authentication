import { readonly, shallowRef } from 'vue';
import type { Tone } from '@/components/ui/types';

export interface ToastItem {
  readonly id: number;
  readonly tone: Tone;
  readonly message: string;
  /** null: stays until dismissed (the default for warnings and errors). */
  readonly timeoutMs: number | null;
}

export interface ToastOptions {
  tone?: Tone;
  timeoutMs?: number | null;
}

/** Long enough to read a sentence; paused while hovered or focused. */
export const DEFAULT_TOAST_TIMEOUT_MS = 6000;

const items = shallowRef<readonly ToastItem[]>([]);
let nextId = 1;

function show(message: string, options: ToastOptions = {}): number {
  const tone = options.tone ?? 'info';
  const sticky = tone === 'danger' || tone === 'warning';
  const timeoutMs = options.timeoutMs !== undefined ? options.timeoutMs : sticky ? null : DEFAULT_TOAST_TIMEOUT_MS;
  const id = nextId++;
  items.value = [...items.value, { id, tone, message, timeoutMs }];
  return id;
}

function dismiss(id: number): void {
  items.value = items.value.filter((item) => item.id !== id);
}

function clearAll(): void {
  items.value = [];
}

/** App-wide toasts, rendered by ToastRegion (mounted once in App.vue). */
export function useToast() {
  return { items: readonly(items), show, dismiss, clearAll };
}
