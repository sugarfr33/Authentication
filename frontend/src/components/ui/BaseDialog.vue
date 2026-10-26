<script setup lang="ts">
// Native <dialog> + showModal(): the browser traps focus, makes the page inert and handles Esc.
// Focus goes to a safe control on open (Cancel for destructive dialogs) and back to the opener on close.
import { nextTick, onBeforeUnmount, onMounted, ref, useId, watch } from 'vue';
import { messages } from '@/i18n/messages';
import BaseButton from './BaseButton.vue';

const props = withDefaults(
  defineProps<{
    title: string;
    description?: string;
    /** Restate action and object, e.g. "Sign out all sessions". */
    confirmLabel: string;
    cancelLabel?: string;
    tone?: 'default' | 'danger';
    /** Confirm in progress: confirm shows busy, cancel and Esc are blocked. */
    confirmLoading?: boolean;
  }>(),
  { description: undefined, cancelLabel: messages.common.cancel, tone: 'default', confirmLoading: false },
);

const open = defineModel<boolean>('open', { required: true });
const emit = defineEmits<{ confirm: []; cancel: [] }>();
defineSlots<{ default?(): unknown }>();

const uid = useId();
const titleId = `dialog-${uid}-title`;
const descriptionId = `dialog-${uid}-description`;
const dialog = ref<HTMLDialogElement | null>(null);
let opener: HTMLElement | null = null;

async function show(): Promise<void> {
  const el = dialog.value;
  if (!el || el.open) return;
  opener = document.activeElement instanceof HTMLElement ? document.activeElement : null;
  if (typeof el.showModal === 'function') el.showModal();
  else el.setAttribute('open', '');
  await nextTick();
  el.querySelector<HTMLElement>('[data-autofocus]')?.focus();
}

function hide(): void {
  const el = dialog.value;
  if (el?.open) {
    if (typeof el.close === 'function') el.close();
    else el.removeAttribute('open');
  }
  const target = opener;
  opener = null;
  if (target?.isConnected) target.focus();
}

function cancel(): void {
  if (props.confirmLoading) return;
  open.value = false;
  emit('cancel');
}

/** Esc fires "cancel" on a modal dialog; we decide instead of the browser. */
function onNativeCancel(event: Event): void {
  event.preventDefault();
  cancel();
}

/** A click on the dialog element itself (not its panel) is a click on the backdrop. */
function onDialogClick(event: MouseEvent): void {
  if (event.target === dialog.value) cancel();
}

watch(open, (value) => (value ? void show() : hide()), { flush: 'post' });
onMounted(() => {
  if (open.value) void show();
});
onBeforeUnmount(hide);
</script>

<template>
  <dialog
    ref="dialog"
    class="dialog"
    :aria-labelledby="titleId"
    :aria-describedby="description ? descriptionId : undefined"
    @cancel="onNativeCancel"
    @click="onDialogClick"
  >
    <div class="dialog__panel">
      <h2 :id="titleId" class="dialog__title">{{ title }}</h2>
      <p v-if="description" :id="descriptionId" class="dialog__description">{{ description }}</p>
      <div v-if="$slots.default" class="dialog__body"><slot /></div>
      <div class="dialog__actions">
        <BaseButton
          variant="secondary"
          :disabled="confirmLoading"
          :data-autofocus="tone === 'danger' ? '' : undefined"
          @click="cancel"
        >
          {{ cancelLabel }}
        </BaseButton>
        <BaseButton
          :variant="tone === 'danger' ? 'danger' : 'primary'"
          :loading="confirmLoading"
          :data-autofocus="tone === 'danger' ? undefined : ''"
          @click="emit('confirm')"
        >
          {{ confirmLabel }}
        </BaseButton>
      </div>
    </div>
  </dialog>
</template>

<style scoped>
.dialog {
  width: min(var(--dialog-max), calc(100vw - var(--space-8)));
  max-height: calc(100vh - var(--space-8));
  padding: 0;
  border: var(--card-border);
  border-radius: var(--dialog-radius);
  background: var(--color-surface-raised);
  color: var(--color-text);
  box-shadow: var(--shadow-overlay);
}

.dialog::backdrop {
  background: var(--color-overlay);
}

.dialog[open] {
  animation: dialog-in var(--duration-base) var(--ease-standard);
}

.dialog__panel {
  display: grid;
  gap: var(--space-4);
  padding: var(--dialog-padding);
}

.dialog__title {
  font-size: var(--font-size-lg);
}

.dialog__description {
  color: var(--color-text-muted);
}

.dialog__actions {
  display: flex;
  flex-wrap: wrap-reverse;
  justify-content: flex-end;
  gap: var(--space-2);
}

@media (max-width: 30em) {
  .dialog__actions > * {
    flex: 1 1 100%;
  }
}

@keyframes dialog-in {
  from {
    opacity: 0;
    transform: translateY(var(--space-2));
  }
}
</style>
