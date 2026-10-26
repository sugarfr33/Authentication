<script setup lang="ts">
import { ref } from 'vue';
import BaseIcon from './BaseIcon.vue';
import BaseSpinner from './BaseSpinner.vue';
import type { IconName } from './icons';
import type { ButtonSize, ButtonVariant } from './types';

const props = withDefaults(
  defineProps<{
    variant?: ButtonVariant;
    size?: ButtonSize;
    type?: 'button' | 'submit' | 'reset';
    disabled?: boolean;
    /** Busy: stays focusable and keeps its label, but ignores activation (no double submit). */
    loading?: boolean;
    block?: boolean;
    icon?: IconName;
  }>(),
  { variant: 'primary', size: 'md', type: 'button', disabled: false, loading: false, block: false, icon: undefined },
);

const emit = defineEmits<{ click: [event: MouseEvent] }>();
defineSlots<{ default(): unknown }>();

const el = ref<HTMLButtonElement | null>(null);
defineExpose({ focus: () => el.value?.focus() });

function onClick(event: MouseEvent): void {
  if (props.loading) {
    event.preventDefault();
    return;
  }
  emit('click', event);
}
</script>

<template>
  <button
    ref="el"
    class="btn"
    :class="[`btn--${variant}`, `btn--${size}`, { 'btn--block': block, 'btn--loading': loading }]"
    :type="type"
    :disabled="disabled"
    :aria-busy="loading ? 'true' : undefined"
    @click="onClick"
  >
    <BaseSpinner v-if="loading" size="sm" decorative />
    <BaseIcon v-else-if="icon" :name="icon" size="sm" />
    <span class="btn__label"><slot /></span>
  </button>
</template>

<style scoped>
.btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: var(--space-2);
  min-width: var(--target-min);
  border: var(--border-width) solid transparent;
  border-radius: var(--button-radius);
  font-weight: var(--button-font-weight);
  line-height: var(--line-height-tight);
  text-align: center;
  cursor: pointer;
  transition:
    background-color var(--duration-fast) var(--ease-standard),
    border-color var(--duration-fast) var(--ease-standard),
    color var(--duration-fast) var(--ease-standard);
}

.btn--sm {
  min-height: var(--button-height-sm);
  padding: 0 var(--button-padding-x-sm);
  font-size: var(--font-size-sm);
}

.btn--md {
  min-height: var(--button-height-md);
  padding: 0 var(--button-padding-x-md);
  font-size: var(--font-size-md);
}

.btn--lg {
  min-height: var(--button-height-lg);
  padding: 0 var(--button-padding-x-lg);
  font-size: var(--font-size-lg);
}

.btn--block {
  width: 100%;
}

.btn--primary {
  background: var(--color-primary);
  color: var(--color-on-primary);
}

.btn--primary:hover:not(:disabled) {
  background: var(--color-primary-hover);
}

.btn--primary:active:not(:disabled) {
  background: var(--color-primary-active);
}

.btn--secondary {
  background: var(--color-surface);
  border-color: var(--color-border-strong);
  color: var(--color-text);
}

.btn--secondary:hover:not(:disabled) {
  background: var(--color-surface-sunken);
}

.btn--ghost {
  background: transparent;
  color: var(--color-link);
}

.btn--ghost:hover:not(:disabled) {
  background: var(--color-primary-subtle);
}

.btn--danger {
  background: var(--color-danger);
  color: var(--color-on-danger);
}

.btn--danger:hover:not(:disabled) {
  background: var(--color-danger-hover);
}

.btn:disabled {
  background: var(--color-surface-sunken);
  border-color: var(--color-border);
  color: var(--color-text-disabled);
  cursor: not-allowed;
}

.btn--loading {
  cursor: progress;
}

.btn:focus-visible {
  outline: var(--focus-ring);
  outline-offset: var(--focus-ring-offset);
}
</style>
