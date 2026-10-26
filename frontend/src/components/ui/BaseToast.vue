<script setup lang="ts">
import { onBeforeUnmount, onMounted } from 'vue';
import { messages } from '@/i18n/messages';
import BaseIcon from './BaseIcon.vue';
import type { Tone } from './types';

const props = defineProps<{
  tone: Tone;
  message: string;
  timeoutMs: number | null;
}>();

const emit = defineEmits<{ dismiss: [] }>();

let timer: ReturnType<typeof setTimeout> | null = null;

function start(): void {
  stop();
  if (props.timeoutMs !== null) timer = setTimeout(() => emit('dismiss'), props.timeoutMs);
}

function stop(): void {
  if (timer !== null) clearTimeout(timer);
  timer = null;
}

onMounted(start);
onBeforeUnmount(stop);
</script>

<template>
  <div
    class="toast"
    :class="`toast--${tone}`"
    @mouseenter="stop"
    @mouseleave="start"
    @focusin="stop"
    @focusout="start"
  >
    <BaseIcon class="toast__icon" :name="tone" />
    <p class="toast__message"><span class="visually-hidden">{{ messages.tone[tone] }}: </span>{{ message }}</p>
    <button type="button" class="toast__dismiss" @click="emit('dismiss')">
      <BaseIcon name="close" size="sm" />
      <span class="visually-hidden">{{ messages.common.dismiss }}</span>
    </button>
  </div>
</template>

<style scoped>
.toast {
  display: flex;
  align-items: flex-start;
  gap: var(--space-3);
  width: 100%;
  padding: var(--space-3) var(--space-4);
  border: var(--border-width) solid var(--color-border);
  border-inline-start-width: var(--space-1);
  border-radius: var(--toast-radius);
  background: var(--color-surface-raised);
  color: var(--color-text);
  box-shadow: var(--shadow-toast);
}

.toast__icon {
  margin-block-start: var(--space-1);
}

.toast__message {
  flex: 1;
  min-width: 0;
}

.toast--info {
  border-inline-start-color: var(--color-primary);
}

.toast--info .toast__icon {
  color: var(--color-primary);
}

.toast--success {
  border-inline-start-color: var(--color-success-text);
}

.toast--success .toast__icon {
  color: var(--color-success-text);
}

.toast--warning {
  border-inline-start-color: var(--color-warning-text);
}

.toast--warning .toast__icon {
  color: var(--color-warning-text);
}

.toast--danger {
  border-inline-start-color: var(--color-danger-text);
}

.toast--danger .toast__icon {
  color: var(--color-danger-text);
}

.toast__dismiss {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: var(--target-min);
  height: var(--target-min);
  padding: 0;
  border: 0;
  border-radius: var(--radius-sm);
  background: transparent;
  color: var(--color-text-muted);
  cursor: pointer;
}

.toast__dismiss:hover {
  color: var(--color-text);
}

.toast__dismiss:focus-visible {
  outline: var(--focus-ring);
  outline-offset: var(--focus-ring-offset);
}
</style>
