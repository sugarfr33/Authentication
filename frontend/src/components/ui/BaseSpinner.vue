<script setup lang="ts">
import { messages } from '@/i18n/messages';

withDefaults(
  defineProps<{
    size?: 'sm' | 'md' | 'lg';
    /** Announced text (role="status"). Ignored when decorative. */
    label?: string;
    /** Inside a busy control that already says what is happening: hidden from assistive tech. */
    decorative?: boolean;
  }>(),
  { size: 'md', label: messages.common.loading, decorative: false },
);
</script>

<template>
  <span v-if="decorative" class="spinner" :class="`spinner--${size}`" aria-hidden="true" />
  <span v-else class="spinner-status" role="status">
    <span class="spinner" :class="`spinner--${size}`" aria-hidden="true" />
    <span class="visually-hidden">{{ label }}</span>
  </span>
</template>

<style scoped>
.spinner-status {
  display: inline-flex;
  align-items: center;
}

.spinner {
  display: inline-block;
  flex: none;
  border: var(--spinner-stroke) solid currentColor;
  border-inline-end-color: transparent;
  border-radius: var(--radius-full);
  animation: spin calc(var(--duration-slow) * 2.5) linear infinite;
}

.spinner--sm {
  width: var(--spinner-size-sm);
  height: var(--spinner-size-sm);
}

.spinner--md {
  width: var(--spinner-size-md);
  height: var(--spinner-size-md);
}

.spinner--lg {
  width: var(--spinner-size-lg);
  height: var(--spinner-size-lg);
}

@keyframes spin {
  to {
    transform: rotate(1turn);
  }
}
</style>
