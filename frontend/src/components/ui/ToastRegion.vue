<script setup lang="ts">
// Two live regions that exist from page load (a region added together with its content is often not
// announced): polite for info/success, assertive for warnings and errors. The assertive one is a plain
// aria-live region, not role="alert": an empty alert on every page is announced by some screen readers on
// load (T31, UX review m5); aria-live="assertive" still interrupts when a toast is added.
import { computed } from 'vue';
import { useToast } from '@/composables/useToast';
import { messages } from '@/i18n/messages';
import BaseToast from './BaseToast.vue';

const { items, dismiss } = useToast();
const polite = computed(() => items.value.filter((t) => t.tone === 'info' || t.tone === 'success'));
const urgent = computed(() => items.value.filter((t) => t.tone === 'warning' || t.tone === 'danger'));
</script>

<template>
  <div class="toasts">
    <section class="toasts__region" aria-live="assertive" :aria-label="messages.common.urgentNotifications">
      <BaseToast
        v-for="toast in urgent"
        :key="toast.id"
        :tone="toast.tone"
        :message="toast.message"
        :timeout-ms="toast.timeoutMs"
        @dismiss="dismiss(toast.id)"
      />
    </section>
    <section class="toasts__region" role="status" aria-live="polite" :aria-label="messages.common.notifications">
      <BaseToast
        v-for="toast in polite"
        :key="toast.id"
        :tone="toast.tone"
        :message="toast.message"
        :timeout-ms="toast.timeoutMs"
        @dismiss="dismiss(toast.id)"
      />
    </section>
  </div>
</template>

<style scoped>
.toasts {
  position: fixed;
  inset-block-end: var(--space-4);
  inset-inline-end: var(--space-4);
  z-index: var(--z-toast);
  display: grid;
  gap: var(--space-2);
  width: min(var(--toast-width), calc(100vw - var(--space-8)));
  pointer-events: none;
}

.toasts__region {
  display: grid;
  gap: var(--space-2);
}

.toasts__region > * {
  pointer-events: auto;
}

@media (max-width: 30em) {
  .toasts {
    inset-inline: var(--space-4);
    width: auto;
  }
}
</style>
