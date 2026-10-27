<script setup lang="ts">
// Error summary for a form with several invalid fields (T31, WCAG 3.3.1 / 2.4.3). It is not a live region: the
// field errors are announced where they are, and useAuthForm moves focus here, so the summary is read once. Each
// entry is a link that moves focus to its field (found by its name attribute inside the same form).
import { computed, ref, useId } from 'vue';
import { messages } from '@/i18n/messages';
import BaseIcon from './BaseIcon.vue';

const props = defineProps<{
  /** Field key (the input's name attribute) to its error message; empty or missing means valid. */
  errors: Readonly<Partial<Record<string, string>>>;
  /** Field key to its visible label, in form order. */
  labels: Readonly<Record<string, string>>;
}>();

const root = ref<HTMLElement | null>(null);
// useId: stable across server and client renders and unique per instance (no Math.random).
const titleId = `error-summary-${useId()}`;

const entries = computed(() =>
  Object.entries(props.labels)
    .map(([name, label]) => ({ name, label, message: props.errors[name] ?? '' }))
    .filter((entry) => entry.message.length > 0),
);

function goTo(event: MouseEvent, name: string): void {
  event.preventDefault();
  root.value?.closest('form')?.querySelector<HTMLElement>(`[name="${CSS.escape(name)}"]`)?.focus();
}

defineExpose({
  focus(): void {
    root.value?.focus();
  },
});
</script>

<template>
  <!-- role=group so aria-labelledby is allowed and the title names the summary when focus lands on it. -->
  <div ref="root" class="error-summary" role="group" tabindex="-1" :aria-labelledby="titleId">
    <BaseIcon class="error-summary__icon" name="danger" />
    <div>
      <p :id="titleId" class="error-summary__title">{{ messages.validation.formHasErrors }}</p>
      <ul class="error-summary__list">
        <li v-for="entry in entries" :key="entry.name">
          <a :href="`#${entry.name}`" @click="goTo($event, entry.name)">{{ entry.label }}: {{ entry.message }}</a>
        </li>
      </ul>
    </div>
  </div>
</template>

<style scoped>
.error-summary {
  display: flex;
  gap: var(--space-3);
  padding: var(--space-4);
  border: var(--border-width) solid var(--color-danger-border);
  border-radius: var(--radius-md);
  background: var(--color-danger-bg);
  color: var(--color-danger-on-bg);
}

.error-summary:focus-visible,
.error-summary:focus {
  outline: var(--focus-ring);
  outline-offset: var(--focus-ring-offset);
}

.error-summary__icon {
  flex: none;
}

.error-summary__title {
  margin: 0 0 var(--space-2);
  font-weight: var(--font-weight-semibold);
}

.error-summary__list {
  margin: 0;
  padding-inline-start: var(--space-4);
}

/* Same colour as the text (a verified pair with the background), told apart by the underline. */
.error-summary__list a {
  color: inherit;
  text-decoration: underline;
}
</style>
