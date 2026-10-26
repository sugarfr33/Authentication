<script setup lang="ts">
import { useId, useSlots } from 'vue';

withDefaults(
  defineProps<{
    title?: string;
    headingLevel?: 1 | 2 | 3 | 4;
    as?: 'section' | 'article' | 'div';
  }>(),
  { title: undefined, headingLevel: 2, as: 'section' },
);

defineSlots<{ default(): unknown; actions?(): unknown; footer?(): unknown }>();
const slots = useSlots();
const headingId = `card-${useId()}`;
</script>

<template>
  <component :is="as" class="card" :aria-labelledby="title ? headingId : undefined">
    <header v-if="title || slots.actions" class="card__header">
      <component :is="`h${headingLevel}`" v-if="title" :id="headingId" class="card__title">{{ title }}</component>
      <div v-if="slots.actions" class="card__actions"><slot name="actions" /></div>
    </header>
    <div class="card__body"><slot /></div>
    <footer v-if="slots.footer" class="card__footer"><slot name="footer" /></footer>
  </component>
</template>

<style scoped>
.card {
  display: grid;
  gap: var(--space-4);
  padding: var(--card-padding);
  border: var(--card-border);
  border-radius: var(--card-radius);
  background: var(--color-surface);
  box-shadow: var(--shadow-raised);
}

.card__header {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: space-between;
  gap: var(--space-3);
}

.card__title {
  font-size: var(--font-size-lg);
}

.card__actions {
  display: flex;
  flex-wrap: wrap;
  gap: var(--space-2);
}

.card__body {
  display: grid;
  gap: var(--space-4);
}

.card__footer {
  display: flex;
  flex-wrap: wrap;
  justify-content: flex-end;
  gap: var(--space-2);
  padding-top: var(--space-4);
  border-top: var(--card-border);
}

@media (max-width: 30em) {
  .card {
    padding: var(--space-4);
  }
}
</style>
