<script setup lang="ts">
import { ICON_ID_PREFIX, type IconName } from './icons';

withDefaults(
  defineProps<{
    name: IconName;
    size?: 'sm' | 'md' | 'lg';
    /** Accessible name. Omit for decorative icons next to text (the default). */
    label?: string;
  }>(),
  { size: 'md', label: undefined },
);
</script>

<template>
  <svg
    class="icon"
    :class="`icon--${size}`"
    :role="label ? 'img' : undefined"
    :aria-label="label || undefined"
    :aria-hidden="label ? undefined : 'true'"
    focusable="false"
  >
    <use :href="`#${ICON_ID_PREFIX}${name}`" />
  </svg>
</template>

<style scoped>
.icon {
  flex: none;
  fill: none;
  stroke: currentColor;
  stroke-width: 2;
  stroke-linecap: round;
  stroke-linejoin: round;
}

.icon--sm {
  width: var(--icon-size-sm);
  height: var(--icon-size-sm);
}

.icon--md {
  width: var(--icon-size-md);
  height: var(--icon-size-md);
}

.icon--lg {
  width: var(--icon-size-lg);
  height: var(--icon-size-lg);
}
</style>
