<script setup lang="ts">
import { computed } from 'vue';
import { messages } from '@/i18n/messages';
import BaseIcon from './BaseIcon.vue';
import type { Tone } from './types';

const props = withDefaults(
  defineProps<{
    tone?: Tone;
    title?: string;
    /**
     * off: static content (present at page load). polite: role="status" (async results).
     * assertive: role="alert" (errors that need attention now, e.g. a failed submit).
     */
    live?: 'off' | 'polite' | 'assertive';
    dismissible?: boolean;
  }>(),
  { tone: 'info', title: undefined, live: 'off', dismissible: false },
);

const emit = defineEmits<{ dismiss: [] }>();
defineSlots<{ default(): unknown }>();

const role = computed(() => (props.live === 'assertive' ? 'alert' : props.live === 'polite' ? 'status' : undefined));
</script>

<template>
  <div class="alert" :class="`alert--${tone}`" :role="role">
    <BaseIcon class="alert__icon" :name="tone" />
    <div class="alert__content">
      <p v-if="title" class="alert__title">
        <span class="visually-hidden">{{ messages.tone[tone] }}: </span>{{ title }}
      </p>
      <span v-else class="visually-hidden">{{ messages.tone[tone] }}: </span>
      <div class="alert__body"><slot /></div>
    </div>
    <button v-if="dismissible" type="button" class="alert__dismiss" @click="emit('dismiss')">
      <BaseIcon name="close" size="sm" />
      <span class="visually-hidden">{{ messages.common.close }}</span>
    </button>
  </div>
</template>

<style scoped>
.alert {
  display: flex;
  align-items: flex-start;
  gap: var(--space-3);
  padding: var(--alert-padding);
  border: var(--border-width) solid;
  border-radius: var(--alert-radius);
}

.alert__icon {
  margin-block-start: var(--space-1);
}

.alert__content {
  flex: 1;
  min-width: 0;
  display: grid;
  gap: var(--space-1);
}

.alert__title {
  font-weight: var(--font-weight-semibold);
}

.alert--info {
  background: var(--color-info-bg);
  border-color: var(--color-info-border);
  color: var(--color-info-on-bg);
}

.alert--success {
  background: var(--color-success-bg);
  border-color: var(--color-success-border);
  color: var(--color-success-on-bg);
}

.alert--warning {
  background: var(--color-warning-bg);
  border-color: var(--color-warning-border);
  color: var(--color-warning-on-bg);
}

.alert--danger {
  background: var(--color-danger-bg);
  border-color: var(--color-danger-border);
  color: var(--color-danger-on-bg);
}

.alert__dismiss {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: var(--target-min);
  height: var(--target-min);
  margin: calc(var(--space-1) * -1);
  padding: 0;
  border: 0;
  border-radius: var(--radius-sm);
  background: transparent;
  color: inherit;
  cursor: pointer;
}

.alert__dismiss:focus-visible {
  outline: var(--focus-ring);
  outline-offset: var(--focus-ring-offset);
}
</style>
