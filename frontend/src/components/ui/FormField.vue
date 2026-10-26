<script setup lang="ts">
import { computed, useId } from 'vue';
import BaseIcon from './BaseIcon.vue';

const props = withDefaults(
  defineProps<{
    label: string;
    /** Control id; generated when omitted. */
    id?: string;
    hint?: string;
    /** Error text. Rendered next to the control, linked with aria-describedby and announced politely. */
    error?: string | null;
    required?: boolean;
  }>(),
  { id: undefined, hint: undefined, error: null, required: false },
);

defineSlots<{
  default(props: { id: string; describedBy: string | undefined; invalid: boolean; required: boolean }): unknown;
}>();

const generatedId = useId();
const fieldId = computed(() => props.id ?? `field-${generatedId}`);
const hintId = computed(() => `${fieldId.value}-hint`);
const errorId = computed(() => `${fieldId.value}-error`);
const hasError = computed(() => typeof props.error === 'string' && props.error.length > 0);
const describedBy = computed(() => {
  const ids = [props.hint ? hintId.value : null, hasError.value ? errorId.value : null].filter((v) => v !== null);
  return ids.length > 0 ? ids.join(' ') : undefined;
});
</script>

<template>
  <div class="field" :class="{ 'field--invalid': hasError }">
    <label :for="fieldId" class="field__label">
      {{ label }}<span v-if="required" class="field__required" aria-hidden="true">*</span>
    </label>
    <p v-if="hint" :id="hintId" class="field__hint">{{ hint }}</p>
    <slot :id="fieldId" :describedBy="describedBy" :invalid="hasError" :required="required" />
    <p :id="errorId" class="field__error" aria-live="polite">
      <template v-if="hasError">
        <BaseIcon name="danger" size="sm" />
        <span>{{ error }}</span>
      </template>
    </p>
  </div>
</template>

<style scoped>
.field {
  display: grid;
  gap: var(--space-1);
}

.field__label {
  font-weight: var(--font-weight-medium);
  font-size: var(--font-size-sm);
  color: var(--color-text);
}

.field__required {
  margin-inline-start: var(--space-1);
  color: var(--color-danger-text);
}

.field__hint {
  font-size: var(--font-size-sm);
  color: var(--color-text-muted);
}

.field__error {
  display: flex;
  align-items: flex-start;
  gap: var(--space-1);
  font-size: var(--font-size-sm);
  color: var(--color-danger-text);
}

.field__error:empty {
  min-height: 0;
}
</style>
