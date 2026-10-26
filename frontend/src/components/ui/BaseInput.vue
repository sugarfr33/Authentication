<script setup lang="ts">
import { ref } from 'vue';
import type { PasswordAutocomplete, TextAutocomplete } from './types';

withDefaults(
  defineProps<{
    id?: string;
    type?: 'text' | 'email' | 'password' | 'search' | 'tel' | 'url';
    /** Required on purpose: every field states its autocomplete token (WCAG 1.3.5). */
    autocomplete: TextAutocomplete | PasswordAutocomplete;
    name?: string;
    invalid?: boolean;
    describedBy?: string;
    disabled?: boolean;
    readonly?: boolean;
    required?: boolean;
    inputmode?: 'text' | 'email' | 'numeric' | 'tel' | 'url' | 'search';
    spellcheck?: boolean;
    autocapitalize?: 'off' | 'none' | 'sentences' | 'words';
    maxlength?: number;
  }>(),
  {
    id: undefined,
    type: 'text',
    name: undefined,
    invalid: false,
    describedBy: undefined,
    disabled: false,
    readonly: false,
    required: false,
    inputmode: undefined,
    spellcheck: undefined,
    autocapitalize: undefined,
    maxlength: undefined,
  },
);

const model = defineModel<string>({ default: '' });

const el = ref<HTMLInputElement | null>(null);
defineExpose({ focus: () => el.value?.focus() });
</script>

<template>
  <input
    :id="id"
    ref="el"
    v-model="model"
    class="input"
    :class="{ 'input--invalid': invalid }"
    :type="type"
    :name="name"
    :autocomplete="autocomplete"
    :inputmode="inputmode"
    :spellcheck="spellcheck"
    :autocapitalize="autocapitalize"
    :maxlength="maxlength"
    :disabled="disabled"
    :readonly="readonly"
    :required="required"
    :aria-invalid="invalid ? 'true' : undefined"
    :aria-describedby="describedBy || undefined"
  />
</template>

<style scoped>
.input {
  display: block;
  width: 100%;
  min-height: var(--input-height);
  padding: var(--space-2) var(--input-padding-x);
  border: var(--input-border);
  border-radius: var(--input-radius);
  background: var(--input-bg);
  color: var(--color-text);
  font-size: var(--font-size-md);
  line-height: var(--line-height-normal);
  transition: border-color var(--duration-fast) var(--ease-standard);
}

.input:hover:not(:disabled, [readonly]) {
  border-color: var(--color-text-muted);
}

.input:focus-visible {
  outline: var(--focus-ring);
  outline-offset: var(--focus-ring-offset);
}

.input--invalid {
  border-color: var(--color-danger-text);
  border-width: var(--border-width-thick);
}

.input:disabled {
  background: var(--color-surface-sunken);
  border-color: var(--color-border);
  color: var(--color-text-disabled);
  cursor: not-allowed;
}

.input[readonly] {
  background: var(--color-surface-sunken);
}
</style>
