<script setup lang="ts">
import { computed, ref, useId } from 'vue';
import { format, messages } from '@/i18n/messages';
import BaseIcon from './BaseIcon.vue';
import BaseInput from './BaseInput.vue';
import { estimatePasswordStrength } from './passwordStrength';
import type { PasswordAutocomplete } from './types';

const props = withDefaults(
  defineProps<{
    id?: string;
    /** current-password on sign-in, new-password on register/reset/change: password managers rely on it. */
    autocomplete: PasswordAutocomplete;
    name?: string;
    invalid?: boolean;
    describedBy?: string;
    required?: boolean;
    disabled?: boolean;
    /** Show the strength hint (for new passwords). */
    showStrength?: boolean;
  }>(),
  {
    id: undefined,
    name: undefined,
    invalid: false,
    describedBy: undefined,
    required: false,
    disabled: false,
    showStrength: false,
  },
);

const model = defineModel<string>({ default: '' });

const generatedId = useId();
const inputId = computed(() => props.id ?? `password-${generatedId}`);
const strengthId = computed(() => `${inputId.value}-strength`);
const visible = ref(false);

const strength = computed(() => estimatePasswordStrength(model.value));
const strengthText = computed(() =>
  format(messages.password.strengthLabel, { level: messages.password.strength[strength.value] }),
);
const showMeter = computed(() => props.showStrength && model.value.length > 0);
const describedBy = computed(() => {
  const ids = [props.describedBy, showMeter.value ? strengthId.value : undefined].filter((v) => !!v);
  return ids.length > 0 ? ids.join(' ') : undefined;
});

const input = ref<InstanceType<typeof BaseInput> | null>(null);
defineExpose({ focus: () => input.value?.focus() });
</script>

<template>
  <div class="password">
    <div class="password__control">
      <BaseInput
        :id="inputId"
        ref="input"
        v-model="model"
        class="password__input"
        :type="visible ? 'text' : 'password'"
        :autocomplete="autocomplete"
        :name="name"
        :invalid="invalid"
        :described-by="describedBy"
        :required="required"
        :disabled="disabled"
        :spellcheck="false"
        autocapitalize="off"
      />
      <button
        type="button"
        class="password__toggle"
        :aria-pressed="visible ? 'true' : 'false'"
        :aria-controls="inputId"
        :disabled="disabled"
        @click="visible = !visible"
      >
        <BaseIcon :name="visible ? 'eye-off' : 'eye'" />
        <span class="visually-hidden">{{ messages.password.show }}</span>
      </button>
    </div>
    <div v-if="showMeter" class="password__strength">
      <div class="password__bars" aria-hidden="true">
        <span v-for="n in 4" :key="n" class="password__bar" :class="{ 'password__bar--on': n <= strength }" />
      </div>
      <p :id="strengthId" class="password__strength-text">{{ strengthText }}</p>
    </div>
  </div>
</template>

<style scoped>
.password {
  display: grid;
  gap: var(--space-2);
}

.password__control {
  position: relative;
}

.password__control .password__input {
  padding-inline-end: calc(var(--target-comfortable) + var(--space-1));
}

.password__toggle {
  position: absolute;
  inset-block: 0;
  inset-inline-end: 0;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: var(--target-comfortable);
  min-height: var(--target-comfortable);
  border: 0;
  border-radius: var(--input-radius);
  background: transparent;
  color: var(--color-text-muted);
  cursor: pointer;
}

.password__toggle:hover:not(:disabled) {
  color: var(--color-text);
}

.password__toggle[aria-pressed='true'] {
  color: var(--color-primary);
}

.password__toggle:focus-visible {
  outline: var(--focus-ring);
  outline-offset: calc(var(--focus-ring-offset) * -1);
}

.password__toggle:disabled {
  color: var(--color-text-disabled);
  cursor: not-allowed;
}

.password__strength {
  display: grid;
  gap: var(--space-1);
}

.password__bars {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: var(--space-1);
}

.password__bar {
  height: var(--space-1);
  border-radius: var(--radius-full);
  background: var(--color-border);
}

.password__bar--on {
  background: var(--color-primary);
}

.password__strength-text {
  font-size: var(--font-size-sm);
  color: var(--color-text-muted);
}
</style>
