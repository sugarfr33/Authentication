<script setup lang="ts">
// The API answers the same 202 whether or not the address already has an account, so this page shows the
// same confirmation every time (no user enumeration). Field errors from the API's ValidationProblem are shown
// as text under their fields.
import { ref } from 'vue';
import { RouterLink } from 'vue-router';
import { authApi } from '@/api';
import { BaseAlert, BaseButton, BaseCard, BaseInput, FormErrorSummary, FormField, PasswordInput } from '@/components/ui';
import { useAuthForm, useFocusTarget } from '@/composables/useAuthForm';
import { collectErrors, validateDisplayName, validateEmail, validateNewPassword } from '@/forms/validation';
import { messages } from '@/i18n/messages';

const displayName = ref('');
const email = ref('');
const password = ref('');
const accepted = ref(false);
const { errors, formError, submitting, errorCount, run } = useAuthForm(['displayName', 'email', 'password'] as const);
const successMessage = useFocusTarget('successEl');

async function submit(): Promise<void> {
  await run(
    () =>
      collectErrors({
        displayName: validateDisplayName(displayName.value),
        email: validateEmail(email.value),
        password: validateNewPassword(password.value, email.value, messages.validation.choosePasswordRequired),
      }),
    async () => {
      await authApi.register({ displayName: displayName.value.trim(), email: email.value.trim(), password: password.value });
      password.value = '';
      accepted.value = true;
      await successMessage.focus();
    },
  );
}
</script>

<template>
  <div class="page page--narrow stack stack--lg">
    <BaseCard :title="messages.register.title" :heading-level="1">
      <div v-if="accepted" ref="successEl" tabindex="-1">
        <BaseAlert tone="success" live="polite" :title="messages.register.acceptedTitle">
          {{ messages.auth.registerAccepted }}
        </BaseAlert>
      </div>
      <form v-else ref="formEl" class="stack" novalidate @submit.prevent="submit">
        <div v-if="formError" ref="alertEl" tabindex="-1">
          <BaseAlert tone="danger" live="assertive">{{ formError }}</BaseAlert>
        </div>
        <FormErrorSummary
          v-if="errorCount >= 2"
          ref="summaryEl"
          :errors="errors"
          :labels="{ displayName: messages.fields.displayName, email: messages.fields.email, password: messages.fields.password }"
        />
        <FormField
          v-slot="field"
          :label="messages.fields.displayName"
          :hint="messages.fields.displayNameHint"
          :error="errors.displayName"
          required
        >
          <BaseInput
            :id="field.id"
            v-model="displayName"
            name="displayName"
            autocomplete="name"
            :maxlength="128"
            :described-by="field.describedBy"
            :invalid="field.invalid"
            :required="field.required"
          />
        </FormField>
        <FormField v-slot="field" :label="messages.fields.email" :error="errors.email" required>
          <BaseInput
            :id="field.id"
            v-model="email"
            type="email"
            name="email"
            autocomplete="email"
            inputmode="email"
            autocapitalize="off"
            :spellcheck="false"
            :described-by="field.describedBy"
            :invalid="field.invalid"
            :required="field.required"
          />
        </FormField>
        <FormField
          v-slot="field"
          :label="messages.fields.password"
          :hint="messages.password.hint"
          :error="errors.password"
          required
        >
          <PasswordInput
            :id="field.id"
            v-model="password"
            name="password"
            autocomplete="new-password"
            show-strength
            :described-by="field.describedBy"
            :invalid="field.invalid"
            :required="field.required"
          />
        </FormField>
        <BaseButton type="submit" block :loading="submitting">{{ messages.register.submit }}</BaseButton>
      </form>
      <template #footer>
        <p class="muted">
          {{ messages.register.haveAccount }} <RouterLink to="/login">{{ messages.register.signIn }}</RouterLink>
        </p>
      </template>
    </BaseCard>
  </div>
</template>
