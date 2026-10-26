<script setup lang="ts">
// Same confirmation for every well-formed address (the API answers an identical 202): no user enumeration.
import { ref } from 'vue';
import { RouterLink } from 'vue-router';
import { authApi } from '@/api';
import { BaseAlert, BaseButton, BaseCard, BaseInput, FormField } from '@/components/ui';
import { useAuthForm } from '@/composables/useAuthForm';
import { collectErrors, validateEmail } from '@/forms/validation';
import { messages } from '@/i18n/messages';

const email = ref('');
const accepted = ref(false);
const { errors, formError, submitting, run } = useAuthForm(['email'] as const);

async function submit(): Promise<void> {
  await run(
    () => collectErrors({ email: validateEmail(email.value) }),
    async () => {
      await authApi.forgotPassword(email.value.trim());
      accepted.value = true;
    },
  );
}
</script>

<template>
  <div class="page page--narrow stack stack--lg">
    <BaseCard :title="messages.forgot.title" :heading-level="1">
      <BaseAlert v-if="accepted" tone="success" live="polite" :title="messages.forgot.acceptedTitle">
        {{ messages.auth.forgotAccepted }}
      </BaseAlert>
      <form v-else ref="formEl" class="stack" novalidate @submit.prevent="submit">
        <p>{{ messages.forgot.intro }}</p>
        <div v-if="formError" ref="alertEl" tabindex="-1">
          <BaseAlert tone="danger" live="assertive">{{ formError }}</BaseAlert>
        </div>
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
        <BaseButton type="submit" block :loading="submitting">{{ messages.forgot.submit }}</BaseButton>
      </form>
      <template #footer>
        <p><RouterLink to="/login">{{ messages.forgot.backToSignIn }}</RouterLink></p>
      </template>
    </BaseCard>
  </div>
</template>
