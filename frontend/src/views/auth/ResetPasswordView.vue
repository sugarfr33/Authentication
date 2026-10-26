<script setup lang="ts">
// The reset link is /reset-password#token=... A rejected new password does not spend the link (API), so the
// user can try another one. Success revokes every session, so the local profile is cleared too.
import { onMounted, ref } from 'vue';
import { RouterLink, useRoute, useRouter } from 'vue-router';
import { authApi } from '@/api';
import { BaseAlert, BaseButton, BaseCard, BaseInput, FormField, PasswordInput } from '@/components/ui';
import { useAuthForm } from '@/composables/useAuthForm';
import { collectErrors, validateNewPassword } from '@/forms/validation';
import { messages } from '@/i18n/messages';
import { takeFragmentToken } from '@/router/fragmentToken';
import { useSessionStore } from '@/stores/session';

const route = useRoute();
const router = useRouter();
const session = useSessionStore();

const token = ref<string | null>(null);
const ready = ref(false);
const newPassword = ref('');
const done = ref(false);
const linkInvalid = ref(false);
const { errors, formError, submitting, run } = useAuthForm(['newPassword'] as const);

onMounted(async () => {
  token.value = await takeFragmentToken(route, router);
  ready.value = true;
});

async function submit(): Promise<void> {
  const value = token.value;
  if (value === null) return;
  await run(
    () => collectErrors({ newPassword: validateNewPassword(newPassword.value) }),
    async () => {
      await authApi.resetPassword(value, newPassword.value);
      newPassword.value = '';
      token.value = null;
      session.clear();
      done.value = true;
    },
    (error) => {
      // A 400 without field errors is the one generic "invalid or expired link" answer.
      if (error.status === 400 && Object.keys(error.fieldErrors).length === 0) {
        linkInvalid.value = true;
        return { form: messages.auth.resetLinkInvalid };
      }
      return null;
    },
  );
}
</script>

<template>
  <div class="page page--narrow stack stack--lg">
    <BaseCard :title="messages.reset.title" :heading-level="1">
      <template v-if="!ready" />
      <BaseAlert v-else-if="done" tone="success" live="polite" :title="messages.reset.doneTitle">
        <div class="stack">
          <p>{{ messages.reset.doneBody }}</p>
          <p><RouterLink to="/login">{{ messages.reset.signIn }}</RouterLink></p>
        </div>
      </BaseAlert>
      <BaseAlert v-else-if="token === null && !linkInvalid" tone="warning">
        <div class="stack">
          <p>{{ messages.reset.missingToken }}</p>
          <p><RouterLink to="/forgot-password">{{ messages.reset.requestNew }}</RouterLink></p>
        </div>
      </BaseAlert>
      <form v-else ref="formEl" class="stack" novalidate @submit.prevent="submit">
        <div v-if="formError" ref="alertEl" tabindex="-1">
          <BaseAlert tone="danger" live="assertive">
            <div class="stack">
              <p>{{ formError }}</p>
              <p v-if="linkInvalid"><RouterLink to="/forgot-password">{{ messages.reset.requestNew }}</RouterLink></p>
            </div>
          </BaseAlert>
        </div>
        <!-- Lets password managers store the new password against an account; the API knows the user from the link. -->
        <BaseInput class="visually-hidden" autocomplete="username" aria-hidden="true" tabindex="-1" />
        <FormField
          v-slot="field"
          :label="messages.fields.newPassword"
          :hint="messages.password.hint"
          :error="errors.newPassword"
          required
        >
          <PasswordInput
            :id="field.id"
            v-model="newPassword"
            name="newPassword"
            autocomplete="new-password"
            show-strength
            :disabled="linkInvalid"
            :described-by="field.describedBy"
            :invalid="field.invalid"
            :required="field.required"
          />
        </FormField>
        <BaseButton type="submit" block :loading="submitting" :disabled="linkInvalid">{{ messages.reset.submit }}</BaseButton>
      </form>
    </BaseCard>
  </div>
</template>
