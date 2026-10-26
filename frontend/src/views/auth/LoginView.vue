<script setup lang="ts">
import { ref } from 'vue';
import { RouterLink, useRoute, useRouter } from 'vue-router';
import { BaseAlert, BaseButton, BaseCard, BaseInput, FormField, PasswordInput } from '@/components/ui';
import { useAuthForm } from '@/composables/useAuthForm';
import { collectErrors, validateCurrentPassword, validateEmail } from '@/forms/validation';
import { messages } from '@/i18n/messages';
import { continueAfterSignIn, returnToQuery } from '@/router/returnTo';
import { useSessionStore } from '@/stores/session';

const route = useRoute();
const router = useRouter();
const session = useSessionStore();

const email = ref('');
const password = ref('');
const { errors, formError, submitting, run } = useAuthForm(['email', 'password'] as const);

async function submit(): Promise<void> {
  await run(
    () => collectErrors({ email: validateEmail(email.value), password: validateCurrentPassword(password.value) }),
    async () => {
      const result = await session.signIn(email.value.trim(), password.value);
      password.value = '';
      if (result.kind === 'mfa-required') {
        await router.push({ name: 'mfa-challenge', query: returnToQuery(route.query.returnTo) });
        return;
      }
      await continueAfterSignIn(router, route.query.returnTo);
    },
    (error) => {
      // One generic answer for every sign-in failure: it never says whether the account exists.
      if (error.status === 401) {
        password.value = '';
        return { form: messages.auth.loginFailed };
      }
      return null;
    },
  );
}
</script>

<template>
  <div class="page page--narrow stack stack--lg">
    <BaseCard :title="messages.login.title" :heading-level="1">
      <form ref="formEl" class="stack" novalidate @submit.prevent="submit">
        <div v-if="formError" ref="alertEl" tabindex="-1">
          <BaseAlert tone="danger" live="assertive">{{ formError }}</BaseAlert>
        </div>
        <FormField v-slot="field" :label="messages.fields.email" :error="errors.email" required>
          <BaseInput
            :id="field.id"
            v-model="email"
            type="email"
            name="email"
            autocomplete="username"
            inputmode="email"
            autocapitalize="off"
            :spellcheck="false"
            :described-by="field.describedBy"
            :invalid="field.invalid"
            :required="field.required"
          />
        </FormField>
        <FormField v-slot="field" :label="messages.fields.password" :error="errors.password" required>
          <PasswordInput
            :id="field.id"
            v-model="password"
            name="password"
            autocomplete="current-password"
            :described-by="field.describedBy"
            :invalid="field.invalid"
            :required="field.required"
          />
        </FormField>
        <BaseButton type="submit" block :loading="submitting">{{ messages.login.submit }}</BaseButton>
        <p><RouterLink to="/forgot-password">{{ messages.login.forgot }}</RouterLink></p>
      </form>
      <template #footer>
        <p class="muted">
          {{ messages.login.noAccount }} <RouterLink to="/register">{{ messages.login.register }}</RouterLink>
        </p>
      </template>
    </BaseCard>
  </div>
</template>
