<script setup lang="ts">
// Second sign-in step. The challenge is an HttpOnly cookie set by POST /auth/login (202); this page never
// sees it. A wrong code keeps the challenge, so the user can type the next code; an expired challenge needs
// a new sign-in (same generic message either way).
import { nextTick, ref } from 'vue';
import { RouterLink, useRoute, useRouter } from 'vue-router';
import { BaseAlert, BaseButton, BaseCard, BaseInput, FormField } from '@/components/ui';
import { useAuthForm } from '@/composables/useAuthForm';
import { collectErrors, validateRecoveryCode, validateTotpCode } from '@/forms/validation';
import { messages } from '@/i18n/messages';
import { continueAfterSignIn, returnToQuery } from '@/router/returnTo';
import { useSessionStore } from '@/stores/session';

const route = useRoute();
const router = useRouter();
const session = useSessionStore();

const useRecovery = ref(false);
const code = ref('');
const codeInput = ref<InstanceType<typeof BaseInput> | null>(null);
const { errors, formError, submitting, run, clear } = useAuthForm(['code'] as const);

async function switchMode(): Promise<void> {
  useRecovery.value = !useRecovery.value;
  code.value = '';
  clear();
  await nextTick();
  codeInput.value?.focus();
}

async function submit(): Promise<void> {
  await run(
    () => collectErrors({ code: useRecovery.value ? validateRecoveryCode(code.value) : validateTotpCode(code.value) }),
    async () => {
      await session.completeMfa(code.value.trim(), useRecovery.value);
      await continueAfterSignIn(router, route.query.returnTo);
    },
    (error) => {
      if (error.status === 401) {
        code.value = '';
        return { form: messages.mfaChallenge.failed, focus: 'code' };
      }
      return null;
    },
  );
}
</script>

<template>
  <div class="page page--narrow stack stack--lg">
    <BaseCard :title="messages.mfaChallenge.title" :heading-level="1">
      <p>{{ useRecovery ? messages.mfaChallenge.introRecovery : messages.mfaChallenge.intro }}</p>
      <form ref="formEl" class="stack" novalidate @submit.prevent="submit">
        <div v-if="formError" ref="alertEl" tabindex="-1">
          <BaseAlert tone="danger" live="assertive">
            <div class="stack">
              <p>{{ formError }}</p>
              <p>
                <RouterLink :to="{ name: 'login', query: returnToQuery(route.query.returnTo) }">{{
                  messages.mfaChallenge.restart
                }}</RouterLink>
              </p>
            </div>
          </BaseAlert>
        </div>
        <FormField
          v-if="!useRecovery"
          v-slot="field"
          :label="messages.fields.code"
          :hint="messages.fields.codeHint"
          :error="errors.code"
          required
        >
          <BaseInput
            :id="field.id"
            ref="codeInput"
            v-model="code"
            name="code"
            autocomplete="one-time-code"
            inputmode="numeric"
            :maxlength="10"
            :spellcheck="false"
            :described-by="field.describedBy"
            :invalid="field.invalid"
            :required="field.required"
          />
        </FormField>
        <FormField
          v-else
          v-slot="field"
          :label="messages.fields.recoveryCode"
          :hint="messages.fields.recoveryCodeHint"
          :error="errors.code"
          required
        >
          <BaseInput
            :id="field.id"
            ref="codeInput"
            v-model="code"
            name="code"
            autocomplete="off"
            autocapitalize="characters"
            :maxlength="20"
            :spellcheck="false"
            :described-by="field.describedBy"
            :invalid="field.invalid"
            :required="field.required"
          />
        </FormField>
        <BaseButton type="submit" block :loading="submitting">{{ messages.mfaChallenge.submit }}</BaseButton>
        <div class="cluster">
          <BaseButton variant="link" @click="switchMode">
            {{ useRecovery ? messages.mfaChallenge.useApp : messages.mfaChallenge.useRecovery }}
          </BaseButton>
        </div>
      </form>
    </BaseCard>
  </div>
</template>
