<script setup lang="ts">
// The verification link is /verify-email#token=... It is redeemed only after an explicit click, never on page
// load: a sign-up link activates the password chosen in that sign-up, so the user confirms that it was theirs
// (residual pre-hijack risk, docs/registration-and-email-verification.md), and link scanners that run scripts
// cannot redeem it.
import { onMounted, ref } from 'vue';
import { RouterLink, useRoute, useRouter } from 'vue-router';
import { authApi } from '@/api';
import { BaseAlert, BaseButton, BaseCard } from '@/components/ui';
import { useAuthForm } from '@/composables/useAuthForm';
import { messages } from '@/i18n/messages';
import { takeFragmentToken } from '@/router/fragmentToken';

const route = useRoute();
const router = useRouter();

const token = ref<string | null>(null);
const ready = ref(false);
const done = ref(false);
const linkInvalid = ref(false);
const { formError, submitting, run } = useAuthForm([] as const);

onMounted(async () => {
  token.value = await takeFragmentToken(route, router);
  ready.value = true;
});

async function confirm(): Promise<void> {
  const value = token.value;
  if (value === null) return;
  await run(
    () => ({}),
    async () => {
      await authApi.verifyEmail(value);
      token.value = null;
      done.value = true;
    },
    (error) => {
      if (error.status === 400) {
        linkInvalid.value = true;
        return { form: messages.auth.verifyLinkInvalid };
      }
      return null;
    },
  );
}
</script>

<template>
  <div class="page page--narrow stack stack--lg">
    <BaseCard :title="messages.verify.title" :heading-level="1">
      <template v-if="!ready" />
      <BaseAlert v-else-if="done" tone="success" live="polite" :title="messages.verify.doneTitle">
        <div class="stack">
          <p>{{ messages.verify.doneBody }}</p>
          <p><RouterLink to="/login">{{ messages.verify.signIn }}</RouterLink></p>
        </div>
      </BaseAlert>
      <BaseAlert v-else-if="token === null && !linkInvalid" tone="warning">
        <div class="stack">
          <p>{{ messages.verify.missingToken }}</p>
          <p><RouterLink to="/register">{{ messages.verify.registerAgain }}</RouterLink></p>
        </div>
      </BaseAlert>
      <div v-else class="stack">
        <div v-if="formError" ref="alertEl" tabindex="-1">
          <BaseAlert tone="danger" live="assertive">
            <div class="stack">
              <p>{{ formError }}</p>
              <p v-if="linkInvalid"><RouterLink to="/register">{{ messages.verify.registerAgain }}</RouterLink></p>
            </div>
          </BaseAlert>
        </div>
        <p>{{ messages.verify.intro }}</p>
        <BaseButton block :loading="submitting" :disabled="linkInvalid" @click="confirm">{{ messages.verify.submit }}</BaseButton>
      </div>
    </BaseCard>
  </div>
</template>
