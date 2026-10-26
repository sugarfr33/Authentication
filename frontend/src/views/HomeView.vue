<script setup lang="ts">
import { ref } from 'vue';
import { RouterLink, useRouter } from 'vue-router';
import { BaseAlert, BaseButton, BaseCard, BaseSpinner } from '@/components/ui';
import { useToast } from '@/composables/useToast';
import { describeError } from '@/i18n/errors';
import { format, messages } from '@/i18n/messages';
import { useSessionStore } from '@/stores/session';

const session = useSessionStore();
const router = useRouter();
const toast = useToast();
const loadError = ref<string | null>(null);
const signingOut = ref(false);

async function load(): Promise<void> {
  loadError.value = null;
  try {
    await session.load();
  } catch (error) {
    loadError.value = describeError(error);
  }
}

async function signOut(): Promise<void> {
  signingOut.value = true;
  try {
    await session.signOut();
    toast.show(messages.home.signedOutToast, { tone: 'success' });
    await router.replace({ name: 'login' });
  } catch (error) {
    toast.show(describeError(error), { tone: 'danger' });
  } finally {
    signingOut.value = false;
  }
}

// The route guard already loaded the session (requiresAuth); load() here is only the retry button.
</script>

<template>
  <div class="page page--narrow stack stack--lg">
    <h1>{{ messages.home.title }}</h1>

    <BaseSpinner v-if="session.status === 'loading'" :label="messages.home.checking" size="lg" />

    <BaseAlert v-else-if="loadError" tone="danger" live="assertive" :title="messages.home.loadFailed">
      <div class="stack">
        <p>{{ loadError }}</p>
        <div class="cluster">
          <BaseButton variant="secondary" size="sm" @click="load">{{ messages.home.retry }}</BaseButton>
        </div>
      </div>
    </BaseAlert>

    <BaseCard v-else-if="session.isAuthenticated && session.profile" :title="format(messages.home.signedInAs, { name: session.profile.displayName })">
      <dl class="details">
        <dt>{{ messages.home.email }}</dt>
        <dd>{{ session.profile.email }}</dd>
        <dt>{{ messages.home.roles }}</dt>
        <dd>{{ session.profile.roles.length > 0 ? session.profile.roles.join(', ') : messages.home.noRoles }}</dd>
        <dt>{{ messages.home.mfa }}</dt>
        <dd>{{ session.profile.mfaEnabled ? messages.account.mfaOn : messages.account.mfaOff }}</dd>
      </dl>
      <p v-if="!session.profile.mfaEnabled"><RouterLink :to="{ name: 'mfa-enroll' }">{{ messages.account.setUpMfa }}</RouterLink></p>
      <template #footer>
        <BaseButton variant="secondary" :loading="signingOut" @click="signOut">{{ messages.home.signOut }}</BaseButton>
      </template>
    </BaseCard>

    <BaseAlert v-else-if="session.status === 'anonymous'" tone="info">
      <div class="stack">
        <p>{{ messages.home.signedOut }}</p>
        <p><RouterLink :to="{ name: 'login' }">{{ messages.login.submit }}</RouterLink></p>
      </div>
    </BaseAlert>
  </div>
</template>
