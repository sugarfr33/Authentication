<script setup lang="ts">
import { onMounted } from 'vue';
import { RouterLink } from 'vue-router';
import { BaseCard } from '@/components/ui';
import { messages } from '@/i18n/messages';
import { useSessionStore } from '@/stores/session';

// Signed out, 'Go to your account' would only bounce to sign-in, so say where the link goes (T31, UX review m10).
const session = useSessionStore();
onMounted(() => {
  if (session.status === 'unknown') void session.load().catch(() => undefined);
});
</script>

<template>
  <div class="page page--narrow stack">
    <BaseCard :title="messages.notFound.title" :heading-level="1">
      <p>{{ messages.notFound.body }}</p>
      <p v-if="session.isAuthenticated"><RouterLink to="/">{{ messages.notFound.home }}</RouterLink></p>
      <p v-else><RouterLink :to="{ name: 'login' }">{{ messages.notFound.signIn }}</RouterLink></p>
    </BaseCard>
  </div>
</template>
