<script setup lang="ts">
import { RouterLink } from 'vue-router';
import { BaseCard } from '@/components/ui';
import { messages } from '@/i18n/messages';
</script>

<template>
  <div class="page page--narrow stack">
    <BaseCard :title="messages.notFound.title" :heading-level="1">
      <p>{{ messages.notFound.body }}</p>
      <p><RouterLink to="/">{{ messages.notFound.home }}</RouterLink></p>
    </BaseCard>
  </div>
</template>
