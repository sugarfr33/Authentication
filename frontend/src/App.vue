<script setup lang="ts">
import { nextTick, ref } from 'vue';
import { RouterLink, RouterView, useRouter } from 'vue-router';
import { IconSprite, ToastRegion } from '@/components/ui';
import { messages } from '@/i18n/messages';

const main = ref<HTMLElement | null>(null);
const router = useRouter();

// After an in-app navigation, move focus to the new content so screen readers start there.
let firstNavigation = true;
router.afterEach(async () => {
  if (firstNavigation) {
    firstNavigation = false;
    return;
  }
  await nextTick();
  main.value?.focus();
});
</script>

<template>
  <IconSprite />
  <a class="skip-link" href="#main">{{ messages.app.skipToContent }}</a>
  <header class="app-header">
    <nav class="app-header__inner" :aria-label="messages.app.primaryNav">
      <RouterLink to="/" class="app-header__brand">{{ messages.app.name }}</RouterLink>
    </nav>
  </header>
  <main id="main" ref="main" class="app-main" tabindex="-1">
    <RouterView />
  </main>
  <ToastRegion />
</template>

<style scoped>
.skip-link {
  position: absolute;
  inset-inline-start: var(--space-4);
  top: var(--space-2);
  z-index: var(--z-toast);
  padding: var(--space-2) var(--space-4);
  border-radius: var(--radius-md);
  background: var(--color-primary);
  color: var(--color-on-primary);
  transform: translateY(-200%);
}

.skip-link:focus {
  transform: none;
}

.app-header {
  position: sticky;
  top: 0;
  z-index: var(--z-sticky);
  border-bottom: var(--border-width) solid var(--color-border);
  background: var(--color-surface);
}

.app-header__inner {
  display: flex;
  align-items: center;
  max-width: var(--content-max);
  min-height: var(--space-16);
  margin-inline: auto;
  padding-inline: var(--space-4);
}

.app-header__brand {
  color: var(--color-text);
  font-size: var(--font-size-lg);
  font-weight: var(--font-weight-bold);
  text-decoration: none;
}

.app-main:focus {
  outline: none;
}
</style>
