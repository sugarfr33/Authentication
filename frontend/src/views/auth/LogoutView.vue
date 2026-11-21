<script setup lang="ts">
// RP-initiated logout (docs/single-logout-and-shared-domain.md): an application sends the browser to
// /logout?client_id=...&post_logout_redirect_uri=...&state=... after forgetting its own tokens.
// - GET /oauth/logout validates the request first (unknown client: "not valid"); it never changes anything.
// - Nothing is ended on page load: the user confirms, so a link alone (or a link scanner) cannot sign anyone out.
// - On confirm: POST /oauth/logout ends the user's sessions at that application, then POST /auth/logout ends the
//   Central Auth browser session, so the next sign-in anywhere asks for the password.
// - The browser then goes to the server-built redirect_to (a registered post-logout URI, character for character),
//   and only if it is an https URL (http only for loopback); otherwise it stays here.
import { computed, onMounted, ref } from 'vue';
import { RouterLink, useRoute } from 'vue-router';
import { authApi, isApiError, type LogoutParams, type LogoutTarget } from '@/api';
import { BaseAlert, BaseButton, BaseCard, BaseSpinner } from '@/components/ui';
import { useAuthForm, useFocusTarget } from '@/composables/useAuthForm';
import { describeError } from '@/i18n/errors';
import { format, messages } from '@/i18n/messages';
import { browserNavigation, safePostLogoutTarget as safeRedirect } from '@/router/returnTo';
import { useSessionStore } from '@/stores/session';

type Phase = 'checking' | 'invalid' | 'failed' | 'confirm' | 'signed-out' | 'returning';

const route = useRoute();
const session = useSessionStore();
const phase = ref<Phase>('checking');
const loadError = ref<string | null>(null);
const target = ref<LogoutTarget | null>(null);
const { formError, submitting, run } = useAuthForm([] as const);
const doneMessage = useFocusTarget('doneEl');

/** One value per parameter: a repeated parameter makes the request invalid, as the API says too. */
function single(raw: unknown): string | undefined | null {
  if (raw === undefined) return undefined;
  return typeof raw === 'string' ? raw : null;
}

function readParams(): LogoutParams | null {
  const clientId = single(route.query.client_id);
  const postLogoutRedirectUri = single(route.query.post_logout_redirect_uri);
  const state = single(route.query.state);
  if (!clientId || postLogoutRedirectUri === null || state === null) return null;
  return {
    clientId,
    ...(postLogoutRedirectUri !== undefined ? { postLogoutRedirectUri } : {}),
    ...(state !== undefined ? { state } : {}),
  };
}

const params = readParams();

const backLink = computed(() => safeRedirect(target.value?.redirectTo ?? null));
const appName = () => target.value?.clientId ?? params?.clientId ?? '';

async function check(): Promise<void> {
  if (params === null) {
    phase.value = 'invalid';
    return;
  }
  phase.value = 'checking';
  loadError.value = null;
  try {
    target.value = await authApi.describeLogout(params);
    await session.load();
    phase.value = session.isAuthenticated ? 'confirm' : 'signed-out';
  } catch (error) {
    if (isApiError(error) && error.status === 400) {
      phase.value = 'invalid';
      return;
    }
    loadError.value = describeError(error);
    phase.value = 'failed';
  }
}

async function signOut(): Promise<void> {
  if (params === null) return;
  await run(
    () => ({}),
    async () => {
      try {
        target.value = await authApi.confirmLogout(params);
      } catch (error) {
        // 401: the browser session ended meanwhile (another tab), which already ended every application session.
        if (!(isApiError(error) && error.status === 401)) throw error;
      }
      await session.signOut();
      const next = backLink.value;
      phase.value = next ? 'returning' : 'signed-out';
      await doneMessage.focus();
      if (next) browserNavigation.assign(next);
    },
    (error) => {
      if (error.status === 400 && !error.title) {
        phase.value = 'invalid';
        return { form: messages.logout.invalid };
      }
      return null;
    },
  );
}

onMounted(check);
</script>

<template>
  <div class="page page--narrow stack stack--lg">
    <BaseCard :title="messages.logout.title" :heading-level="1">
      <BaseSpinner v-if="phase === 'checking'" :label="messages.logout.checking" />
      <BaseAlert v-else-if="phase === 'invalid'" tone="warning">
        <div class="stack">
          <p>{{ messages.logout.invalid }}</p>
          <p><RouterLink to="/">{{ messages.notFound.home }}</RouterLink></p>
        </div>
      </BaseAlert>
      <BaseAlert v-else-if="phase === 'failed'" tone="danger" live="assertive">
        <div class="stack">
          <p>{{ messages.logout.loadFailed }} {{ loadError }}</p>
          <p><BaseButton variant="secondary" @click="check">{{ messages.logout.retry }}</BaseButton></p>
        </div>
      </BaseAlert>
      <div v-else-if="phase === 'signed-out' || phase === 'returning'" ref="doneEl" tabindex="-1">
        <BaseAlert tone="success" live="polite" :title="messages.logout.signedOutTitle">
          <div class="stack">
            <p v-if="phase === 'returning'">{{ format(messages.logout.returning, { app: appName() }) }}</p>
            <p v-else>{{ messages.logout.signedOutBody }}</p>
            <p v-if="backLink">
              <a :href="backLink">{{ format(messages.logout.backToApp, { app: appName() }) }}</a>
            </p>
            <p v-else><RouterLink to="/login">{{ messages.logout.signIn }}</RouterLink></p>
          </div>
        </BaseAlert>
      </div>
      <div v-else class="stack">
        <div v-if="formError" ref="alertEl" tabindex="-1">
          <BaseAlert tone="danger" live="assertive">{{ formError }}</BaseAlert>
        </div>
        <p>{{ format(messages.logout.intro, { app: appName() }) }}</p>
        <BaseButton block :loading="submitting" @click="signOut">{{ messages.logout.submit }}</BaseButton>
        <RouterLink to="/">{{ messages.logout.stay }}</RouterLink>
      </div>
    </BaseCard>
  </div>
</template>
