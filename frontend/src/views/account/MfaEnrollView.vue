<script setup lang="ts">
// Turning on two-step verification (docs/mfa-totp.md section 4):
// 1. re-authenticate with the password -> the API answers once with the setup key and otpauth URI (shown as text);
// 2. confirm with a code from the app -> the API answers once with 10 recovery codes and ENDS EVERY SESSION
//    (this browser's cookies included), so the local profile is cleared and the user signs in again afterwards.
// The key and the codes live only in this component's memory and are dropped when it unmounts.
import { nextTick, onBeforeUnmount, ref } from 'vue';
import { useRouter } from 'vue-router';
import { authApi, type MfaEnrollment } from '@/api';
import { BaseAlert, BaseButton, BaseCard, BaseInput, FormField, PasswordInput } from '@/components/ui';
import { useAuthForm } from '@/composables/useAuthForm';
import { useToast } from '@/composables/useToast';
import { collectErrors, validateCurrentPassword, validateTotpCode } from '@/forms/validation';
import { messages } from '@/i18n/messages';
import { useSessionStore } from '@/stores/session';

type Step = 'password' | 'confirm' | 'codes';

const router = useRouter();
const session = useSessionStore();
const toast = useToast();

const step = ref<Step>('password');
const password = ref('');
const code = ref('');
const enrollment = ref<MfaEnrollment | null>(null);
const recoveryCodes = ref<string[]>([]);
const stepHeading = ref<HTMLElement | null>(null);
const canRestart = ref(false);

const passwordForm = useAuthForm(['password'] as const, { form: 'passwordFormEl', alert: 'passwordAlertEl' });
const confirmForm = useAuthForm(['code'] as const, { form: 'confirmFormEl', alert: 'confirmAlertEl' });

/** Only an otpauth TOTP URI becomes a link; anything else is shown as the key alone. */
function safeOtpLink(uri: string): string | null {
  return uri.startsWith('otpauth://totp/') ? uri : null;
}

async function goTo(next: Step): Promise<void> {
  step.value = next;
  await nextTick();
  stepHeading.value?.focus();
}

async function start(): Promise<void> {
  canRestart.value = false;
  await passwordForm.run(
    () => collectErrors({ password: validateCurrentPassword(password.value) }),
    async () => {
      enrollment.value = await authApi.enrollMfa(password.value);
      password.value = '';
      await goTo('confirm');
    },
    (error) => {
      if (error.status === 400 && Object.keys(error.fieldErrors).length === 0) {
        password.value = '';
        return { fields: { password: messages.mfaEnroll.passwordWrong } };
      }
      if (error.status === 404) return { form: messages.mfaEnroll.unavailable };
      if (error.status === 409) return { form: messages.mfaEnroll.alreadyOn };
      return null;
    },
  );
}

async function confirm(): Promise<void> {
  await confirmForm.run(
    () => collectErrors({ code: validateTotpCode(code.value) }),
    async () => {
      recoveryCodes.value = await authApi.confirmMfa(code.value.replace(/\s+/g, ''));
      code.value = '';
      enrollment.value = null;
      // The API ended every session, this one included.
      session.clear();
      await goTo('codes');
    },
    (error) => {
      if (error.status === 400 && Object.keys(error.fieldErrors).length === 0) {
        code.value = '';
        return { fields: { code: messages.mfaEnroll.codeWrong } };
      }
      if (error.status === 409) {
        canRestart.value = true;
        return { form: messages.mfaEnroll.expired };
      }
      return null;
    },
  );
}

async function restart(): Promise<void> {
  enrollment.value = null;
  code.value = '';
  confirmForm.clear();
  canRestart.value = false;
  await goTo('password');
}

async function copyCodes(): Promise<void> {
  try {
    await navigator.clipboard.writeText(recoveryCodes.value.join('\n'));
    toast.show(messages.mfaEnroll.copied, { tone: 'success' });
  } catch {
    toast.show(messages.mfaEnroll.copyFailed, { tone: 'warning' });
  }
}

async function finish(): Promise<void> {
  recoveryCodes.value = [];
  toast.show(messages.mfaEnroll.signedOutNotice, { tone: 'info' });
  await router.replace({ name: 'login' });
}

onBeforeUnmount(() => {
  enrollment.value = null;
  recoveryCodes.value = [];
  password.value = '';
});
</script>

<template>
  <div class="page page--narrow stack stack--lg">
    <BaseCard :title="messages.mfaEnroll.title" :heading-level="1">
      <div v-if="step === 'password'" class="stack">
        <p>{{ messages.mfaEnroll.intro }}</p>
        <form ref="passwordFormEl" class="stack" novalidate @submit.prevent="start">
          <div v-if="passwordForm.formError.value" ref="passwordAlertEl" tabindex="-1">
            <BaseAlert tone="danger" live="assertive">{{ passwordForm.formError.value }}</BaseAlert>
          </div>
          <p ref="stepHeading" tabindex="-1">{{ messages.mfaEnroll.passwordStep }}</p>
          <!-- Lets password managers match the saved password to this account. -->
          <BaseInput
            class="visually-hidden"
            :model-value="session.profile?.email ?? ''"
            autocomplete="username"
            aria-hidden="true"
            tabindex="-1"
            readonly
          />
          <FormField v-slot="field" :label="messages.fields.password" :error="passwordForm.errors.value.password" required>
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
          <BaseButton type="submit" :loading="passwordForm.submitting.value">{{ messages.mfaEnroll.start }}</BaseButton>
        </form>
      </div>

      <div v-else-if="step === 'confirm' && enrollment" class="stack">
        <h2 ref="stepHeading" tabindex="-1">{{ messages.mfaEnroll.scanTitle }}</h2>
        <p>{{ messages.mfaEnroll.scanBody }}</p>
        <dl class="details">
          <dt>{{ messages.mfaEnroll.keyLabel }}</dt>
          <dd><code>{{ enrollment.manualEntryKey }}</code></dd>
        </dl>
        <p v-if="safeOtpLink(enrollment.otpAuthUri)">
          <a :href="safeOtpLink(enrollment.otpAuthUri) ?? undefined">{{ messages.mfaEnroll.openLink }}</a>
        </p>
        <form ref="confirmFormEl" class="stack" novalidate @submit.prevent="confirm">
          <div v-if="confirmForm.formError.value" ref="confirmAlertEl" tabindex="-1">
            <BaseAlert tone="danger" live="assertive">
              <div class="stack">
                <p>{{ confirmForm.formError.value }}</p>
                <div v-if="canRestart" class="cluster">
                  <BaseButton variant="secondary" size="sm" @click="restart">{{ messages.mfaEnroll.restart }}</BaseButton>
                </div>
              </div>
            </BaseAlert>
          </div>
          <p>{{ messages.mfaEnroll.confirmStep }}</p>
          <FormField
            v-slot="field"
            :label="messages.fields.code"
            :hint="messages.fields.codeHint"
            :error="confirmForm.errors.value.code"
            required
          >
            <BaseInput
              :id="field.id"
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
          <BaseButton type="submit" :loading="confirmForm.submitting.value">{{ messages.mfaEnroll.confirm }}</BaseButton>
        </form>
      </div>

      <div v-else-if="step === 'codes'" class="stack">
        <h2 ref="stepHeading" tabindex="-1">{{ messages.mfaEnroll.codesTitle }}</h2>
        <BaseAlert tone="warning">{{ messages.mfaEnroll.codesBody }}</BaseAlert>
        <ul :aria-label="messages.mfaEnroll.codesListLabel">
          <li v-for="item in recoveryCodes" :key="item"><code>{{ item }}</code></li>
        </ul>
        <div class="cluster">
          <BaseButton variant="secondary" @click="copyCodes">{{ messages.mfaEnroll.copy }}</BaseButton>
          <BaseButton @click="finish">{{ messages.mfaEnroll.done }}</BaseButton>
        </div>
      </div>
    </BaseCard>
  </div>
</template>
