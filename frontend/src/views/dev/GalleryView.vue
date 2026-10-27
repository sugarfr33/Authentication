<script setup lang="ts">
// DEV ONLY (route registered behind import.meta.env.DEV). Every kit component in every variant and state,
// with a theme switch (system/light/dark) and preview widths of 320 and 414 px.
import { computed, onBeforeUnmount, ref } from 'vue';
import {
  BaseAlert,
  BaseButton,
  BaseCard,
  BaseDialog,
  BaseInput,
  BaseSpinner,
  BaseTable,
  FormField,
  PasswordInput,
  type ButtonSize,
  type ButtonVariant,
  type TableColumn,
  type Tone,
} from '@/components/ui';
import { useToast } from '@/composables/useToast';

type Theme = 'system' | 'light' | 'dark';
type Width = 'full' | '414' | '320';

const theme = ref<Theme>('system');
const width = ref<Width>('full');

function setTheme(next: Theme): void {
  theme.value = next;
  if (next === 'system') delete document.documentElement.dataset.theme;
  else document.documentElement.dataset.theme = next;
}
onBeforeUnmount(() => delete document.documentElement.dataset.theme);

const variants: ButtonVariant[] = ['primary', 'secondary', 'ghost', 'danger', 'link'];
const sizes: ButtonSize[] = ['sm', 'md', 'lg'];
const tones: Tone[] = ['info', 'success', 'warning', 'danger'];

const email = ref('');
const emailInvalid = ref('not-an-email');
const readonlyValue = ref('ada@example.com');
const currentPassword = ref('');
const newPassword = ref('correct horse battery');
const badPassword = ref('short');

const columns: TableColumn[] = [
  { key: 'device', label: 'Device' },
  { key: 'ip', label: 'IP address' },
  { key: 'lastUsed', label: 'Last used', align: 'end' },
];
interface DemoRow {
  id: string;
  device: string;
  ip: string;
  lastUsed: Date;
}
const rows: DemoRow[] = [
  { id: '1', device: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Firefox/140.0', ip: '203.0.113.7', lastUsed: new Date() },
  // Hostile-looking value: must show up as literal text.
  { id: '2', device: '<img src=x onerror=alert(1)>', ip: '198.51.100.23', lastUsed: new Date(Date.now() - 86_400_000) },
];
const showEmpty = ref(false);
const tableRows = computed(() => (showEmpty.value ? [] : rows));

const dialogOpen = ref(false);
const dangerOpen = ref(false);
const dangerBusy = ref(false);
function confirmDanger(): void {
  dangerBusy.value = true;
  setTimeout(() => {
    dangerBusy.value = false;
    dangerOpen.value = false;
    toast.show('All other sessions were signed out.', { tone: 'success' });
  }, 1200);
}

const toast = useToast();
const dismissed = ref(false);
</script>

<template>
  <div class="page stack stack--lg">
    <div class="stack">
      <h1>UI kit gallery</h1>
      <p class="muted">Development only. Not part of production builds.</p>
      <div class="cluster" role="group" aria-label="Theme">
        <BaseButton
          v-for="option in ['system', 'light', 'dark'] as const"
          :key="option"
          size="sm"
          :variant="theme === option ? 'primary' : 'secondary'"
          :aria-pressed="theme === option ? 'true' : 'false'"
          @click="setTheme(option)"
        >
          Theme: {{ option }}
        </BaseButton>
      </div>
      <div class="cluster" role="group" aria-label="Preview width">
        <BaseButton
          v-for="option in ['full', '414', '320'] as const"
          :key="option"
          size="sm"
          :variant="width === option ? 'primary' : 'secondary'"
          :aria-pressed="width === option ? 'true' : 'false'"
          @click="width = option"
        >
          Width: {{ option === 'full' ? 'full' : `${option} px` }}
        </BaseButton>
      </div>
    </div>

    <div class="frame" :class="`frame--${width}`">
      <div class="stack stack--lg">
        <BaseCard title="Buttons">
          <div v-for="variant in variants" :key="variant" class="cluster">
            <BaseButton v-for="size in sizes" :key="size" :variant="variant" :size="size">Save {{ size }}</BaseButton>
            <BaseButton :variant="variant" disabled>Disabled</BaseButton>
            <BaseButton :variant="variant" loading>Saving</BaseButton>
            <BaseButton :variant="variant" icon="success">With icon</BaseButton>
          </div>
          <BaseButton block>Block button</BaseButton>
        </BaseCard>

        <BaseCard title="Inputs and form fields">
          <FormField v-slot="field" label="Email" hint="We only use it to sign you in." required>
            <BaseInput
              :id="field.id"
              v-model="email"
              type="email"
              autocomplete="email"
              inputmode="email"
              :described-by="field.describedBy"
              :invalid="field.invalid"
              :required="field.required"
            />
          </FormField>
          <FormField v-slot="field" label="Email (error)" error="Enter an email address like name@example.com.">
            <BaseInput
              :id="field.id"
              v-model="emailInvalid"
              type="email"
              autocomplete="email"
              :described-by="field.describedBy"
              :invalid="field.invalid"
            />
          </FormField>
          <FormField v-slot="field" label="Display name (disabled)">
            <BaseInput :id="field.id" model-value="Ada" autocomplete="name" disabled />
          </FormField>
          <FormField v-slot="field" label="Email (read only)">
            <BaseInput :id="field.id" v-model="readonlyValue" autocomplete="email" readonly />
          </FormField>
        </BaseCard>

        <BaseCard title="Password inputs">
          <FormField v-slot="field" label="Current password" required>
            <PasswordInput
              :id="field.id"
              v-model="currentPassword"
              autocomplete="current-password"
              :described-by="field.describedBy"
              :invalid="field.invalid"
              :required="field.required"
            />
          </FormField>
          <FormField v-slot="field" label="New password" hint="Use at least 12 characters.">
            <PasswordInput
              :id="field.id"
              v-model="newPassword"
              autocomplete="new-password"
              show-strength
              :described-by="field.describedBy"
            />
          </FormField>
          <FormField v-slot="field" label="New password (error)" error="Use at least 12 characters.">
            <PasswordInput
              :id="field.id"
              v-model="badPassword"
              autocomplete="new-password"
              show-strength
              :described-by="field.describedBy"
              :invalid="field.invalid"
            />
          </FormField>
          <FormField v-slot="field" label="Password (disabled)">
            <PasswordInput :id="field.id" autocomplete="current-password" disabled />
          </FormField>
        </BaseCard>

        <BaseCard title="Alerts">
          <BaseAlert v-for="tone in tones" :key="tone" :tone="tone" :title="`A ${tone} title`">
            Body text that explains what happened and what to do next.
          </BaseAlert>
          <BaseAlert tone="info">An alert without a title.</BaseAlert>
          <BaseAlert v-if="!dismissed" tone="success" dismissible @dismiss="dismissed = true">
            A dismissible alert.
          </BaseAlert>
        </BaseCard>

        <BaseCard title="Card with actions and footer">
          <template #actions>
            <BaseButton size="sm" variant="ghost">Edit</BaseButton>
          </template>
          <p>Cards group related content under one heading.</p>
          <template #footer>
            <BaseButton variant="secondary">Cancel</BaseButton>
            <BaseButton>Save changes</BaseButton>
          </template>
        </BaseCard>

        <BaseCard title="Table">
          <template #actions>
            <BaseButton size="sm" variant="secondary" :aria-pressed="showEmpty ? 'true' : 'false'" @click="showEmpty = !showEmpty">
              Show empty state
            </BaseButton>
          </template>
          <BaseTable
            :columns="columns"
            :rows="tableRows"
            :row-key="(row) => row.id"
            caption="Active sessions"
            empty-text="No active sessions."
          />
        </BaseCard>

        <BaseCard title="Spinners">
          <div class="cluster">
            <BaseSpinner size="sm" />
            <BaseSpinner size="md" />
            <BaseSpinner size="lg" label="Loading sessions" />
          </div>
        </BaseCard>

        <BaseCard title="Dialogs">
          <div class="cluster">
            <BaseButton variant="secondary" @click="dialogOpen = true">Open dialog</BaseButton>
            <BaseButton variant="danger" @click="dangerOpen = true">Sign out everywhere</BaseButton>
          </div>
          <BaseDialog
            v-model:open="dialogOpen"
            title="Save changes?"
            description="Your display name will be updated."
            confirm-label="Save changes"
            @confirm="dialogOpen = false"
          />
          <BaseDialog
            v-model:open="dangerOpen"
            tone="danger"
            title="Sign out all other sessions?"
            description="Every other browser and app signed in to your account will be signed out."
            confirm-label="Sign out all sessions"
            :confirm-loading="dangerBusy"
            @confirm="confirmDanger"
          />
        </BaseCard>

        <BaseCard title="Toasts">
          <div class="cluster">
            <BaseButton
              v-for="tone in tones"
              :key="tone"
              size="sm"
              variant="secondary"
              @click="toast.show(`A ${tone} notification.`, { tone })"
            >
              Show {{ tone }} toast
            </BaseButton>
          </div>
        </BaseCard>
      </div>
    </div>
  </div>
</template>

<style scoped>
/* Dev-only preview frames (the only page-level styles, allowed because this page never ships). */
.frame {
  margin-inline: auto;
  width: 100%;
}

.frame--414,
.frame--320 {
  padding: var(--space-2);
  border: var(--border-width) dashed var(--color-border-strong);
  border-radius: var(--radius-lg);
  overflow-x: auto;
}

.frame--414 {
  max-width: calc(25.875rem + var(--space-4));
}

.frame--320 {
  max-width: calc(20rem + var(--space-4));
}
</style>
