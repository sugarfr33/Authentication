// Shared submit flow for the auth forms:
// client checks first (no request when they fail), then the API call; the API stays authoritative.
// - Field errors (client, or the API's ValidationProblem `errors`) show under their field as text.
// - Anything else becomes one form-level message (an assertive BaseAlert in the page).
// - Two or more invalid fields: the page shows a FormErrorSummary (errorCount >= 2) and focus moves to it (T31);
//   its links take the user to each field.
// - Otherwise, after a failed submit, focus moves to the first invalid field (WCAG 3.3.1), to a field the page names
//   (mapError `focus`, e.g. the cleared password after a generic sign-in failure; the role=alert message is
//   still announced once), or else to the form message.
import { computed, nextTick, ref, useTemplateRef, type ComputedRef, type Ref } from 'vue';
import { focusFirstInvalid } from '@/components/ui';
import { isApiError, type ApiError } from '@/api';
import { describeError } from '@/i18n/errors';
import type { FieldErrors } from '@/forms/validation';

/** Lets a page translate a failure into its own message; return null for the default. */
export type ErrorMapper<K extends string> = (
  error: ApiError,
) => { form?: string; fields?: FieldErrors<K>; focus?: K } | null;

export interface AuthForm<K extends string> {
  errors: Ref<FieldErrors<K>>;
  formError: Ref<string | null>;
  submitting: Ref<boolean>;
  /** Number of fields with an error; the page shows a FormErrorSummary when it is 2 or more. */
  errorCount: ComputedRef<number>;
  run(validate: () => FieldErrors<K>, action: () => Promise<void>, mapError?: ErrorMapper<K>): Promise<boolean>;
  clear(): void;
}

function countErrors(errors: Record<string, string | undefined>): number {
  return Object.values(errors).filter((message) => typeof message === 'string' && message.length > 0).length;
}

function hasAny(errors: Record<string, string | undefined>): boolean {
  return countErrors(errors) > 0;
}

/** At this many invalid fields focus goes to the summary instead of the first field. */
export const SUMMARY_THRESHOLD = 2;

/**
 * Template refs (by name, so one page can hold two forms): the <form> element, so focus can move to its first
 * invalid field, a focusable (tabindex=-1) wrapper of the form-level alert, focused when no field is invalid, and the
 * FormErrorSummary (default ref "summaryEl").
 */
export interface AuthFormRefs {
  form?: string;
  alert?: string;
  summary?: string;
}

export function useAuthForm<K extends string>(fields: readonly K[], refs: AuthFormRefs = {}): AuthForm<K> {
  const errors = ref({}) as Ref<FieldErrors<K>>;
  const formError = ref<string | null>(null);
  const submitting = ref(false);
  const formEl = useTemplateRef<HTMLFormElement>(refs.form ?? 'formEl');
  const alertEl = useTemplateRef<HTMLElement>(refs.alert ?? 'alertEl');
  const summaryEl = useTemplateRef<{ focus(): void }>(refs.summary ?? 'summaryEl');
  const errorCount = computed(() => countErrors(errors.value));

  /** The API's field names are camelCase; match them to ours without caring about case. */
  function serverFieldErrors(error: ApiError): FieldErrors<K> {
    const mapped: FieldErrors<K> = {};
    for (const [name, list] of Object.entries(error.fieldErrors)) {
      const field = fields.find((f) => f.toLowerCase() === name.toLowerCase());
      if (field && list.length > 0) mapped[field] = list.join(' ');
    }
    return mapped;
  }

  /** `focusField` is a field key; the input is found by its name attribute inside the form. */
  async function moveFocus(focusField?: K): Promise<void> {
    await nextTick();
    if (errorCount.value >= SUMMARY_THRESHOLD && summaryEl.value) {
      summaryEl.value.focus();
      return;
    }
    if (formEl.value && focusFirstInvalid(formEl.value)) return;
    const named = focusField ? formEl.value?.querySelector<HTMLElement>(`[name="${focusField}"]`) : null;
    if (named) {
      named.focus();
      return;
    }
    alertEl.value?.focus();
  }

  function clear(): void {
    errors.value = {};
    formError.value = null;
  }

  async function run(validate: () => FieldErrors<K>, action: () => Promise<void>, mapError?: ErrorMapper<K>): Promise<boolean> {
    if (submitting.value) return false;
    formError.value = null;
    const clientErrors = validate();
    errors.value = clientErrors;
    if (hasAny(clientErrors)) {
      await moveFocus();
      return false;
    }

    submitting.value = true;
    try {
      await action();
      return true;
    } catch (error) {
      const custom = isApiError(error) && mapError ? mapError(error) : null;
      const fromServer = isApiError(error) ? serverFieldErrors(error) : {};
      errors.value = { ...fromServer, ...(custom?.fields ?? {}) };
      formError.value = custom?.form ?? (hasAny(errors.value) ? null : describeError(error));
      await moveFocus(custom?.focus);
      return false;
    } finally {
      submitting.value = false;
    }
  }

  return { errors, formError, submitting, errorCount, run, clear };
}

/**
 * When a form is swapped for its success message, the focused button disappears and focus would fall back to
 * <body> (WCAG 2.4.3). Bind ref="<name>" on a tabindex=-1 wrapper of the message and call focus() after showing it.
 */
export function useFocusTarget(name: string): { focus(): Promise<void> } {
  const target = useTemplateRef<HTMLElement>(name);
  return {
    async focus() {
      await nextTick();
      target.value?.focus();
    },
  };
}
