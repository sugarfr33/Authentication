// Shared submit flow for the auth forms:
// client checks first (no request when they fail), then the API call; the API stays authoritative.
// - Field errors (client, or the API's ValidationProblem `errors`) show under their field as text.
// - Anything else becomes one form-level message (an assertive BaseAlert in the page).
// - After a failed submit, focus moves to the first invalid field (WCAG 3.3.1), or to the form message.
import { nextTick, ref, useTemplateRef, type Ref } from 'vue';
import { focusFirstInvalid } from '@/components/ui';
import { isApiError, type ApiError } from '@/api';
import { describeError } from '@/i18n/errors';
import type { FieldErrors } from '@/forms/validation';

/** Lets a page translate a failure into its own message; return null for the default. */
export type ErrorMapper<K extends string> = (error: ApiError) => { form?: string; fields?: FieldErrors<K> } | null;

export interface AuthForm<K extends string> {
  errors: Ref<FieldErrors<K>>;
  formError: Ref<string | null>;
  submitting: Ref<boolean>;
  run(validate: () => FieldErrors<K>, action: () => Promise<void>, mapError?: ErrorMapper<K>): Promise<boolean>;
  clear(): void;
}

function hasAny(errors: Record<string, string | undefined>): boolean {
  return Object.values(errors).some((message) => typeof message === 'string' && message.length > 0);
}

/**
 * Template refs (by name, so one page can hold two forms): the <form> element, so focus can move to its first
 * invalid field, and a focusable (tabindex=-1) wrapper of the form-level alert, focused when no field is invalid.
 */
export interface AuthFormRefs {
  form?: string;
  alert?: string;
}

export function useAuthForm<K extends string>(fields: readonly K[], refs: AuthFormRefs = {}): AuthForm<K> {
  const errors = ref({}) as Ref<FieldErrors<K>>;
  const formError = ref<string | null>(null);
  const submitting = ref(false);
  const formEl = useTemplateRef<HTMLFormElement>(refs.form ?? 'formEl');
  const alertEl = useTemplateRef<HTMLElement>(refs.alert ?? 'alertEl');

  /** The API's field names are camelCase; match them to ours without caring about case. */
  function serverFieldErrors(error: ApiError): FieldErrors<K> {
    const mapped: FieldErrors<K> = {};
    for (const [name, list] of Object.entries(error.fieldErrors)) {
      const field = fields.find((f) => f.toLowerCase() === name.toLowerCase());
      if (field && list.length > 0) mapped[field] = list.join(' ');
    }
    return mapped;
  }

  async function moveFocus(): Promise<void> {
    await nextTick();
    if (formEl.value && focusFirstInvalid(formEl.value)) return;
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
      await moveFocus();
      return false;
    } finally {
      submitting.value = false;
    }
  }

  return { errors, formError, submitting, run, clear };
}
