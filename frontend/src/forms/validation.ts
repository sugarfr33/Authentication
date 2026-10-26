// Client-side checks: quick feedback only. The API is authoritative and re-checks everything; its
// ValidationProblem field messages are shown as they come (as text). These mirror the server rules
// (docs/registration-and-email-verification.md, T06 password policy) closely enough not to refuse a valid value.
import { format, messages } from '@/i18n/messages';

export const PASSWORD_MIN = 12;
export const PASSWORD_MAX = 128;
export const DISPLAY_NAME_MAX = 128;
export const EMAIL_MAX = 256;

/** Field name to message; a field without an entry is valid. */
export type FieldErrors<K extends string> = Partial<Record<K, string>>;

/** Builds a FieldErrors from validator results, dropping the nulls. */
export function collectErrors<K extends string>(results: Record<K, string | null>): FieldErrors<K> {
  const errors: FieldErrors<K> = {};
  for (const key of Object.keys(results) as K[]) {
    const message = results[key];
    if (message) errors[key] = message;
  }
  return errors;
}

// eslint-disable-next-line no-control-regex
const CONTROL = /[\u0000-\u001f\u007f-\u009f]/;

function codePoints(value: string): number {
  return [...value].length;
}

export function validateEmail(value: string): string | null {
  const email = value.trim();
  if (email === '') return messages.validation.emailRequired;
  if (email.length > EMAIL_MAX || /\s/.test(email) || CONTROL.test(email)) return messages.validation.emailInvalid;
  const parts = email.split('@');
  if (parts.length !== 2) return messages.validation.emailInvalid;
  const [local, domain] = parts as [string, string];
  if (local.length < 1 || local.length > 64) return messages.validation.emailInvalid;
  const labels = domain.split('.');
  if (labels.length < 2 || labels.some((label) => label.length === 0)) return messages.validation.emailInvalid;
  return null;
}

/** Sign-in and re-authentication: presence only. Never apply the policy here (it would hint at nothing useful). */
export function validateCurrentPassword(value: string): string | null {
  return value.length === 0 ? messages.validation.passwordRequired : null;
}

export function validateNewPassword(value: string, email?: string): string | null {
  if (value.length === 0) return messages.validation.newPasswordRequired;
  const length = codePoints(value.normalize('NFKC'));
  if (length < PASSWORD_MIN) return format(messages.validation.passwordTooShort, { min: PASSWORD_MIN });
  if (length > PASSWORD_MAX) return format(messages.validation.passwordTooLong, { max: PASSWORD_MAX });
  const local = email?.trim().split('@')[0];
  if (local && local.length > 0 && value.normalize('NFKC').toLowerCase() === local.toLowerCase()) {
    return messages.validation.passwordIsEmailName;
  }
  return null;
}

export function validateDisplayName(value: string): string | null {
  const name = value.trim();
  if (name === '') return messages.validation.displayNameRequired;
  if (codePoints(name) > DISPLAY_NAME_MAX) return format(messages.validation.displayNameTooLong, { max: DISPLAY_NAME_MAX });
  if (CONTROL.test(name)) return messages.validation.displayNameInvalid;
  return null;
}

/** 6 digits; spaces are ignored (the API trims them too). */
export function validateTotpCode(value: string): string | null {
  const code = value.replace(/\s+/g, '');
  if (code === '') return messages.validation.codeRequired;
  return /^\d{6}$/.test(code) ? null : messages.validation.codeInvalid;
}

/** 10 characters of the API's alphabet; case, spaces and the hyphen are ignored (as the API does). */
export function validateRecoveryCode(value: string): string | null {
  const code = value.replace(/[\s-]+/g, '').toUpperCase();
  if (code === '') return messages.validation.recoveryCodeRequired;
  return /^[23456789ABCDEFGHJKLMNPQRSTUVWXYZ]{10}$/.test(code) ? null : messages.validation.recoveryCodeInvalid;
}
