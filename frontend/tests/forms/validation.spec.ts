// T24: client checks mirror the API rules (the API stays authoritative).
import { describe, expect, it } from 'vitest';
import {
  collectErrors,
  validateCurrentPassword,
  validateDisplayName,
  validateEmail,
  validateNewPassword,
  validateRecoveryCode,
  validateTotpCode,
} from '@/forms/validation';
import { messages } from '@/i18n/messages';

describe('client validation', () => {
  it('email', () => {
    expect(validateEmail('')).toBe(messages.validation.emailRequired);
    expect(validateEmail('   ')).toBe(messages.validation.emailRequired);
    for (const bad of ['name', 'a@b', 'a@@b.com', 'a b@c.com', '@b.com', 'a@.com', 'a@b..com', `${'a'.repeat(250)}@b.com`]) {
      expect(validateEmail(bad), bad).toBe(messages.validation.emailInvalid);
    }
    expect(validateEmail(' Ana.Lee+tag@example.co.uk ')).toBeNull();
  });

  it('current password: presence only, never the policy', () => {
    expect(validateCurrentPassword('')).toBe(messages.validation.passwordRequired);
    expect(validateCurrentPassword('short')).toBeNull();
    expect(validateCurrentPassword('   ')).toBeNull();
  });

  it('new password: 12 to 128 code points after NFKC, not the email local part', () => {
    expect(validateNewPassword('')).toBe(messages.validation.newPasswordRequired);
    expect(validateNewPassword('a'.repeat(11))).toContain('12');
    expect(validateNewPassword('a'.repeat(12))).toBeNull();
    expect(validateNewPassword('😀'.repeat(12))).toBeNull(); // 12 code points, 24 UTF-16 units
    expect(validateNewPassword('a'.repeat(129))).toContain('128');
    expect(validateNewPassword('averylongname', 'AVeryLongName@example.com')).toBe(messages.validation.passwordIsEmailName);
    expect(validateNewPassword('averylongname!', 'averylongname@example.com')).toBeNull();
  });

  it('display name', () => {
    expect(validateDisplayName('  ')).toBe(messages.validation.displayNameRequired);
    expect(validateDisplayName('a'.repeat(129))).toContain('128');
    expect(validateDisplayName('Ana\nLee')).toBe(messages.validation.displayNameInvalid);
    expect(validateDisplayName('Ana Lee')).toBeNull();
  });

  it('codes', () => {
    expect(validateTotpCode('')).toBe(messages.validation.codeRequired);
    expect(validateTotpCode('12345')).toBe(messages.validation.codeInvalid);
    expect(validateTotpCode('12a456')).toBe(messages.validation.codeInvalid);
    expect(validateTotpCode(' 123 456 ')).toBeNull();
    expect(validateRecoveryCode('')).toBe(messages.validation.recoveryCodeRequired);
    expect(validateRecoveryCode('abcde-23456')).toBeNull();
    expect(validateRecoveryCode('ABCDE 23456')).toBeNull();
    expect(validateRecoveryCode('ABCDE-2345O')).toBe(messages.validation.recoveryCodeInvalid); // O is not in the alphabet
    expect(validateRecoveryCode('ABCDE-2345')).toBe(messages.validation.recoveryCodeInvalid);
  });

  it('collectErrors drops valid fields', () => {
    expect(collectErrors({ a: null, b: 'bad' })).toEqual({ b: 'bad' });
  });
});
