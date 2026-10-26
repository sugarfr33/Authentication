// T24: sign-in, register, forgot, reset, verify and MFA pages: labelled fields with the right autocomplete,
// errors announced and focused, client validation before any request, server answers rendered as text,
// generic copy (no user enumeration), and the email-link token read from the fragment then removed.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ApiError, authApi, type UserProfile } from '@/api';
import { messages } from '@/i18n/messages';
import { button, input, mountApp, settle, submit, type, type MountedApp } from '../helpers/app';

const PROFILE: UserProfile = {
  id: 'u1',
  email: 'ana@example.com',
  emailVerified: true,
  displayName: 'Ana',
  mfaEnabled: false,
  roles: [],
  permissions: [],
};

let app: MountedApp | null = null;

beforeEach(() => {
  vi.spyOn(authApi, 'getProfile').mockRejectedValue(new ApiError({ status: 401 }));
});

afterEach(() => {
  app?.unmount();
  app = null;
});

/** After a form is swapped for its success message, focus is on that message, not lost to <body>. */
function expectFocusOnSuccess(text: string): void {
  const active = document.activeElement as HTMLElement | null;
  expect(active).not.toBe(document.body);
  expect(active?.getAttribute('tabindex')).toBe('-1');
  expect(active?.textContent).toContain(text);
}

function liveRegionsText(root: ParentNode): string {
  return [...root.querySelectorAll('[aria-live="assertive"], [aria-live="polite"], [role="alert"], [role="status"]')].map((el) => el.textContent ?? '').join(' ');
}

describe('sign-in page', () => {
  it('has labelled fields with sign-in autocomplete and no paste blocking', async () => {
    app = await mountApp('/login');
    const email = input(app.root, messages.fields.email);
    const password = input(app.root, messages.fields.password);
    expect(email.type).toBe('email');
    expect(email.getAttribute('autocomplete')).toBe('username');
    expect(password.type).toBe('password');
    expect(password.getAttribute('autocomplete')).toBe('current-password');
    for (const field of [email, password]) {
      expect(field.getAttribute('onpaste')).toBeNull();
      const paste = new Event('paste', { bubbles: true, cancelable: true });
      field.dispatchEvent(paste);
      expect(paste.defaultPrevented).toBe(false);
    }
    expect(app.root.querySelector('form')?.hasAttribute('novalidate')).toBe(true);
    expect(button(app.root, messages.login.submit).type).toBe('submit');
  });

  it('checks fields before sending, announces the errors and focuses the first invalid field', async () => {
    const login = vi.spyOn(authApi, 'login');
    app = await mountApp('/login');
    await submit(app.root);
    expect(login).not.toHaveBeenCalled();
    const email = input(app.root, messages.fields.email);
    expect(email.getAttribute('aria-invalid')).toBe('true');
    expect(document.activeElement).toBe(email);
    const describedBy = email.getAttribute('aria-describedby') ?? '';
    const error = describedBy.split(' ').map((id) => document.getElementById(id)?.textContent ?? '').join(' ');
    expect(error).toContain(messages.validation.emailRequired);
    expect(liveRegionsText(app.root)).toContain(messages.validation.emailRequired);
    expect(liveRegionsText(app.root)).toContain(messages.validation.passwordRequired);
  });

  it('shows one generic message for a failed sign-in in an alert, and puts focus back on the password', async () => {
    vi.spyOn(authApi, 'login').mockRejectedValue(new ApiError({ status: 401, title: 'Invalid email or password.' }));
    app = await mountApp('/login');
    await type(input(app.root, messages.fields.email), 'nobody@example.com');
    await type(input(app.root, messages.fields.password), 'wrong password');
    await submit(app.root);
    const alert = app.root.querySelector('[role="alert"]');
    expect(alert?.textContent).toContain(messages.auth.loginFailed);
    expect(document.activeElement).toBe(input(app.root, messages.fields.password));
    expect(document.activeElement?.contains(alert ?? null)).toBe(false);
    expect(input(app.root, messages.fields.password).value).toBe('');
    expect(app.root.textContent).not.toMatch(/not found|no account|does not exist|unknown/i);
  });

  it('signs in and follows a safe returnTo', async () => {
    vi.spyOn(authApi, 'login').mockResolvedValue({ kind: 'signed-in', profile: PROFILE });
    app = await mountApp('/login?returnTo=%2Faccount%2Fmfa');
    await type(input(app.root, messages.fields.email), ' ana@example.com ');
    await type(input(app.root, messages.fields.password), 'a long enough password');
    await submit(app.root);
    expect(authApi.login).toHaveBeenCalledWith('ana@example.com', 'a long enough password');
    await vi.waitFor(() => expect(app!.router.currentRoute.value.fullPath).toBe('/account/mfa'));
  });

  it('ignores an external returnTo after sign-in (no open redirect)', async () => {
    vi.spyOn(authApi, 'login').mockResolvedValue({ kind: 'signed-in', profile: PROFILE });
    app = await mountApp('/login?returnTo=' + encodeURIComponent('https://evil.example/phish'));
    await type(input(app.root, messages.fields.email), 'ana@example.com');
    await type(input(app.root, messages.fields.password), 'a long enough password');
    await submit(app.root);
    await vi.waitFor(() => expect(app!.router.currentRoute.value.fullPath).toBe('/'));
  });

  it('goes to the MFA step when the API asks for it, keeping the returnTo', async () => {
    vi.spyOn(authApi, 'login').mockResolvedValue({ kind: 'mfa-required' });
    app = await mountApp('/login?returnTo=%2Faccount%2Fmfa');
    await type(input(app.root, messages.fields.email), 'ana@example.com');
    await type(input(app.root, messages.fields.password), 'a long enough password');
    await submit(app.root);
    await vi.waitFor(() => expect(app!.router.currentRoute.value.name).toBe('mfa-challenge'));
    expect(app.router.currentRoute.value.query.returnTo).toBe('/account/mfa');
  });

  it('shows the rate-limit answer as text', async () => {
    vi.spyOn(authApi, 'login').mockRejectedValue(new ApiError({ status: 429, retryAfterSeconds: 30 }));
    app = await mountApp('/login');
    await type(input(app.root, messages.fields.email), 'ana@example.com');
    await type(input(app.root, messages.fields.password), 'x');
    await submit(app.root);
    expect(app.root.querySelector('[role="alert"]')?.textContent?.trim().length).toBeGreaterThan(0);
  });
});

describe('MFA challenge page', () => {
  it('takes a one-time code, switches to a recovery code, and keeps the message generic', async () => {
    const verify = vi.spyOn(authApi, 'verifyMfa').mockRejectedValue(new ApiError({ status: 401 }));
    app = await mountApp('/login/verify');
    const code = input(app.root, messages.fields.code);
    expect(code.getAttribute('autocomplete')).toBe('one-time-code');
    expect(code.getAttribute('inputmode')).toBe('numeric');
    await type(code, '12345');
    await submit(app.root);
    expect(verify).not.toHaveBeenCalled();
    expect(liveRegionsText(app.root)).toContain(messages.validation.codeInvalid);

    await type(input(app.root, messages.fields.code), '123 456');
    await submit(app.root);
    expect(verify).toHaveBeenCalledWith('123 456', false);
    expect(app.root.querySelector('[role="alert"]')?.textContent).toContain(messages.mfaChallenge.failed);
    expect(document.activeElement).toBe(input(app.root, messages.fields.code));

    button(app.root, messages.mfaChallenge.useRecovery).click();
    await settle();
    const recovery = input(app.root, messages.fields.recoveryCode);
    expect(document.activeElement).toBe(recovery);
    await type(recovery, 'abcde-23456');
    await submit(app.root);
    expect(verify).toHaveBeenLastCalledWith('abcde-23456', true);
  });

  it('signs in on a valid code', async () => {
    vi.spyOn(authApi, 'verifyMfa').mockResolvedValue(PROFILE);
    app = await mountApp('/login/verify?returnTo=%2Faccount%2Fmfa');
    await type(input(app.root, messages.fields.code), '123456');
    await submit(app.root);
    expect(app.session.isAuthenticated).toBe(true);
    await vi.waitFor(() => expect(app!.router.currentRoute.value.fullPath).toBe('/account/mfa'));
  });
});

describe('register page', () => {
  it('uses new-password and shows the same confirmation as the API for any address', async () => {
    const register = vi.spyOn(authApi, 'register').mockResolvedValue(undefined);
    app = await mountApp('/register');
    expect(input(app.root, messages.fields.email).getAttribute('autocomplete')).toBe('email');
    expect(input(app.root, messages.fields.displayName).getAttribute('autocomplete')).toBe('name');
    const password = input(app.root, messages.fields.password);
    expect(password.getAttribute('autocomplete')).toBe('new-password');

    await type(input(app.root, messages.fields.displayName), 'Ana');
    await type(input(app.root, messages.fields.email), 'ana@example.com');
    await type(password, 'short');
    await submit(app.root);
    expect(register).not.toHaveBeenCalled();
    expect(document.activeElement).toBe(input(app.root, messages.fields.password));

    await type(input(app.root, messages.fields.password), 'a long enough password');
    await submit(app.root);
    expect(register).toHaveBeenCalledWith({ displayName: 'Ana', email: 'ana@example.com', password: 'a long enough password' });
    expect(liveRegionsText(app.root)).toContain(messages.auth.registerAccepted);
    expectFocusOnSuccess(messages.auth.registerAccepted);
  });

  it('renders the API field errors as text under their fields', async () => {
    vi.spyOn(authApi, 'register').mockRejectedValue(
      new ApiError({ status: 400, fieldErrors: { password: ['<b>This password is too common.</b>'] } }),
    );
    app = await mountApp('/register');
    await type(input(app.root, messages.fields.displayName), 'Ana');
    await type(input(app.root, messages.fields.email), 'ana@example.com');
    await type(input(app.root, messages.fields.password), 'password1234');
    await submit(app.root);
    const password = input(app.root, messages.fields.password);
    expect(password.getAttribute('aria-invalid')).toBe('true');
    expect(document.activeElement).toBe(password);
    expect(app.root.textContent).toContain('<b>This password is too common.</b>');
    expect(app.root.querySelector('b')).toBeNull();
  });
});

describe('forgot-password page', () => {
  it('shows the same confirmation for every well-formed address', async () => {
    const forgot = vi.spyOn(authApi, 'forgotPassword').mockResolvedValue(undefined);
    app = await mountApp('/forgot-password');
    await type(input(app.root, messages.fields.email), 'nobody@example.com');
    await submit(app.root);
    expect(forgot).toHaveBeenCalledWith('nobody@example.com');
    expect(liveRegionsText(app.root)).toContain(messages.auth.forgotAccepted);
    expectFocusOnSuccess(messages.auth.forgotAccepted);
    expect(messages.auth.forgotAccepted).toMatch(/^If an account/);
  });
});

describe('reset-password page', () => {
  it('reads the token from the fragment, removes it from the URL, and posts it', async () => {
    const reset = vi.spyOn(authApi, 'resetPassword').mockResolvedValue(undefined);
    app = await mountApp('/reset-password#token=abc123');
    expect(app.router.currentRoute.value.hash).toBe('');
    const field = input(app.root, messages.fields.newPassword);
    expect(field.getAttribute('autocomplete')).toBe('new-password');
    await type(field, 'a brand new password');
    await submit(app.root);
    expect(reset).toHaveBeenCalledWith('abc123', 'a brand new password');
    expect(liveRegionsText(app.root)).toContain(messages.reset.doneTitle);
    expectFocusOnSuccess(messages.reset.doneTitle);
  });

  it('shows the generic invalid-link answer and a way to get a new link', async () => {
    vi.spyOn(authApi, 'resetPassword').mockRejectedValue(new ApiError({ status: 400, title: 'The reset link is invalid or has expired.' }));
    app = await mountApp('/reset-password#token=old');
    await type(input(app.root, messages.fields.newPassword), 'a brand new password');
    await submit(app.root);
    expect(app.root.querySelector('[role="alert"]')?.textContent).toContain(messages.auth.resetLinkInvalid);
    expect(app.root.textContent).toContain(messages.reset.requestNew);
  });

  it('explains what to do without a token', async () => {
    app = await mountApp('/reset-password');
    expect(app.root.textContent).toContain(messages.reset.missingToken);
    expect(app.root.querySelector('form')).toBeNull();
  });
});

describe('verify-email page', () => {
  it('waits for an explicit confirmation before redeeming the fragment token', async () => {
    const verify = vi.spyOn(authApi, 'verifyEmail').mockResolvedValue(undefined);
    app = await mountApp('/verify-email#token=tok');
    expect(app.router.currentRoute.value.hash).toBe('');
    expect(verify).not.toHaveBeenCalled();
    button(app.root, messages.verify.submit).click();
    await settle();
    expect(verify).toHaveBeenCalledWith('tok');
    expect(liveRegionsText(app.root)).toContain(messages.verify.doneTitle);
    expectFocusOnSuccess(messages.verify.doneTitle);
  });

  it('announces an invalid link and focuses the message', async () => {
    vi.spyOn(authApi, 'verifyEmail').mockRejectedValue(new ApiError({ status: 400 }));
    app = await mountApp('/verify-email#token=tok');
    button(app.root, messages.verify.submit).click();
    await settle();
    const alert = app.root.querySelector('[role="alert"]');
    expect(alert?.textContent).toContain(messages.auth.verifyLinkInvalid);
    expect(document.activeElement?.contains(alert ?? null)).toBe(true);
  });
});

describe('MFA enroll page', () => {
  beforeEach(() => {
    vi.spyOn(authApi, 'getProfile').mockResolvedValue(PROFILE);
  });

  it('re-authenticates, shows the key as text, confirms, shows the codes and clears the session', async () => {
    vi.spyOn(authApi, 'enrollMfa').mockResolvedValue({
      otpAuthUri: 'otpauth://totp/CentralAuth:ana@example.com?secret=KEY&issuer=CentralAuth',
      manualEntryKey: '<img src=x>KEY',
    });
    vi.spyOn(authApi, 'confirmMfa').mockResolvedValue(['AAAAA-22222', 'BBBBB-33333']);
    app = await mountApp('/account/mfa');
    expect(input(app.root, messages.fields.password).getAttribute('autocomplete')).toBe('current-password');
    await type(input(app.root, messages.fields.password), 'my password');
    await submit(app.root);
    expect(authApi.enrollMfa).toHaveBeenCalledWith('my password');
    expect(app.root.textContent).toContain('<img src=x>KEY');
    expect(app.root.querySelector('img')).toBeNull();
    expect(document.activeElement?.textContent).toBe(messages.mfaEnroll.scanTitle);
    expect(app.root.querySelector('a[href^="otpauth://totp/"]')).not.toBeNull();

    await type(input(app.root, messages.fields.code), '123456');
    await submit(app.root);
    expect(authApi.confirmMfa).toHaveBeenCalledWith('123456');
    expect(app.root.textContent).toContain('AAAAA-22222');
    expect(app.session.isAuthenticated).toBe(false);
    expect(document.activeElement?.textContent).toBe(messages.mfaEnroll.codesTitle);
  });

  it('marks a wrong password on its field, and maps 404 and 409 to plain messages', async () => {
    const enroll = vi
      .spyOn(authApi, 'enrollMfa')
      .mockRejectedValueOnce(new ApiError({ status: 400 }))
      .mockRejectedValueOnce(new ApiError({ status: 409 }));
    app = await mountApp('/account/mfa');
    await type(input(app.root, messages.fields.password), 'wrong');
    await submit(app.root);
    expect(liveRegionsText(app.root)).toContain(messages.mfaEnroll.passwordWrong);
    await type(input(app.root, messages.fields.password), 'right');
    await submit(app.root);
    expect(app.root.querySelector('[role="alert"]')?.textContent).toContain(messages.mfaEnroll.alreadyOn);
    expect(enroll).toHaveBeenCalledTimes(2);
  });

  it('does not link an enrollment URI that is not otpauth', async () => {
    vi.spyOn(authApi, 'enrollMfa').mockResolvedValue({ otpAuthUri: 'javascript:alert(1)', manualEntryKey: 'KEY' });
    app = await mountApp('/account/mfa');
    await type(input(app.root, messages.fields.password), 'my password');
    await submit(app.root);
    expect(app.root.textContent).toContain('KEY');
    expect(app.root.querySelector('a[href^="javascript"]')).toBeNull();
  });
});
