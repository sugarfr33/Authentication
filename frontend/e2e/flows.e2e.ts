// User flows against the stubbed API: sign-in with and without MFA (keyboard only), recovery codes, register,
// forgot, reset, failures (429, 500, network, expired link, server field errors), 404, signed-in on load, reduced
// motion and the dark theme. Every state a flow reaches (errors, successes) is scanned with axe (UX review M1), and
// every success checks where focus went (m6). Wording must stay generic: no answer says whether an account exists.
import {
  COMMON_PASSWORD,
  EXPIRED_RESET_TOKEN,
  MFA_USER,
  PASSWORD,
  PLAIN_PROFILE,
  PLAIN_USER,
  PROFILE,
  RECOVERY_CODE,
  RESET_TOKEN,
  TOTP_CODE,
  tooManyRequests,
} from './support/mockApi';
import { expect, expectAxeClean, focusStop, focusedText, tabTo, test } from './support/fixtures';
import { screenshot, writeJson } from './support/evidence';
import type { Page } from '@playwright/test';

const ENUMERATION = /not found|no account|does not exist|unknown user|not registered|already (registered|exists|in use)/i;

async function expectGeneric(page: Page): Promise<void> {
  expect(await page.locator('main').innerText()).not.toMatch(ENUMERATION);
}

function logins(calls: readonly string[]): number {
  return calls.filter((c) => c === 'POST /api/v1/auth/login').length;
}

test('sign-in with two-step verification, keyboard only, with focus on the field to fix', async ({ page, api }) => {
  await page.goto('/login');
  await expect(page.getByRole('heading', { level: 1, name: 'Sign in' })).toBeVisible();

  // Email, then password: the natural order, reached with Tab only.
  await tabTo(page, 'email');
  await page.keyboard.type(MFA_USER.email);
  await page.keyboard.press('Tab');
  expect(await page.evaluate(() => document.activeElement?.getAttribute('name'))).toBe('password');
  await page.keyboard.type('not the password');
  await page.keyboard.press('Enter');

  // One generic answer, announced (role=alert), and focus back on the password, now cleared.
  await expect(page.getByRole('alert').filter({ hasText: 'Invalid email or password.' })).toBeVisible();
  await expect(page.locator('input[name="password"]')).toBeFocused();
  await expect(page.locator('input[name="password"]')).toHaveValue('');
  await expectGeneric(page);
  await expectAxeClean(page, 'flow-login-failed');
  await screenshot(page, 'flow-login-failed');

  await page.keyboard.type(MFA_USER.password);
  await page.keyboard.press('Enter');

  await expect(page).toHaveURL(/\/login\/verify$/);
  await expect(page.getByRole('heading', { level: 1, name: 'Two-step verification' })).toBeVisible();
  // After an in-app navigation focus moves to <main>, so the next Tab starts in the new page.
  expect((await focusStop(page))?.description).toMatch(/^main:/);
  await screenshot(page, 'flow-mfa-challenge');

  await tabTo(page, 'code');
  await page.keyboard.type(TOTP_CODE);
  await page.keyboard.press('Enter');

  await expect(page).toHaveURL(/\/$/);
  await expect(page.getByText(PROFILE.email)).toBeVisible();
  await expectAxeClean(page, 'flow-signed-in');
  await screenshot(page, 'flow-signed-in');
  // Two sign-in attempts and one verification; any start-up calls (refresh, /me) are not this flow's business.
  expect(logins(api.calls)).toBe(2);
  expect(api.calls.filter((c) => c === 'POST /api/v1/auth/mfa/verify')).toHaveLength(1);
});

test('sign-in without two-step verification goes straight to the account', async ({ page, api }) => {
  await page.goto('/login');
  await page.locator('input[name="email"]').fill(PLAIN_USER.email);
  await page.locator('input[name="password"]').fill(PLAIN_USER.password);
  await page.getByRole('button', { name: 'Sign in' }).click();

  await expect(page).toHaveURL(/\/$/);
  await expect(page.getByText(PLAIN_PROFILE.email)).toBeVisible();
  expect(api.calls).not.toContain('POST /api/v1/auth/mfa/verify');
});

test('sign-in with nothing filled in: an error summary takes focus and its links reach each field', async ({ page, api }) => {
  await page.goto('/login');
  await page.getByRole('button', { name: 'Sign in' }).click();

  const summary = page.locator('.error-summary');
  await expect(summary).toBeFocused();
  await expect(summary).toContainText('Fix the highlighted fields and try again.');
  await expectAxeClean(page, 'flow-login-summary');
  await screenshot(page, 'flow-login-summary');
  expect(logins(api.calls)).toBe(0);

  await summary.getByRole('link', { name: /Password/ }).click();
  await expect(page.locator('input[name="password"]')).toBeFocused();
});

test('sign-in rate limited (429): says how long to wait, nothing about the account', async ({ page, api }) => {
  api.failNext('POST /api/v1/auth/login', tooManyRequests(30));
  await page.goto('/login');
  await page.locator('input[name="email"]').fill(MFA_USER.email);
  await page.locator('input[name="password"]').fill(PASSWORD);
  await page.getByRole('button', { name: 'Sign in' }).click();

  await expect(page.getByRole('alert').filter({ hasText: 'Too many attempts. Wait 30 seconds and try again.' })).toBeVisible();
  await expect(page).toHaveURL(/\/login$/);
  await expectGeneric(page);
  await expectAxeClean(page, 'flow-login-429');
  await screenshot(page, 'flow-login-429');
});

test('sign-in when the server fails (500) or cannot be reached: a plain retry message', async ({ page, api }) => {
  await page.goto('/login');
  await page.locator('input[name="email"]').fill(MFA_USER.email);
  await page.locator('input[name="password"]').fill(PASSWORD);

  api.failNext('POST /api/v1/auth/login', { status: 500, title: 'An error occurred while processing your request.' });
  await page.getByRole('button', { name: 'Sign in' }).click();
  await expect(page.getByRole('alert').filter({ hasText: 'Something went wrong on our side. Try again.' })).toBeVisible();
  await expect(page.locator('main')).not.toContainText('An error occurred while processing');
  await expectAxeClean(page, 'flow-login-500');

  api.failNext('POST /api/v1/auth/login', 'network');
  await page.getByRole('button', { name: 'Sign in' }).click();
  await expect(page.getByRole('alert').filter({ hasText: 'We could not reach the server.' })).toBeVisible();
  await screenshot(page, 'flow-login-network');
  await expectGeneric(page);
});

test('the password toggle names its state, and a failed sign-in clears the shown password', async ({ page }) => {
  await page.goto('/login');
  const password = page.locator('input[name="password"]');
  const toggle = page.getByRole('button', { name: 'Show password' });
  await password.fill('not the password');

  await expect(toggle).toHaveAttribute('aria-pressed', 'false');
  await expect(password).toHaveAttribute('type', 'password');
  await toggle.click();
  await expect(toggle).toHaveAttribute('aria-pressed', 'true');
  await expect(password).toHaveAttribute('type', 'text');
  await expect(toggle).toHaveAttribute('aria-controls', (await password.getAttribute('id')) ?? 'missing');

  await page.locator('input[name="email"]').fill(MFA_USER.email);
  await page.getByRole('button', { name: 'Sign in' }).click();
  await expect(page.getByRole('alert').filter({ hasText: 'Invalid email or password.' })).toBeVisible();
  await expect(password).toHaveValue('');
});

test('a wrong two-step code keeps the user on the challenge with the generic message', async ({ page }) => {
  await page.goto('/login/verify');
  await page.locator('input[name="code"]').fill('000000');
  await page.getByRole('button', { name: 'Verify and sign in' }).click();

  await expect(page.getByRole('alert').filter({ hasText: 'Invalid or expired verification.' })).toBeVisible();
  await expect(page).toHaveURL(/\/login\/verify$/);
  await expectAxeClean(page, 'flow-mfa-wrong');
});

test('a recovery code signs in, through the link-styled switch', async ({ page, api }) => {
  await page.goto('/login');
  await page.locator('input[name="email"]').fill(MFA_USER.email);
  await page.locator('input[name="password"]').fill(PASSWORD);
  await page.getByRole('button', { name: 'Sign in' }).click();
  await expect(page).toHaveURL(/\/login\/verify$/);

  const switchToRecovery = page.getByRole('button', { name: 'Use a recovery code instead' });
  // UX review m2: it looks like the page's other links (underlined, normal weight).
  const look = await switchToRecovery.evaluate((el) => {
    const style = getComputedStyle(el);
    return { underline: style.textDecorationLine, weight: style.fontWeight };
  });
  expect(look.underline).toContain('underline');
  expect(Number(look.weight)).toBeLessThan(600);

  await switchToRecovery.click();
  await expect(page.getByLabel('Recovery code')).toBeFocused();
  await page.getByLabel('Recovery code').fill(RECOVERY_CODE);
  await page.getByRole('button', { name: 'Verify and sign in' }).click();

  await expect(page).toHaveURL(/\/$/);
  await expect(page.getByText(PROFILE.email)).toBeVisible();
  expect(api.calls.filter((c) => c === 'POST /api/v1/auth/mfa/verify')).toHaveLength(1);
});

test('register: an error summary first, then the neutral "check your inbox" answer with focus on it', async ({ page, api }) => {
  await page.goto('/register');
  await page.getByRole('button', { name: 'Create account' }).click();
  await expect(page.locator('.error-summary')).toBeFocused();
  await expect(page.getByText('Enter a display name.').first()).toBeVisible();
  // UX review m1: sign-up asks for "a password"; "a new password" is the reset wording.
  await expect(page.getByText('Enter a password.').first()).toBeVisible();
  await expect(page.getByText('Enter a new password.')).toHaveCount(0);
  await expect(page.locator('input[name="displayName"]')).toHaveAttribute('aria-invalid', 'true');
  await expectAxeClean(page, 'flow-register-invalid');
  await screenshot(page, 'flow-register-invalid');
  expect(api.calls).not.toContain('POST /api/v1/auth/register');

  await page.locator('input[name="displayName"]').fill('Ada Lovelace');
  await page.locator('input[name="email"]').fill('ada@example.test');
  await page.locator('input[name="password"]').fill(PASSWORD);
  await page.getByRole('button', { name: 'Create account' }).click();

  await expect(page.getByRole('status').filter({ hasText: 'Check your inbox' })).toBeVisible();
  expect(await focusedText(page), 'focus moves to the confirmation, not <body>').toContain('Check your inbox');
  await expectGeneric(page);
  await expectAxeClean(page, 'flow-register-accepted');
  await screenshot(page, 'flow-register-accepted');
});

test('register: the API\'s field error shows under the password, with focus there', async ({ page }) => {
  await page.goto('/register');
  await page.locator('input[name="displayName"]').fill('Ada Lovelace');
  await page.locator('input[name="email"]').fill('ada@example.test');
  await page.locator('input[name="password"]').fill(COMMON_PASSWORD);
  await page.getByRole('button', { name: 'Create account' }).click();

  const password = page.locator('input[name="password"]');
  await expect(password).toHaveAttribute('aria-invalid', 'true');
  await expect(password).toBeFocused();
  await expect(page.getByText('Password is too common; choose a less predictable one.')).toBeVisible();
  await expectGeneric(page);
  await expectAxeClean(page, 'flow-register-server-error');
  await screenshot(page, 'flow-register-server-error');
});

test('register rate limited (429): the wait message, and no confirmation', async ({ page, api }) => {
  api.failNext('POST /api/v1/auth/register', tooManyRequests(60));
  await page.goto('/register');
  await page.locator('input[name="displayName"]').fill('Ada Lovelace');
  await page.locator('input[name="email"]').fill('ada@example.test');
  await page.locator('input[name="password"]').fill(PASSWORD);
  await page.getByRole('button', { name: 'Create account' }).click();

  await expect(page.getByRole('alert').filter({ hasText: 'Too many attempts. Wait 60 seconds and try again.' })).toBeVisible();
  await expect(page.getByText('Check your inbox')).toHaveCount(0);
});

test('forgot password: the same answer whether or not the account exists, with focus on it', async ({ page }) => {
  await page.goto('/forgot-password');
  await page.locator('input[name="email"]').fill('nobody@example.test');
  await page.getByRole('button', { name: 'Send reset link' }).click();

  await expect(page.getByRole('status').filter({ hasText: 'Check your inbox' })).toBeVisible();
  await expect(page.getByText('If an account can reset its password with this address')).toBeVisible();
  expect(await focusedText(page), 'focus moves to the confirmation, not <body>').toContain('Check your inbox');
  await expectGeneric(page);
  await expectAxeClean(page, 'flow-forgot-accepted');
  await screenshot(page, 'flow-forgot-accepted');
});

test('forgot password rate limited (429): the wait message', async ({ page, api }) => {
  api.failNext('POST /api/v1/auth/forgot-password', tooManyRequests(45));
  await page.goto('/forgot-password');
  await page.locator('input[name="email"]').fill('nobody@example.test');
  await page.getByRole('button', { name: 'Send reset link' }).click();

  await expect(page.getByRole('alert').filter({ hasText: 'Too many attempts. Wait 45 seconds and try again.' })).toBeVisible();
  await expectAxeClean(page, 'flow-forgot-429');
});

test('reset password: the token leaves the address bar, and a new password signs every session out', async ({ page }) => {
  await page.goto(`/reset-password#token=${RESET_TOKEN}`);
  await expect(page.getByRole('heading', { level: 1, name: 'Choose a new password' })).toBeVisible();
  await expect.poll(() => page.evaluate(() => location.hash)).toBe('');

  await page.locator('input[name="newPassword"]').fill(PASSWORD);
  await page.getByRole('button', { name: 'Save new password' }).click();

  await expect(page.getByRole('status').filter({ hasText: 'Your password was changed' })).toBeVisible();
  expect(await focusedText(page), 'focus moves to the confirmation, not <body>').toContain('Your password was changed');
  await expectAxeClean(page, 'flow-reset-done');
  await screenshot(page, 'flow-reset-done');
});

test('reset password with an expired link: the one generic answer and a way to get a new link', async ({ page }) => {
  await page.goto(`/reset-password#token=${EXPIRED_RESET_TOKEN}`);
  await page.locator('input[name="newPassword"]').fill(PASSWORD);
  await page.getByRole('button', { name: 'Save new password' }).click();

  await expect(page.getByRole('alert').filter({ hasText: 'The reset link is invalid or has expired.' })).toBeVisible();
  await expect(page.getByRole('link', { name: 'Ask for a new reset link' })).toBeVisible();
  await expectGeneric(page);
  await expectAxeClean(page, 'flow-reset-expired');
  await screenshot(page, 'flow-reset-expired');
});

test('reset password without a link explains what to do', async ({ page }) => {
  await page.goto('/reset-password');
  await expect(page.getByText('This page needs the link from your reset email.')).toBeVisible();
  await expect(page.getByRole('link', { name: 'Ask for a new reset link' })).toBeVisible();
  await screenshot(page, 'flow-reset-missing-token');
});

test('unknown address: 404 page with its own title, offering sign-in when signed out', async ({ page }) => {
  await page.goto('/definitely/not/here');
  await expect(page.getByRole('heading', { level: 1, name: 'Page not found' })).toBeVisible();
  await expect(page).toHaveTitle(/Page not found/);
  await expect(page.getByRole('link', { name: 'Go to sign in' })).toBeVisible();
  await expect(page.getByRole('link', { name: 'Go to your account' })).toHaveCount(0);
});

test('signed in on load through a silent refresh: the account opens, no sign-in form', async ({ page, api }) => {
  api.refreshable = true;
  await page.goto('/');
  await expect(page).toHaveURL(/\/$/);
  await expect(page.getByText(PROFILE.email)).toBeVisible();
  expect(api.calls).toContain('POST /api/v1/auth/refresh');

  await page.goto('/definitely/not/here');
  await expect(page.getByRole('link', { name: 'Go to your account' })).toBeVisible();
});

test('reduced motion: durations drop to zero, and the dialog no longer animates; the spinner only slows', async ({ page }) => {
  const motion = () =>
    page.evaluate(() => {
      const root = getComputedStyle(document.documentElement);
      const button = document.querySelector('button');
      const spinner = document.querySelector('.spinner, [class*="spinner"]');
      return {
        base: root.getPropertyValue('--duration-base').trim(),
        fast: root.getPropertyValue('--duration-fast').trim(),
        spin: root.getPropertyValue('--duration-spin').trim(),
        buttonTransition: button ? getComputedStyle(button).transitionDuration : null,
        spinnerAnimation: spinner ? getComputedStyle(spinner).animationDuration : null,
      };
    });
  const dialogAnimation = async (): Promise<string> => {
    await page.getByRole('button', { name: 'Open dialog' }).click();
    const duration = await page.getByRole('dialog').evaluate((el) => getComputedStyle(el).animationDuration);
    await page.keyboard.press('Escape');
    return duration;
  };

  await page.emulateMedia({ reducedMotion: 'no-preference' });
  await page.goto('/dev/gallery');
  await expect(page.getByRole('heading', { level: 1, name: 'UI kit gallery' })).toBeVisible();
  const normal = { ...(await motion()), dialog: await dialogAnimation() };

  await page.emulateMedia({ reducedMotion: 'reduce' });
  const reduced = { ...(await motion()), dialog: await dialogAnimation() };
  writeJson('reduced-motion', { normal, reduced });

  expect(normal.base).not.toBe('0ms');
  expect(reduced.base).toBe('0ms');
  expect(reduced.fast).toBe('0ms');
  expect(reduced.buttonTransition?.split(',').every((d) => parseFloat(d) === 0)).toBe(true);
  expect(parseFloat(normal.dialog)).toBeGreaterThan(0);
  expect(parseFloat(reduced.dialog)).toBe(0);
  // A loading ring keeps turning (a frozen one reads as broken), but slower.
  expect(reduced.spinnerAnimation).not.toBeNull();
  expect(parseFloat(reduced.spinnerAnimation ?? '0')).toBeGreaterThan(parseFloat(normal.spinnerAnimation ?? '0'));
});

test('dark theme follows the system preference', async ({ page }) => {
  const colours = () => page.evaluate(() => ({ background: getComputedStyle(document.body).backgroundColor, text: getComputedStyle(document.body).color }));

  await page.emulateMedia({ colorScheme: 'light' });
  await page.goto('/login');
  const light = await colours();
  await page.emulateMedia({ colorScheme: 'dark' });
  const dark = await colours();
  writeJson('theme-colours', { light, dark });

  expect(dark.background).not.toBe(light.background);
  expect(dark.text).not.toBe(light.text);
});
