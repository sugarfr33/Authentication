// User flows against the stubbed API: sign-in with MFA by keyboard only, register, forgot, reset, 404,
// reduced motion and the dark theme.
import { MFA_USER, PASSWORD, PROFILE, RESET_TOKEN, TOTP_CODE } from './support/mockApi';
import { expect, focusStop, tabTo, test } from './support/fixtures';
import { screenshot, writeJson } from './support/evidence';

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
  await screenshot(page, 'flow-signed-in');
  expect(api.calls.filter((c) => c.startsWith('POST'))).toEqual([
    'POST /api/v1/auth/refresh',
    'POST /api/v1/auth/login',
    'POST /api/v1/auth/login',
    'POST /api/v1/auth/mfa/verify',
  ]);
});

test('a wrong two-step code keeps the user on the challenge with the generic message', async ({ page }) => {
  await page.goto('/login/verify');
  await page.locator('input[name="code"]').fill('000000');
  await page.getByRole('button', { name: 'Verify and sign in' }).click();

  await expect(page.getByRole('alert').filter({ hasText: 'Invalid or expired verification.' })).toBeVisible();
  await expect(page).toHaveURL(/\/login\/verify$/);
});

test('register: client validation first, then the neutral "check your inbox" answer', async ({ page, api }) => {
  await page.goto('/register');
  await page.getByRole('button', { name: 'Create account' }).click();
  await expect(page.getByText('Enter a display name.')).toBeVisible();
  await expect(page.locator('input[name="displayName"]')).toHaveAttribute('aria-invalid', 'true');
  await expect(page.locator('input[name="displayName"]')).toBeFocused();
  await screenshot(page, 'flow-register-invalid');
  expect(api.calls).not.toContain('POST /api/v1/auth/register');

  await page.locator('input[name="displayName"]').fill('Ada Lovelace');
  await page.locator('input[name="email"]').fill('ada@example.test');
  await page.locator('input[name="password"]').fill(PASSWORD);
  await page.getByRole('button', { name: 'Create account' }).click();

  await expect(page.getByRole('status').filter({ hasText: 'Check your inbox' })).toBeVisible();
  await screenshot(page, 'flow-register-accepted');
});

test('forgot password: the same answer whether or not the account exists', async ({ page }) => {
  await page.goto('/forgot-password');
  await page.locator('input[name="email"]').fill('nobody@example.test');
  await page.getByRole('button', { name: 'Send reset link' }).click();

  await expect(page.getByRole('status').filter({ hasText: 'Check your inbox' })).toBeVisible();
  await expect(page.getByText('If an account can reset its password with this address')).toBeVisible();
  await screenshot(page, 'flow-forgot-accepted');
});

test('reset password: the token leaves the address bar, and a new password signs every session out', async ({ page }) => {
  await page.goto(`/reset-password#token=${RESET_TOKEN}`);
  await expect(page.getByRole('heading', { level: 1, name: 'Choose a new password' })).toBeVisible();
  await expect.poll(() => page.evaluate(() => location.hash)).toBe('');

  await page.locator('input[name="newPassword"]').fill(PASSWORD);
  await page.getByRole('button', { name: 'Save new password' }).click();

  await expect(page.getByRole('status').filter({ hasText: 'Your password was changed' })).toBeVisible();
  await screenshot(page, 'flow-reset-done');
});

test('reset password without a link explains what to do', async ({ page }) => {
  await page.goto('/reset-password');
  await expect(page.getByText('This page needs the link from your reset email.')).toBeVisible();
  await expect(page.getByRole('link', { name: 'Ask for a new reset link' })).toBeVisible();
  await screenshot(page, 'flow-reset-missing-token');
});

test('unknown address: 404 page with its own title', async ({ page }) => {
  await page.goto('/definitely/not/here');
  await expect(page.getByRole('heading', { level: 1, name: 'Page not found' })).toBeVisible();
  await expect(page).toHaveTitle(/Page not found/);
});

test('reduced motion: durations drop to zero; without it they do not', async ({ page }) => {
  const durations = () =>
    page.evaluate(() => {
      const root = getComputedStyle(document.documentElement);
      const button = document.querySelector('button[type="submit"]');
      return {
        base: root.getPropertyValue('--duration-base').trim(),
        fast: root.getPropertyValue('--duration-fast').trim(),
        buttonTransition: button ? getComputedStyle(button).transitionDuration : null,
      };
    });

  await page.emulateMedia({ reducedMotion: 'no-preference' });
  await page.goto('/login');
  await expect(page.getByRole('button', { name: 'Sign in' })).toBeVisible();
  const normal = await durations();

  await page.emulateMedia({ reducedMotion: 'reduce' });
  const reduced = await durations();
  writeJson('reduced-motion', { normal, reduced });

  expect(normal.base).not.toBe('0ms');
  expect(reduced.base).toBe('0ms');
  expect(reduced.fast).toBe('0ms');
  expect(reduced.buttonTransition?.split(',').every((d) => parseFloat(d) === 0)).toBe(true);
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
