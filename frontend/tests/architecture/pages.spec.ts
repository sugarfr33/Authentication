// T24: pages compose the T23 kit only (no page-level styles, no raw HTML), and every auth form is wired for
// accessible errors (novalidate + the shared form composable).
import { describe, expect, it } from 'vitest';
import { readSources } from '../helpers/sources';

const pages = [...readSources(['.vue'])].filter(([file]) => /^\/src\/views\/(auth|account)\//.test(file));

describe('auth pages', () => {
  it('finds the pages (sanity check of the scan)', () => {
    expect(pages.map(([file]) => file)).toEqual(
      expect.arrayContaining([
        '/src/views/auth/LoginView.vue',
        '/src/views/auth/MfaChallengeView.vue',
        '/src/views/auth/RegisterView.vue',
        '/src/views/auth/ForgotPasswordView.vue',
        '/src/views/auth/ResetPasswordView.vue',
        '/src/views/auth/VerifyEmailView.vue',
        '/src/views/account/MfaEnrollView.vue',
      ]),
    );
  });

  it.each(pages)('%s has no style block, inline style or raw HTML', (_file, text) => {
    expect(text).not.toMatch(/<style[\s>]/);
    expect(text).not.toMatch(/\sstyle=|:style=/);
    expect(text).not.toMatch(/v-html|innerHTML/);
  });

  it.each(pages.filter(([, text]) => text.includes('<form')))('%s forms use novalidate and the shared form flow', (_file, text) => {
    expect(text).toMatch(/<form[^>]*\snovalidate/);
    expect(text).toContain('useAuthForm');
  });
});
