// T24: the return URL after sign-in is a same-origin path only (no open redirect).
import { describe, expect, it } from 'vitest';
import { parseReturnTo, returnToQuery } from '@/router/returnTo';

const APP = 'https://login.example.com';
const API = 'https://login.example.com';

describe('parseReturnTo', () => {
  it.each([
    ['/', '/'],
    ['/account/mfa', '/account/mfa'],
    ['/account/mfa?tab=1#top', '/account/mfa?tab=1#top'],
    ['/a/../account', '/account'],
  ])('follows the same-origin path %s', (raw, path) => {
    expect(parseReturnTo(raw, APP, API)).toEqual({ kind: 'app', path });
  });

  it.each([
    'https://evil.example',
    '/.//evil.com',
    '/..//evil.com',
    '/a/..//evil.com',
    '/%2e//evil.com',
    '/%2E%2E//evil.com/x?y#z',
    '/././/evil.com',
    'http://evil.example/account',
    '//evil.example',
    '//evil.example/path',
    '/\\evil.example',
    '\\\\evil.example',
    '/\t/evil.example',
    '/\n/evil.example',
    ' /account',
    'javascript:alert(1)',
    'data:text/html,hi',
    'account',
    '',
    '/api/v1/auth/logout',
    '/api/v1/oauth/token',
    '/login',
    '/login/verify',
    '/register?x=1',
    '/reset-password',
    '/verify-email',
    `/${'a'.repeat(5000)}`,
  ])('ignores %j', (raw) => {
    expect(parseReturnTo(raw, APP, API)).toBeNull();
  });

  it('ignores non-strings and takes the first of repeated query values', () => {
    expect(parseReturnTo(undefined, APP, API)).toBeNull();
    expect(parseReturnTo(42, APP, API)).toBeNull();
    expect(parseReturnTo(['/account/mfa', 'https://evil.example'], APP, API)).toEqual({ kind: 'app', path: '/account/mfa' });
    expect(parseReturnTo(['https://evil.example', '/'], APP, API)).toBeNull();
  });

  it('resumes the OAuth authorize path on the API origin, and nothing else under /api', () => {
    const raw = '/api/v1/oauth/authorize?client_id=app&state=s';
    expect(parseReturnTo(raw, APP, 'https://api.example.com')).toEqual({
      kind: 'oauth',
      url: 'https://api.example.com/api/v1/oauth/authorize?client_id=app&state=s',
    });
    expect(parseReturnTo('/api/v1/oauth/authorize', APP, API)).toBeNull();
    expect(parseReturnTo('/api/v1/oauth/authorize/../../auth/logout?x', APP, API)).toBeNull();
    expect(parseReturnTo('/api/v1/oauth/authorizeX?x', APP, API)).toBeNull();
  });

  it('returnToQuery forwards only a safe value', () => {
    expect(returnToQuery('/account/mfa')).toEqual({ returnTo: '/account/mfa' });
    expect(returnToQuery('//evil.example')).toEqual({});
    expect(returnToQuery(undefined)).toEqual({});
  });
});
