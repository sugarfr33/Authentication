// Endpoints under /api/v1/auth. Responses are copied field by field into our own types, so nothing the
// API might add (now or by mistake) leaks into the app or the store.

import type { HttpClient } from './http';
import type { ActiveSession, LoginResult, MfaEnrollment, RegisterInput, UserProfile } from './types';

function fail(what: string): never {
  throw new Error(`Unexpected ${what} response from the API.`);
}

function asRecord(value: unknown, what: string): Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value) ? (value as Record<string, unknown>) : fail(what);
}

function str(record: Record<string, unknown>, key: string, what: string): string {
  const value = record[key];
  return typeof value === 'string' ? value : fail(what);
}

function bool(record: Record<string, unknown>, key: string, what: string): boolean {
  const value = record[key];
  return typeof value === 'boolean' ? value : fail(what);
}

function strings(record: Record<string, unknown>, key: string, what: string): string[] {
  const value = record[key];
  return Array.isArray(value) && value.every((v) => typeof v === 'string') ? [...(value as string[])] : fail(what);
}

function date(record: Record<string, unknown>, key: string, what: string): Date {
  const parsed = new Date(str(record, key, what));
  return Number.isNaN(parsed.getTime()) ? fail(what) : parsed;
}

export function toProfile(body: unknown): UserProfile {
  const r = asRecord(body, 'profile');
  return {
    id: str(r, 'id', 'profile'),
    email: str(r, 'email', 'profile'),
    emailVerified: bool(r, 'emailVerified', 'profile'),
    displayName: str(r, 'displayName', 'profile'),
    mfaEnabled: bool(r, 'mfaEnabled', 'profile'),
    roles: strings(r, 'roles', 'profile'),
    permissions: strings(r, 'permissions', 'profile'),
  };
}

export function toSession(body: unknown): ActiveSession {
  const r = asRecord(body, 'session');
  return {
    familyId: str(r, 'familyId', 'session'),
    ip: str(r, 'ip', 'session'),
    userAgent: str(r, 'userAgent', 'session'),
    createdUtc: date(r, 'createdUtc', 'session'),
    lastUsedUtc: date(r, 'lastUsedUtc', 'session'),
    isCurrent: bool(r, 'isCurrent', 'session'),
  };
}

function isMfaRequired(body: unknown): boolean {
  return typeof body === 'object' && body !== null && (body as Record<string, unknown>)['mfa_required'] === true;
}

function recoveryCodes(body: unknown): string[] {
  return strings(asRecord(body, 'recovery codes'), 'recoveryCodes', 'recovery codes');
}

export function createAuthApi(http: HttpClient) {
  return {
    async getProfile(): Promise<UserProfile> {
      return toProfile(await http.request<unknown>('/auth/me'));
    },

    async login(email: string, password: string): Promise<LoginResult> {
      const body = await http.request<unknown>('/auth/login', {
        method: 'POST',
        body: { email, password },
        auth: 'anonymous',
      });
      return isMfaRequired(body) ? { kind: 'mfa-required' } : { kind: 'signed-in', profile: toProfile(body) };
    },

    async verifyMfa(code: string, isRecoveryCode: boolean): Promise<UserProfile> {
      const body = await http.request<unknown>('/auth/mfa/verify', {
        method: 'POST',
        body: { code, isRecoveryCode },
        auth: 'anonymous',
      });
      return toProfile(body);
    },

    async logout(): Promise<void> {
      await http.request<void>('/auth/logout', { method: 'POST', auth: 'anonymous' });
    },

    async logoutAll(): Promise<void> {
      await http.request<void>('/auth/logout-all', { method: 'POST' });
    },

    async listSessions(): Promise<ActiveSession[]> {
      const body = await http.request<unknown>('/auth/sessions');
      return Array.isArray(body) ? body.map(toSession) : fail('sessions');
    },

    async revokeSession(familyId: string): Promise<void> {
      await http.request<void>(`/auth/sessions/${encodeURIComponent(familyId)}`, { method: 'DELETE' });
    },

    async register(input: RegisterInput): Promise<void> {
      await http.request<unknown>('/auth/register', {
        method: 'POST',
        body: { email: input.email, password: input.password, displayName: input.displayName },
        auth: 'anonymous',
      });
    },

    async verifyEmail(token: string): Promise<void> {
      await http.request<void>('/auth/verify-email', { method: 'POST', body: { token }, auth: 'anonymous' });
    },

    async forgotPassword(email: string): Promise<void> {
      await http.request<unknown>('/auth/forgot-password', { method: 'POST', body: { email }, auth: 'anonymous' });
    },

    async resetPassword(token: string, newPassword: string): Promise<void> {
      await http.request<void>('/auth/reset-password', {
        method: 'POST',
        body: { token, newPassword },
        auth: 'anonymous',
      });
    },

    async changePassword(currentPassword: string, newPassword: string): Promise<void> {
      await http.request<void>('/auth/change-password', { method: 'POST', body: { currentPassword, newPassword } });
    },

    async enrollMfa(password: string): Promise<MfaEnrollment> {
      const r = asRecord(await http.request<unknown>('/auth/mfa/enroll', { method: 'POST', body: { password } }), 'MFA enrollment');
      return { otpAuthUri: str(r, 'otpAuthUri', 'MFA enrollment'), manualEntryKey: str(r, 'manualEntryKey', 'MFA enrollment') };
    },

    async confirmMfa(code: string): Promise<string[]> {
      return recoveryCodes(await http.request<unknown>('/auth/mfa/confirm', { method: 'POST', body: { code } }));
    },

    async regenerateRecoveryCodes(password: string, code: string, isRecoveryCode: boolean): Promise<string[]> {
      return recoveryCodes(
        await http.request<unknown>('/auth/mfa/recovery-codes', { method: 'POST', body: { password, code, isRecoveryCode } }),
      );
    },

    async disableMfa(password: string, code: string, isRecoveryCode: boolean): Promise<void> {
      await http.request<void>('/auth/mfa/disable', { method: 'POST', body: { password, code, isRecoveryCode } });
    },
  };
}

export type AuthApi = ReturnType<typeof createAuthApi>;
