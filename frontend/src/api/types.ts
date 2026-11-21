// Shapes of the Auth.Api contracts (backend/src/Auth.Contracts), camelCase as the API serialises them.
// Tokens never appear here: they live only in HttpOnly cookies that script cannot read.

export interface UserProfile {
  readonly id: string;
  readonly email: string;
  readonly emailVerified: boolean;
  readonly displayName: string;
  readonly mfaEnabled: boolean;
  readonly roles: readonly string[];
  readonly permissions: readonly string[];
}

export interface ActiveSession {
  readonly familyId: string;
  /** Display only. Render as text, never as HTML. */
  readonly ip: string;
  /** Display only. Render as text, never as HTML. */
  readonly userAgent: string;
  readonly createdUtc: Date;
  readonly lastUsedUtc: Date;
  readonly isCurrent: boolean;
}

/** RP-initiated logout (/oauth/logout): the application, and where to send the browser afterwards (null: stay here). */
export interface LogoutTarget {
  readonly clientId: string;
  /** Built by the server from the application's registered post-logout URIs, with the state appended. */
  readonly redirectTo: string | null;
}

/** The parameters of an RP-initiated logout, as the application sent them in the /logout link. */
export interface LogoutParams {
  readonly clientId: string;
  readonly postLogoutRedirectUri?: string;
  readonly state?: string;
}

export type LoginResult =
  | { readonly kind: 'signed-in'; readonly profile: UserProfile }
  | { readonly kind: 'mfa-required' };

export interface MfaEnrollment {
  readonly otpAuthUri: string;
  readonly manualEntryKey: string;
}

export interface RegisterInput {
  readonly email: string;
  readonly password: string;
  readonly displayName: string;
}
