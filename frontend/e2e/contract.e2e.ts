// T31 (UX review M3): the stub answers with the API's real shapes and wording. Reads the backend C# source (no build,
// no browser) so a renamed field, a changed status title or a new profile property fails here, not silently in the UI.
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { expect, test } from '@playwright/test';
import { API_TEXT, PLAIN_PROFILE, PROFILE } from './support/mockApi';

const backend = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..', 'backend', 'src');
const source = (path: string): string => readFileSync(resolve(backend, path), 'utf8');

/** Parameter names of a positional C# record, camelCased as System.Text.Json writes them. */
function recordProperties(text: string, record: string): string[] {
  const match = new RegExp(`record\\s+${record}\\s*\\(([\\s\\S]*?)\\);`).exec(text);
  if (!match?.[1]) throw new Error(`record ${record} not found`);
  return match[1]
    .replace(/\[[^\]]*\]/g, '') // attributes such as [property: JsonPropertyName(...)]
    .split(',')
    .map((p) => p.trim().split(/\s+/).pop() ?? '')
    .map((name) => name.charAt(0).toLowerCase() + name.slice(1));
}

test('the profile has exactly the properties of UserProfileResponse', () => {
  const properties = recordProperties(source('Auth.Contracts/Responses/UserProfileResponse.cs'), 'UserProfileResponse');
  expect(Object.keys(PROFILE).sort()).toEqual([...properties].sort());
  expect(Object.keys(PLAIN_PROFILE).sort()).toEqual([...properties].sort());
});

test('202 bodies: {mfa_required:true} for sign-in, {message} for register and forgot', () => {
  expect(source('Auth.Contracts/Responses/MfaEnrollResponse.cs')).toContain('record MfaRequiredResponse([property: JsonPropertyName("mfa_required")] bool MfaRequired)');
  const register = source('Auth.Contracts/Responses/RegisterResponse.cs');
  expect(recordProperties(register, 'RegisterResponse')).toEqual(['message']);
  expect(recordProperties(register, 'ForgotPasswordResponse')).toEqual(['message']);
});

test('request bodies the pages send match the request records', () => {
  const requests = source('Auth.Contracts/Requests/AuthRequests.cs');
  expect(recordProperties(requests, 'MfaVerifyRequest')).toEqual(['code', 'isRecoveryCode']);
  expect(recordProperties(requests, 'ResetPasswordRequest')).toEqual(['token', 'newPassword']);
  expect(recordProperties(requests, 'RegisterRequest')).toEqual(['email', 'password', 'displayName']);
});

test('problem titles and messages are the API\'s own', () => {
  const sessions = source('Auth.Api/Endpoints/SessionEndpoints.cs');
  const mfa = source('Auth.Api/Endpoints/MfaEndpoints.cs');
  const password = source('Auth.Api/Endpoints/PasswordEndpoints.cs');
  const account = source('Auth.Api/Endpoints/AccountEndpoints.cs');
  const limiter = source('Auth.Api/RateLimiting/AuthRateLimiting.cs');
  const validator = source('Auth.Services/Accounts/RegisterRequestValidator.cs');

  expect(sessions).toContain(`InvalidCredentialsTitle = "${API_TEXT.invalidCredentials}"`);
  expect(sessions).toContain(`title: "${API_TEXT.authenticationRequired}"`);
  expect(mfa).toContain(`InvalidFactorTitle = "${API_TEXT.invalidFactor}"`);
  expect(password).toContain(`title: "${API_TEXT.resetLinkInvalid}"`);
  expect(password).toContain(`ForgotAcceptedMessage = "${API_TEXT.forgotAccepted}"`);
  expect(account).toContain(`RegisterAcceptedMessage = "${API_TEXT.registerAccepted}"`);
  expect(account).toContain(`title: "${API_TEXT.registerInvalid}"`);
  expect(limiter).toContain(`Title = "${API_TEXT.tooManyRequests}"`);
  expect(limiter).toContain('HeaderNames.RetryAfter');
  expect(validator).toContain(`"${API_TEXT.passwordCommon}"`);
  expect(validator).toContain('errors["password"]');
});
