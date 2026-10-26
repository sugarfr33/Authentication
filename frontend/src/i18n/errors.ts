import { isApiError } from '@/api';
import { format, messages } from './messages';

/**
 * A user-facing sentence for a failed call. Uses our catalog, never raw server text, so auth failures stay
 * generic. Pages may override per status (e.g. a login 401 maps to messages.auth.loginFailed).
 */
export function describeError(error: unknown): string {
  if (!isApiError(error)) return messages.errors.unexpected;
  if (error.isNetworkError) return messages.errors.network;
  switch (error.status) {
    case 401:
      return messages.auth.sessionExpired;
    case 403:
      return messages.errors.forbidden;
    case 429:
      return error.retryAfterSeconds !== null
        ? format(messages.errors.rateLimited, { seconds: error.retryAfterSeconds })
        : messages.errors.rateLimitedNoTime;
    case 503:
      return messages.errors.unavailable;
    default:
      return messages.errors.unexpected;
  }
}
