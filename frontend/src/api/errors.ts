/** A failed API call. Built from the API's ProblemDetails; carries no request or cookie data. */
export class ApiError extends Error {
  /** HTTP status, or 0 when the request never got an answer (offline, CORS, aborted). */
  readonly status: number;
  /** ProblemDetails title (the API keeps these generic for auth failures). */
  readonly title: string | null;
  readonly detail: string | null;
  /** ValidationProblemDetails errors: field name to messages. */
  readonly fieldErrors: Readonly<Record<string, readonly string[]>>;
  /** Seconds from Retry-After on 429/503, when present. */
  readonly retryAfterSeconds: number | null;
  readonly traceId: string | null;

  constructor(init: {
    status: number;
    title?: string | null;
    detail?: string | null;
    fieldErrors?: Record<string, readonly string[]>;
    retryAfterSeconds?: number | null;
    traceId?: string | null;
  }) {
    super(init.title ?? `Request failed with status ${init.status}`);
    this.name = 'ApiError';
    this.status = init.status;
    this.title = init.title ?? null;
    this.detail = init.detail ?? null;
    this.fieldErrors = init.fieldErrors ?? {};
    this.retryAfterSeconds = init.retryAfterSeconds ?? null;
    this.traceId = init.traceId ?? null;
  }

  get isNetworkError(): boolean {
    return this.status === 0;
  }

  get isUnauthorized(): boolean {
    return this.status === 401;
  }
}

export function isApiError(value: unknown): value is ApiError {
  return value instanceof ApiError;
}

/** Title the API uses when X-XSRF-TOKEN is missing or no longer fits (BrowserProtectionMiddleware). */
export const ANTIFORGERY_FAILURE_TITLE = 'Missing or invalid antiforgery token.';

interface ProblemBody {
  title?: unknown;
  detail?: unknown;
  errors?: unknown;
  traceId?: unknown;
}

export interface ParsedProblem {
  title: string | null;
  detail: string | null;
  fieldErrors: Record<string, readonly string[]>;
  traceId: string | null;
}

/** Reads a ProblemDetails body defensively; anything unexpected becomes nulls. */
export function parseProblem(body: unknown): ParsedProblem {
  const problem: ProblemBody = typeof body === 'object' && body !== null ? (body as ProblemBody) : {};
  const fieldErrors: Record<string, readonly string[]> = {};
  if (typeof problem.errors === 'object' && problem.errors !== null) {
    for (const [field, messages] of Object.entries(problem.errors as Record<string, unknown>)) {
      if (Array.isArray(messages)) {
        fieldErrors[field] = messages.filter((m): m is string => typeof m === 'string');
      }
    }
  }
  return {
    title: typeof problem.title === 'string' ? problem.title : null,
    detail: typeof problem.detail === 'string' ? problem.detail : null,
    fieldErrors,
    traceId: typeof problem.traceId === 'string' ? problem.traceId : null,
  };
}

export function parseRetryAfter(header: string | null): number | null {
  if (header === null) return null;
  const seconds = Number.parseInt(header, 10);
  return Number.isFinite(seconds) && seconds >= 0 ? seconds : null;
}
