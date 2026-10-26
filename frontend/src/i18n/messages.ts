// One message catalog (i18n-ready): sentence case, verbs on buttons, no string concatenation in components.
// Auth failure texts stay generic and match the API's ProblemDetails; never hint whether an account exists.

export const messages = {
  app: {
    name: 'Central Auth',
    pageTitle: '{page} · Central Auth',
    skipToContent: 'Skip to main content',
    primaryNav: 'Main',
  },
  common: {
    loading: 'Loading',
    close: 'Close',
    dismiss: 'Dismiss notification',
    cancel: 'Cancel',
    required: 'required',
    notifications: 'Notifications',
    urgentNotifications: 'Urgent notifications',
  },
  /** Spoken before an alert or toast so its kind is never conveyed by colour alone. */
  tone: {
    info: 'Information',
    success: 'Success',
    warning: 'Warning',
    danger: 'Error',
  },
  password: {
    show: 'Show password',
    strengthLabel: 'Password strength: {level}',
    strength: ['Very weak', 'Weak', 'Fair', 'Good', 'Strong'],
    hint: 'Use at least 12 characters. A longer passphrase is stronger than symbols.',
  },
  auth: {
    loginFailed: 'Invalid email or password.',
    sessionExpired: 'Your session has ended. Sign in again to continue.',
    // Same wording as the API's 202 messages (AccountEndpoints, PasswordEndpoints).
    registerAccepted: 'Check your inbox: we sent you an email to finish signing up.',
    forgotAccepted: 'If an account can reset its password with this address, we sent it an email with a link.',
    mfaInvalid: 'Invalid or expired verification.',
    verifyLinkInvalid: 'The verification link is invalid or has expired.',
    resetLinkInvalid: 'The reset link is invalid or has expired.',
  },
  errors: {
    network: 'We could not reach the server. Check your connection and try again.',
    rateLimited: 'Too many attempts. Wait {seconds} seconds and try again.',
    rateLimitedNoTime: 'Too many attempts. Wait a moment and try again.',
    unavailable: 'The service is busy. Try again in a moment.',
    unexpected: 'Something went wrong on our side. Try again.',
    forbidden: 'This request was blocked. Reload the page and try again.',
  },
  home: {
    title: 'Your account',
    signedInAs: 'Signed in as {name}',
    email: 'Email',
    roles: 'Roles',
    noRoles: 'No roles',
    signedOut: 'You are not signed in.',
    checking: 'Checking your session',
    loadFailed: 'We could not check your session.',
    retry: 'Try again',
    signOut: 'Sign out',
    signedOutToast: 'You have signed out.',
  },
  notFound: {
    title: 'Page not found',
    body: 'The page you asked for does not exist or has moved.',
    home: 'Go to your account',
  },
} as const;

/** Replaces {name} placeholders. Missing values are left visible so they are caught in review. */
export function format(template: string, values: Readonly<Record<string, string | number>> = {}): string {
  return template.replace(/\{(\w+)\}/g, (match, key: string) => (key in values ? String(values[key]) : match));
}
