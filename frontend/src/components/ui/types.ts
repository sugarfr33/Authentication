/** link (T31): an action styled as an inline link, for secondary actions next to links (still a <button>). */
export type ButtonVariant = 'primary' | 'secondary' | 'ghost' | 'danger' | 'link';
export type ButtonSize = 'sm' | 'md' | 'lg';
export type Tone = 'info' | 'success' | 'warning' | 'danger';

export interface TableColumn {
  readonly key: string;
  readonly label: string;
  readonly align?: 'start' | 'end';
}

/** Autocomplete tokens the kit accepts on text inputs (WCAG 1.3.5, password managers). */
export type TextAutocomplete =
  | 'off'
  | 'name'
  | 'nickname'
  | 'email'
  | 'username'
  | 'one-time-code'
  | 'tel'
  | 'url';

export type PasswordAutocomplete = 'current-password' | 'new-password';
