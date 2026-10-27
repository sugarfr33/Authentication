# UI kit and design tokens (T23)

Hand-written Vue 3 components (`frontend/src/components/ui`) on CSS custom properties
(`frontend/src/styles/tokens.css`). No UI library and no icon package. Pages compose the kit and the
layout utilities in `base.css` (`.page`, `.stack`, `.cluster`, `.details`) and carry no styles of their own
(tested). Dev-only gallery: `npm run dev`, then `/dev/gallery` (all variants and states, a theme switch and
320/414 px preview frames). The production build fails if any gallery code reaches `dist/`.

## Tokens

Three tiers in one file:

1. **Primitive** (`--p-*`): raw values. Neutral (slate) and brand (indigo) ramps of 11 shades, the status
   shades in use, a type scale of about 1.25 (0.75 to 2.441 rem), a 4 px space unit, radii, shadows and
   motion. Only tokens.css may reference them (tested).
2. **Semantic**: `--color-text`, `--color-surface`, `--color-danger-on-bg`, `--space-4`, `--font-size-lg`,
   `--focus-ring`, `--target-comfortable` and so on. **Dark mode is redefined at this layer only:** under
   `@media (prefers-color-scheme: dark)` unless `<html data-theme="light">`, and again under
   `<html data-theme="dark">`. The two dark blocks must be identical, and dark must define every light
   colour token (both tested). `prefers-reduced-motion` sets every transition duration to 0, but
   `--duration-spin` only slows from 800 ms to 2.4 s per turn, so a loading indicator still reads as
   working instead of a frozen, broken-looking ring (tested).
3. **Component** (`--button-*`, `--input-*`, `--card-*` and so on): built from semantic tokens.

Component styles contain no hex/rgb/hsl colours and no pixel values except the `1px` visually-hidden
pattern (tested). Breakpoints (`--breakpoint-sm` 30em, md 48em, lg 64em) are documentation only, because
media queries cannot read variables. The kit uses `30em`, and BaseTable uses a container query so it stacks
by its own width.

### Measured contrast (tests/styles/tokens.spec.ts, WCAG formula)

34 pairs per theme are tested. A selection:

| Pair | Min | Light | Dark |
|---|---|---|---|
| `--color-text` on `--color-surface` | 4.5:1 | 17.85:1 | 17.06:1 |
| `--color-text-muted` on `--color-surface` | 4.5:1 | 7.58:1 | 12.02:1 |
| `--color-text-muted` on `--color-surface-sunken` | 4.5:1 | 6.92:1 | 13.59:1 |
| `--color-link` on `--color-surface` | 4.5:1 | 7.90:1 | 8.96:1 |
| `--color-on-primary` on `--color-primary` | 4.5:1 | 6.29:1 | 6.76:1 |
| `--color-on-danger` on `--color-danger` | 4.5:1 | 6.47:1 | 10.63:1 |
| `--color-danger-text` on `--color-surface` | 4.5:1 | 6.47:1 | 9.41:1 |
| `--color-danger-on-bg` on `--color-danger-bg` | 4.5:1 | 7.60:1 | 11.16:1 |
| `--color-success-on-bg` on `--color-success-bg` | 4.5:1 | 6.81:1 | 12.30:1 |
| `--color-warning-on-bg` on `--color-warning-bg` | 4.5:1 | 6.84:1 | 12.03:1 |
| `--color-info-on-bg` on `--color-info-bg` | 4.5:1 | 8.88:1 | 10.72:1 |
| `--color-border-strong` (input boundary) on `--color-surface` | 3:1 | 4.76:1 | 6.96:1 |
| `--color-focus-ring` on `--color-bg` | 3:1 | 6.01:1 | 10.12:1 |
| `--color-focus-ring` on `--color-surface` | 3:1 | 6.29:1 | 8.96:1 |

Disabled controls (`--color-text-disabled`) are exempt (WCAG 1.4.3) and are not tested.

## Components

Each entry gives the anatomy, the variants, the states, the token mapping, the accessibility behaviour and
the API. Every interactive element has a visible `:focus-visible` ring (`--focus-ring`, 2 px plus a 2 px
offset) and a target of at least 24 by 24 px (`--target-min`). Primary controls are 44 px high
(`--target-comfortable`).

### BaseButton
- **Anatomy:** a `<button>` holding an optional spinner or icon and a label.
- **Variants:** `primary`, `secondary`, `ghost`, `danger`, `link`. **Sizes:** `sm` 32 px, `md` 44 px, `lg` 52 px.
  `link` (T31) is an action that looks like the page's links (underlined, link colour, normal weight) but stays a
  `<button>` with the 44 px minimum height, e.g. "Use a recovery code instead".
- **Dark primary (T31):** the fill is `brand-400`, saturated enough that an enabled primary never reads as the
  disabled style (which uses the sunken surface and muted text).
  `block` gives full width.
- **States:** default, hover, active, focus-visible, disabled, loading.
- **A11y:** `type="button"` unless set, so it never submits by accident. While loading it stays focusable,
  sets `aria-busy="true"`, keeps its label, ignores activation and prevents a double submit. Other ARIA
  attributes such as `aria-pressed` fall through.
- **Announcing the result is the page's job.** Its spinner is decorative and `aria-busy` is not reliably
  read, so a page that sets `loading` must announce the outcome: a failure in a `BaseAlert` with
  `live="assertive"`, a success in a `BaseAlert` with `live="polite"` or a toast. For a wait that takes more
  than a moment, also show a `BaseSpinner` (it has `role="status"`) with a label that says what is loading.
- **API:** props `variant`, `size`, `type`, `disabled`, `loading`, `block`, `icon`. Emits `click`.
  Default slot. Exposes `focus()`.

### BaseInput
- A single `<input>` with `v-model`. `type` is text, email, password, search, tel or url.
- **`autocomplete` is a required prop** (WCAG 1.3.5, password managers). Also `invalid` (sets
  `aria-invalid`), `describedBy`, `required`, `disabled`, `readonly`, `inputmode`, `spellcheck`,
  `autocapitalize`, `maxlength`.
- **States:** default, hover, focus-visible, invalid (2 px danger border), disabled, readonly.
  Exposes `focus()`.

### FormField
- **Anatomy:** `<label for>`, an optional hint, the control (slot) and an error line.
- The label is always a real label, never a placeholder. A required field shows a visual `*`
  (aria-hidden), and the control carries native `required`.
- The slot receives `{ id, describedBy, invalid, required }`. `describedBy` lists the hint and the error ids.
- The error line is always rendered with `aria-live="polite"`, so a new error is announced. An icon
  accompanies the colour.
- `focusFirstInvalid(form)` moves focus to the first `[aria-invalid="true"]` control on a failed submit.

### FormErrorSummary (T31)
- Shown by a form when **two or more** fields are invalid (`useAuthForm` exposes `errorCount`; bind
  `ref="summaryEl"`). `useAuthForm` then moves focus to the summary instead of the first field; with one invalid
  field there is no summary and focus goes to that field.
- Props: `errors` (field name to message) and `labels` (field name to visible label, in form order). Each entry is
  "Label: message" as a link that moves focus to the control with that `name` in the same form.
- Not a live region: the field errors already announce themselves, and focus landing on the summary reads it once
  (`tabindex="-1"`, labelled by its title "Fix the highlighted fields and try again."). Danger alert colours plus an
  icon, so colour is not the only signal.

### PasswordInput
- BaseInput plus a show/hide toggle and an optional strength hint.
- `autocomplete` is required: `current-password` or `new-password`.
- The toggle is a real `<button>` with the constant name "Show password", plus `aria-pressed` and
  `aria-controls`. It is 44 px square.
- Paste is never blocked (WCAG 3.3.8: password managers work and there is no cognitive test). The input
  sets `spellcheck=false` and `autocapitalize=off`.
- `showStrength` shows a 4-bar meter (aria-hidden) and the text "Password strength: Fair", linked through
  `aria-describedby`. The hint is local and rough: the API's policy decides.

### BaseAlert
- **Tones:** `info`, `success`, `warning`, `danger`. Each has its own icon shape and a visually hidden prefix
  ("Error: ") so colour is never the only signal.
- **`live`:** `off` for static content, `polite` (`role="status"`) for async results and `assertive`
  (`role="alert"`) for failed submits.
- Optional `title` and `dismissible` (a close button emitting `dismiss`).

### BaseCard
- `<section>` (or `article`/`div`) labelled by its heading. Props `title` and `headingLevel` 1-4.
- Slots: `default`, `actions` (header right) and `footer` (actions, right-aligned).
- Padding shrinks below 30em.

### BaseTable
- **Typed** (`generic="T"`): `columns` (`key`, `label`, `align`), `rows`, `rowKey`, `caption` (required),
  `captionHidden`, `emptyText`. The `cell` scoped slot gets `{ row, column, value }`.
- Headers use `<th scope="col">`. Cells use **text interpolation only**, so IP addresses and user agents can
  never become markup (tested with `<img onerror>`). Dates are formatted with `Intl`.
- When narrower than 30em (container query), rows stack into labelled blocks, so there is no horizontal
  scroll at 320 px.
- The stacked layout sets `display: block`, which makes Chrome and Safari drop the implicit table semantics
  (WCAG 1.3.1). So every element carries its role explicitly: `table`, `rowgroup`, `row`, `columnheader`
  and `cell` (tested). The table is labelled by its caption (`aria-labelledby`). The header row stays in
  the accessibility tree, visually clipped, so cells keep their column header. The visual `data-label`
  prefix uses CSS alt text (`content: attr(data-label) / ""`), so it is not read twice.

### BaseDialog
- A native `<dialog>` with `showModal()`: focus trap, an inert page and Esc, all from the browser.
- `v-model:open`, plus `title`, `description` (`aria-labelledby` and `aria-describedby`), `confirmLabel`
  (it must restate action and object, e.g. "Sign out all sessions"), `cancelLabel`, `tone`
  (`default`/`danger`) and `confirmLoading`.
- **Focus:** on open it goes to Cancel for `danger` and to Confirm otherwise. On close it returns to the
  opener.
- Esc and backdrop clicks cancel. Both are blocked while `confirmLoading` is set.
- `persistent` ignores backdrop clicks (Esc and Cancel still work). Use it for any dialog that holds a
  form or other input, so a stray click loses nothing.

### BaseSpinner
- `role="status"` with visually hidden text (default "Loading"). `decorative` hides it inside a busy
  control.
- Sizes `sm`, `md`, `lg`. Under reduced motion the animation stops and the text still conveys the state.

### Toast (BaseToast and ToastRegion, with `useToast()`)
- `useToast().show(message, { tone, timeoutMs })`. Info and success dismiss themselves after **10 s**,
  paused while hovered or focused, which leaves time to read them and to reach Dismiss by keyboard.
  Warnings and errors are **always sticky**: a `timeoutMs` passed for them is ignored (tested).
- **Toasts carry no actions and no information the user needs later.** Anything to act on (retry, undo,
  a link) goes in a `BaseAlert` on the page. Toasts confirm what already happened ("You have signed out.").
- `ToastRegion` (mounted once in App.vue) keeps two live regions from page load: assertive
  (`aria-live="assertive"`, deliberately **not** `role="alert"`: an empty alert on every page is announced on load
  by some screen readers, T31) for warning and danger, polite (`role="status"`) for info and success.
- Each toast has a visually hidden tone prefix and a "Dismiss notification" button.

### Icons
`IconSprite.vue` is one inline SVG sprite we author (info, success, warning, danger, close, eye, eye-off),
mounted once. `BaseIcon` uses it and is decorative (`aria-hidden`) unless given a `label`.

## API layer notes (T23 audit)

- **L1 (late 401s):** single flight covers one recovery. A 401 whose response arrives after that
  recovery has settled starts a new one, which first probes `GET /auth/me`. The session is already
  fresh, so it answers 200 and nothing is rotated again (tested: one refresh, two probes).
- **L2 (hung recovery):** each recovery request (probe, refresh) is aborted after `recoveryTimeoutMs`
  (default 15 s). The recovery then ends as `unavailable`: the original error is returned, the user is
  not signed out and the Web Lock is released for the next recovery (tested).
- **L3 (replay):** after a 401 or a stale-antiforgery 400 the request is sent once more with the same body.
  This is safe because both answers come from middleware (authentication, BrowserProtectionMiddleware)
  before any endpoint runs, so the first attempt did nothing. Any future endpoint that can answer 400/401
  after doing work must not use this retry path, or must carry an idempotency key.
- **L4 (API origin):** `VITE_API_BASE_URL` is validated at start-up (`src/api/config.ts`): empty (same
  origin, recommended), or an https origin with no path, query or credentials; http is allowed for
  localhost in development only (tested). Cookies are SameSite=Strict, so a cross-site API would get no
  cookies anyway; a different origin on the same site must be in the API's CORS allowlist.
- **CSP:** the host that serves the SPA must send a Content-Security-Policy header. A meta tag is not used
  because the Vite dev server needs inline scripts. Recommended for production:
  `default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'
  <api origin if different>; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'`.

## UX writing

All text lives in `src/i18n/messages.ts`, with `{name}` placeholders and no string concatenation.
Sentence case; buttons start with a verb. Auth texts stay generic and use the same words as the API (for
example "Invalid email or password.", and the register/forgot 202 messages), so no text reveals whether an
account exists. `describeError()` maps an `ApiError` to catalog text and never shows raw server text.
