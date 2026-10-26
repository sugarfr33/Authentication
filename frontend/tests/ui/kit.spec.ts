// UI kit behaviour that WCAG 2.1 AA (plus the 2.2 items in roles.md section 6) depends on, checked in the DOM.
import { afterEach, describe, expect, it, vi } from 'vitest';
import { h, nextTick } from 'vue';
import {
  BaseAlert,
  BaseButton,
  BaseDialog,
  BaseInput,
  BaseTable,
  FormField,
  PasswordInput,
  ToastRegion,
  estimatePasswordStrength,
  focusFirstInvalid,
} from '@/components/ui';
import { useToast } from '@/composables/useToast';
import { flush, mount, type Mounted } from '../helpers/mount';

const mounted: Mounted<Record<string, unknown>>[] = [];
function track<P extends Record<string, unknown>>(m: Mounted<P>): Mounted<P> {
  mounted.push(m as unknown as Mounted<Record<string, unknown>>);
  return m;
}

afterEach(() => {
  while (mounted.length > 0) mounted.pop()?.unmount();
  useToast().clearAll();
  vi.useRealTimers();
});

describe('BaseButton', () => {
  it('defaults to type="button" so it never submits a form by accident', () => {
    const { root } = track(mount(BaseButton, {}, { default: () => 'Save' }));
    expect(root.querySelector('button')?.getAttribute('type')).toBe('button');
  });

  it('while loading: stays focusable, says busy, keeps its label and ignores clicks', async () => {
    const onClick = vi.fn();
    const { root } = track(mount(BaseButton, { loading: true, onClick }, { default: () => 'Save changes' }));
    const button = root.querySelector('button') as HTMLButtonElement;
    expect(button.disabled).toBe(false);
    expect(button.getAttribute('aria-busy')).toBe('true');
    expect(button.textContent).toContain('Save changes');
    button.click();
    await flush();
    expect(onClick).not.toHaveBeenCalled();
  });

  it('emits click when idle', async () => {
    const onClick = vi.fn();
    const { root } = track(mount(BaseButton, { onClick }, { default: () => 'Go' }));
    root.querySelector('button')?.click();
    await flush();
    expect(onClick).toHaveBeenCalledTimes(1);
  });
});

describe('FormField + BaseInput', () => {
  function field(props: Record<string, unknown>) {
    return track(
      mount<Record<string, unknown>>(FormField, { label: 'Email', ...props }, {
        default: (slot: { id: string; describedBy: string | undefined; invalid: boolean; required: boolean }) =>
          h(BaseInput, {
            id: slot.id,
            type: 'email',
            autocomplete: 'email',
            describedBy: slot.describedBy,
            invalid: slot.invalid,
            required: slot.required,
          }),
      }),
    );
  }

  it('labels the control with a real <label for> (not a placeholder)', () => {
    const { root } = field({});
    const input = root.querySelector('input') as HTMLInputElement;
    const label = root.querySelector('label') as HTMLLabelElement;
    expect(label.htmlFor).toBe(input.id);
    expect(label.textContent).toContain('Email');
    expect(input.getAttribute('placeholder')).toBeNull();
    expect(input.getAttribute('autocomplete')).toBe('email');
  });

  it('links hint and error with aria-describedby, sets aria-invalid, and announces the error politely', async () => {
    const m = field({ hint: 'We only use it to sign you in.' });
    const input = m.root.querySelector('input') as HTMLInputElement;
    expect(input.getAttribute('aria-invalid')).toBeNull();
    expect(input.getAttribute('aria-describedby')).toBe(`${input.id}-hint`);

    m.props.error = 'Enter an email address like name@example.com.';
    await flush();

    expect(input.getAttribute('aria-invalid')).toBe('true');
    const describedBy = input.getAttribute('aria-describedby')?.split(' ') ?? [];
    expect(describedBy).toEqual([`${input.id}-hint`, `${input.id}-error`]);
    const error = m.root.querySelector(`#${input.id}-error`) as HTMLElement;
    expect(error.getAttribute('aria-live')).toBe('polite');
    expect(error.textContent).toContain('Enter an email address');
    // an icon accompanies the colour (never colour alone)
    expect(error.querySelector('svg')).not.toBeNull();
  });

  it('marks required with the native attribute', () => {
    const { root } = field({ required: true });
    expect((root.querySelector('input') as HTMLInputElement).required).toBe(true);
  });

  it('focusFirstInvalid moves focus to the first invalid control', async () => {
    const m = field({ error: 'Required.' });
    await flush();
    expect(focusFirstInvalid(m.root)).toBe(true);
    expect(document.activeElement).toBe(m.root.querySelector('input'));
  });
});

describe('PasswordInput', () => {
  it('requires an autocomplete token and passes it through (password managers, WCAG 1.3.5)', () => {
    const { root } = track(mount(PasswordInput, { autocomplete: 'current-password', id: 'pw' }));
    const input = root.querySelector('input') as HTMLInputElement;
    expect(input.type).toBe('password');
    expect(input.getAttribute('autocomplete')).toBe('current-password');
  });

  it('show/hide is a real button with a name, aria-pressed and aria-controls', async () => {
    const { root } = track(mount(PasswordInput, { autocomplete: 'new-password', id: 'pw' }));
    const toggle = root.querySelector('button') as HTMLButtonElement;
    const input = root.querySelector('input') as HTMLInputElement;
    expect(toggle.type).toBe('button');
    expect(toggle.textContent?.trim()).toBe('Show password');
    expect(toggle.getAttribute('aria-controls')).toBe('pw');
    expect(toggle.getAttribute('aria-pressed')).toBe('false');

    toggle.click();
    await flush();
    expect(toggle.getAttribute('aria-pressed')).toBe('true');
    expect(input.type).toBe('text');
  });

  it('does not block paste', () => {
    const { root } = track(mount(PasswordInput, { autocomplete: 'current-password' }));
    const event = new Event('paste', { cancelable: true, bubbles: true });
    root.querySelector('input')?.dispatchEvent(event);
    expect(event.defaultPrevented).toBe(false);
  });

  it('shows a text strength hint linked to the input when asked', async () => {
    const m = track(mount(PasswordInput, { autocomplete: 'new-password', id: 'pw', showStrength: true, modelValue: '' }));
    expect(m.root.querySelector('#pw-strength')).toBeNull();
    m.props.modelValue = 'correct horse battery staple';
    await flush();
    const hint = m.root.querySelector('#pw-strength') as HTMLElement;
    expect(hint.textContent).toMatch(/^Password strength: /);
    expect(m.root.querySelector('input')?.getAttribute('aria-describedby')).toContain('pw-strength');
  });

  it('strength estimate grows with length', () => {
    expect(estimatePasswordStrength('')).toBe(0);
    expect(estimatePasswordStrength('aaaaaaaaaaaa')).toBe(0);
    expect(estimatePasswordStrength('abcdefgh')).toBe(1);
    expect(estimatePasswordStrength('abcdefghijkl')).toBe(2);
    expect(estimatePasswordStrength('correct horse battery staple')).toBe(4);
  });
});

describe('BaseAlert', () => {
  it('assertive alerts use role="alert", polite ones role="status", static ones neither', () => {
    const a = track(mount(BaseAlert, { tone: 'danger', live: 'assertive' }, { default: () => 'Failed' }));
    const p = track(mount(BaseAlert, { tone: 'success', live: 'polite' }, { default: () => 'Saved' }));
    const s = track(mount(BaseAlert, { tone: 'info' }, { default: () => 'Note' }));
    expect(a.root.firstElementChild?.getAttribute('role')).toBe('alert');
    expect(p.root.firstElementChild?.getAttribute('role')).toBe('status');
    expect(s.root.firstElementChild?.getAttribute('role')).toBeNull();
  });

  it('names its tone in text, so colour is not the only signal', () => {
    const { root } = track(mount(BaseAlert, { tone: 'danger', title: 'Could not save' }, { default: () => 'x' }));
    expect(root.textContent).toContain('Error:');
  });
});

describe('BaseTable', () => {
  it('renders hostile strings (IP/user agent) as text, never as markup', () => {
    const rows = [{ id: '1', ua: '<img src=x onerror=alert(1)>', ip: '203.0.113.7' }];
    const { root } = track(
      mount(BaseTable, {
        caption: 'Active sessions',
        columns: [
          { key: 'ua', label: 'Device' },
          { key: 'ip', label: 'IP address' },
        ],
        rows,
        rowKey: (row: { id: string }) => row.id,
      }),
    );
    expect(root.querySelector('img')).toBeNull();
    expect(root.querySelector('td')?.textContent).toBe('<img src=x onerror=alert(1)>');
    expect(root.querySelector('caption')?.textContent).toBe('Active sessions');
    expect([...root.querySelectorAll('th')].every((th) => th.getAttribute('scope') === 'col')).toBe(true);
  });

  it('shows the empty text when there are no rows', () => {
    const { root } = track(
      mount(BaseTable, { caption: 'Sessions', columns: [{ key: 'a', label: 'A' }], rows: [], rowKey: () => 'x', emptyText: 'No active sessions.' }),
    );
    expect(root.querySelector('td')?.textContent?.trim()).toBe('No active sessions.');
  });
});

describe('BaseDialog', () => {
  function openDialog(props: Record<string, unknown>) {
    const opener = document.createElement('button');
    opener.textContent = 'Open';
    document.body.appendChild(opener);
    opener.focus();
    const m = track(mount(BaseDialog, { title: 'Sign out all other sessions?', confirmLabel: 'Sign out all sessions', open: false, ...props }));
    return { m, opener };
  }

  it('is labelled by its title and described by its description', async () => {
    const { m } = openDialog({ description: 'Every other browser will be signed out.' });
    m.props.open = true;
    await flush();
    const dialog = m.root.querySelector('dialog') as HTMLDialogElement;
    expect(dialog.hasAttribute('open')).toBe(true);
    expect(document.getElementById(dialog.getAttribute('aria-labelledby') ?? '')?.textContent).toBe('Sign out all other sessions?');
    expect(document.getElementById(dialog.getAttribute('aria-describedby') ?? '')?.textContent).toContain('Every other browser');
  });

  it('danger dialogs focus Cancel first; Esc closes and returns focus to the opener', async () => {
    const onCancel = vi.fn();
    const { m, opener } = openDialog({ tone: 'danger', onCancel, 'onUpdate:open': (v: boolean) => (m.props.open = v) });
    m.props.open = true;
    await flush();
    await nextTick();
    const dialog = m.root.querySelector('dialog') as HTMLDialogElement;
    expect(document.activeElement?.textContent?.trim()).toBe('Cancel');

    const esc = new Event('cancel', { cancelable: true });
    dialog.dispatchEvent(esc);
    await flush();

    expect(esc.defaultPrevented).toBe(true);
    expect(onCancel).toHaveBeenCalledTimes(1);
    expect(dialog.hasAttribute('open')).toBe(false);
    expect(document.activeElement).toBe(opener);
    opener.remove();
  });

  it('the confirm button restates the action and emits confirm', async () => {
    const onConfirm = vi.fn();
    const { m, opener } = openDialog({ onConfirm });
    m.props.open = true;
    await flush();
    const confirm = [...m.root.querySelectorAll('button')].find((b) => b.textContent?.includes('Sign out all sessions'));
    confirm?.click();
    await flush();
    expect(onConfirm).toHaveBeenCalledTimes(1);
    opener.remove();
  });
});

describe('Toasts', () => {
  it('errors go to the assertive region, info to the polite one; both regions exist before any toast', async () => {
    const { root } = track(mount(ToastRegion));
    const alertRegion = root.querySelector('[role="alert"]') as HTMLElement;
    const statusRegion = root.querySelector('[role="status"]') as HTMLElement;
    expect(alertRegion).not.toBeNull();
    expect(statusRegion).not.toBeNull();

    useToast().show('We could not reach the server.', { tone: 'danger' });
    useToast().show('You have signed out.', { tone: 'success' });
    await flush();

    expect(alertRegion.textContent).toContain('We could not reach the server.');
    expect(statusRegion.textContent).toContain('You have signed out.');
  });

  it('info toasts dismiss themselves; error toasts stay until dismissed', async () => {
    vi.useFakeTimers();
    const { root } = track(mount(ToastRegion));
    useToast().show('Saved.', { tone: 'success' });
    useToast().show('Failed.', { tone: 'danger' });
    await flush();
    vi.advanceTimersByTime(10_000);
    await flush();
    expect(root.textContent).not.toContain('Saved.');
    expect(root.textContent).toContain('Failed.');

    const dismiss = [...root.querySelectorAll('button')].find((b) => b.textContent?.includes('Dismiss notification'));
    dismiss?.click();
    await flush();
    expect(root.textContent).not.toContain('Failed.');
  });
});
