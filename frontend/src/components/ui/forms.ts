/** On a failed submit, move focus to the first invalid control so its error is read out (WCAG 3.3.1). */
export function focusFirstInvalid(root: ParentNode): boolean {
  const target = root.querySelector<HTMLElement>('[aria-invalid="true"]');
  if (!target) return false;
  target.focus();
  return true;
}
