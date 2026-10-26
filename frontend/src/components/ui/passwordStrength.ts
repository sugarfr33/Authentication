/**
 * A rough 0-4 strength hint shown while typing. Guidance only: the API's password policy is authoritative.
 * No dictionary (no extra package); length dominates, character variety adds a little.
 */
export type StrengthLevel = 0 | 1 | 2 | 3 | 4;

export function estimatePasswordStrength(password: string): StrengthLevel {
  const length = [...password].length;
  if (length < 8) return 0;
  if (new Set(password).size <= 2) return 0;

  let score = 1;
  if (length >= 12) score++;
  if (length >= 16) score++;

  const classes = [/[a-z]/, /[A-Z]/, /\d/, /[^A-Za-z0-9]/].filter((pattern) => pattern.test(password)).length;
  if (classes >= 3 || length >= 20) score++;

  return Math.min(score, 4) as StrengthLevel;
}
