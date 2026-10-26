/**
 * Validates VITE_API_BASE_URL (audit L4). Empty means same origin, the recommended deployment: the auth
 * cookies are SameSite=Strict, so a cross-site API would not receive them anyway. A configured origin must be
 * an https origin with nothing else in it (no path, query, credentials), except a loopback http origin in dev.
 */
export function resolveApiBaseUrl(raw: string | undefined, isProduction: boolean): string {
  const value = (raw ?? '').trim();
  if (value === '') return '';

  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error(`VITE_API_BASE_URL is not a valid URL: ${value}`);
  }
  const loopback = url.hostname === 'localhost' || url.hostname === '127.0.0.1' || url.hostname === '[::1]';
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && loopback && !isProduction)) {
    throw new Error('VITE_API_BASE_URL must use https (http is allowed only for localhost in development).');
  }
  if (url.username || url.password || url.search || url.hash || (url.pathname !== '/' && url.pathname !== '')) {
    throw new Error('VITE_API_BASE_URL must be an origin only, e.g. https://auth.example.com');
  }
  return url.origin;
}
