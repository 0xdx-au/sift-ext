// Explicit user-action cleanup only; never intercept navigation or persist page text.
const TRACKING = new Set([
  'utm_source','utm_medium','utm_campaign','utm_term','utm_content',
  'utm_id','utm_source_platform','utm_creative_format','utm_marketing_tactic',
  'fbclid','gclid','dclid','gbraid','wbraid','msclkid','mc_eid'
]);
const SENSITIVE = /^(?:code|state|nonce|session(?:_id)?|auth(?:orization)?|token|access_token|id_token|refresh_token|client_secret|signature|sig|expires|expiry|policy|key|redirect(?:_uri)?|return(?:_url)?|callback|continue|next|destination|payment|checkout|cart|order|invite|invitation|share|x-amz-.*|x-goog-.*)$/i;
const SENSITIVE_PATH = /(?:^|\/)(?:login|signin|sign-in|oauth|authorize|callback|checkout|payment|download|signed|invite|share)(?:\/|$)/i;
function decodeKey(raw) {
  try { return decodeURIComponent(raw.replace(/\+/g, ' ')).toLowerCase(); }
  catch { return null; }
}
export function cleanTrackingUrl(input) {
  if (typeof input !== 'string' || input.length > 8192)
    return { changed: false, value: input, reason: 'invalid-input' };
  let parsed;
  try { parsed = new URL(input); }
  catch { return { changed: false, value: input, reason: 'invalid-url' }; }
  if (!['http:', 'https:'].includes(parsed.protocol) || parsed.username || parsed.password)
    return { changed: false, value: input, reason: 'unsupported-url' };
  if (SENSITIVE_PATH.test(parsed.pathname))
    return { changed: false, value: input, reason: 'sensitive-path' };
  // Escaped path segments can conceal authentication or signed-link routes.
  // Reject them instead of guessing how the application decodes its path.
  if (parsed.pathname.includes('%'))
    return { changed: false, value: input, reason: 'ambiguous-path' };
  const question = input.indexOf('?');
  const firstFragment = input.indexOf('#');
  if (question < 0 || (firstFragment >= 0 && question > firstFragment)) return { changed: false, value: input, reason: 'no-query' };
  const fragment = input.indexOf('#', question);
  const raw = input.slice(question + 1, fragment < 0 ? undefined : fragment);
  const segments = raw.split('&');
  const keys = segments.map((segment) => decodeKey(segment.split('=', 1)[0]));
  if (keys.includes(null) || segments.some((segment) => { try { decodeURIComponent(segment.replace(/\\+/g, ' ')); return false; } catch { return true; } }) || keys.some((key) => SENSITIVE.test(key)))
    return { changed: false, value: input, reason: 'sensitive-or-ambiguous-query' };
  const filtered = segments.filter((_, i) => !TRACKING.has(keys[i]));
  if (filtered.length === segments.length)
    return { changed: false, value: input, reason: 'no-known-tracking-parameters' };
  const suffix = fragment < 0 ? '' : input.slice(fragment);
  const value = input.slice(0, question) + (filtered.length ? '?' + filtered.join('&') : '') + suffix;
  return { changed: true, value, removed: segments.length - filtered.length };
}
