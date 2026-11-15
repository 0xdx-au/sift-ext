import { acquireVerifiedRelease } from './fetch.mjs';
import { verifyRelease } from './verify.mjs';
import { compileForChromium } from './compile.mjs';
import { installDynamicRules } from './install.mjs';

export const FEED_STATE_KEY = 'siftVerifiedFeedState';
const MAX_CACHED_BYTES = 6_000_000; // Chrome storage.local has a separate quota; reserve overhead.
const HEX = /^[0-9a-f]{64}$/;
const ENCODER = new TextEncoder();
const DECODER = new TextDecoder('utf-8', { fatal: true });
const empty = () => ({ version: 2, accepted: null, pending: false });

function record(value) {
  return value && typeof value === 'object' && !Array.isArray(value);
}
function metadata(value) {
  return record(value) && Number.isSafeInteger(value.sequence) && value.sequence > 0 &&
    typeof value.sha256 === 'string' && HEX.test(value.sha256) &&
    typeof value.keyId === 'string' && /^[a-z0-9-]{4,48}$/.test(value.keyId) &&
    typeof value.expiresAt === 'string' && Number.isFinite(Date.parse(value.expiresAt));
}
function checkedState(state) {
  if (state === undefined) return empty();
  if (!record(state) || state.version !== 2 || typeof state.pending !== 'boolean' ||
      !Object.keys(state).every(k => ['version', 'accepted', 'pending'].includes(k)) ||
      (state.accepted !== null && (!record(state.accepted) ||
        !metadata(state.accepted.meta) ||
        typeof state.accepted.payload !== 'string' ||
        typeof state.accepted.proof !== 'string' ||
        ENCODER.encode(state.accepted.payload).length > MAX_CACHED_BYTES ||
        state.accepted.proof.length > 2048))) {
    throw new Error('SIFT: invalid signed release journal');
  }
  return state;
}
export async function readVerifiedFeedState(local) {
  const { [FEED_STATE_KEY]: value } = await local.get(FEED_STATE_KEY);
  return checkedState(value);
}
function exactBytes(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length < 100 || bytes.length > MAX_CACHED_BYTES)
    throw new Error('SIFT: signed release too large for durable authenticated cache');
  let text;
  try { text = DECODER.decode(bytes); } catch { throw new Error('SIFT: invalid signed UTF-8 bytes'); }
  const roundtrip = ENCODER.encode(text);
  if (roundtrip.length !== bytes.length || roundtrip.some((v, i) => v !== bytes[i]))
    throw new Error('SIFT: signed bytes cannot be retained losslessly');
  return text;
}
async function authenticate(accepted, pin, now) {
  if (!pin?.keyId || !pin.publicKeyBase64)
    throw new Error('SIFT: approved public signing identity missing');
  if (!record(accepted) || !metadata(accepted.meta) || accepted.meta.keyId !== pin.keyId ||
      typeof accepted.payload !== 'string' || typeof accepted.proof !== 'string')
    throw new Error('SIFT: invalid cached signed release identity');
  const bytes = ENCODER.encode(accepted.payload);
  if (bytes.length < 100 || bytes.length > MAX_CACHED_BYTES)
    throw new Error('SIFT: cached signed payload size invalid');
  const result = await verifyRelease(bytes, accepted.proof, pin,
    { sequence: accepted.meta.sequence, sha256: accepted.meta.sha256 }, now);
  if (result.sha256 !== accepted.meta.sha256 ||
      result.release.sequence !== accepted.meta.sequence ||
      result.release.keyId !== accepted.meta.keyId ||
      result.release.expiresAt !== accepted.meta.expiresAt)
    throw new Error('SIFT: signed cache metadata inconsistent');
  return result;
}
async function acceptedRules(state, pin, now, maxRules) {
  if (!state.accepted) return [];
  const { release } = await authenticate(state.accepted, pin, now);
  const { rules, stats } = compileForChromium(release.policy, { limit: maxRules });
  if (!rules.length || stats.truncated)
    throw new Error('SIFT: signed cache cannot be enforced without omissions');
  return rules;
}
async function quarantine(dnr) {
  // Explicitly keep the bundled starter rules. Never restore unverified dynamic rules.
  await installDynamicRules(dnr, []);
}
export async function recoverPendingFeed({ dnr, local }, {
  pin, now = Date.now(), maxRules = 20000
} = {}) {
  let state;
  try { state = await readVerifiedFeedState(local); }
  catch (error) {
    await quarantine(dnr);
    return { status: 'quarantined', reason: 'invalid-journal' };
  }
  const settings = await local.get('enabled');
  if (!pin?.publicKeyBase64 || !pin.keyId) {
    await quarantine(dnr);
    return { status: 'unprovisioned', recovered: false };
  }
  try {
    const verifiedRules = await acceptedRules(state, pin, now, maxRules);
    const desired = settings.enabled === false ? [] : verifiedRules;
    await installDynamicRules(dnr, desired);
    if (state.pending) await local.set({ [FEED_STATE_KEY]: { ...state, pending: false } });
    return { status: 'verified', recovered: state.pending, installed: desired.length,
      sequence: state.accepted?.meta.sequence ?? 0 };
  } catch {
    await quarantine(dnr);
    return { status: 'quarantined', reason: 'invalid-or-expired-signed-cache' };
  }
}
export async function applyVerifiedFeed({ dnr, local }, {
  pin, now = Date.now(), maxRules = 20000, acquire = acquireVerifiedRelease
} = {}) {
  if (!pin?.keyId || !pin.publicKeyBase64)
    throw new Error('SIFT: production signing identity not provisioned');
  if ((await local.get('enabled')).enabled === false)
    return { status: 'paused', installed: 0 };
  const before = await readVerifiedFeedState(local);
  if (before.pending) throw new Error('SIFT: interrupted update requires signed recovery');
  // A signed cache MUST be checked before using its sequence as a rollback anchor.
  if (before.accepted) await authenticate(before.accepted, pin, now);
  const previous = before.accepted ?
    { sequence: before.accepted.meta.sequence, sha256: before.accepted.meta.sha256 } : {};
  const acquired = await acquire(pin, previous, { now });
  // Acquisition summaries are not trusted; independently verify the exact bytes again.
  if (!acquired || !(acquired.rawBytes instanceof Uint8Array) ||
      typeof acquired.signatureText !== 'string')
    throw new Error('SIFT: signed evidence absent from feed acquisition');
  const signed = await verifyRelease(acquired.rawBytes, acquired.signatureText, pin, previous, now);
  const { rules, stats } = compileForChromium(signed.release.policy, { limit: maxRules });
  if (!rules.length || stats.truncated)
    throw new Error('SIFT: signed feed exceeds approved DNR rule budget');
  const accepted = {
    meta: {
      keyId: signed.release.keyId, sequence: signed.release.sequence,
      sha256: signed.sha256, expiresAt: signed.release.expiresAt
    },
    payload: exactBytes(acquired.rawBytes),
    proof: acquired.signatureText
  };
  const pendingState = { ...before, pending: true };
  await local.set({ [FEED_STATE_KEY]: pendingState });
  try {
    await installDynamicRules(dnr, rules);
    if ((await local.get('enabled')).enabled === false)
      throw new Error('SIFT: update interrupted by pause');
    await local.set({ [FEED_STATE_KEY]: { version: 2, accepted, pending: false } });
    return { status: 'installed', sequence: accepted.meta.sequence, installed: rules.length,
      sha256: accepted.meta.sha256, omittedDomains: 0 };
  } catch (error) {
    try {
      const restoredRules = await acceptedRules(before, pin, now, maxRules);
      const settings = await local.get('enabled');
      await installDynamicRules(dnr, settings.enabled === false ? [] : restoredRules);
      await local.set({ [FEED_STATE_KEY]: before });
    } catch {
      await quarantine(dnr);
      throw new Error('SIFT: update failed; all SIFT dynamic rules quarantined pending review');
    }
    throw error;
  }
}
