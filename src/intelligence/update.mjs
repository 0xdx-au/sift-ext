import { acquireVerifiedRelease } from './fetch.mjs';
import { compileForChromium } from './compile.mjs';
import { installDynamicRules } from './install.mjs';

export const FEED_STATE_KEY = 'siftVerifiedFeedState';
const MAX_RULES = 28000;
const HEX = /^[0-9a-f]{64}$/;
const empty = () => ({ version: 1, active: null, rules: [], pending: false });

function checkedRules(rules) {
  if (!Array.isArray(rules) || rules.length > MAX_RULES ||
      rules.some(rule => !Number.isInteger(rule?.id) || rule.id < 1000 || rule.id >= 29000) ||
      new Set(rules.map(rule => rule.id)).size !== rules.length) {
    throw new Error('SIFT: invalid local rule state');
  }
  return rules;
}
function checkedState(value) {
  if (value === undefined) return empty();
  if (!value || value.version !== 1 || typeof value.pending !== 'boolean' ||
      !Array.isArray(value.rules)) throw new Error('SIFT: malformed release state');
  checkedRules(value.rules);
  const a = value.active;
  if (a !== null && (!a || !Number.isSafeInteger(a.sequence) || a.sequence < 1 ||
      typeof a.sha256 !== 'string' || !HEX.test(a.sha256) ||
      typeof a.keyId !== 'string' || !/^[a-z0-9-]{4,48}$/.test(a.keyId) ||
      typeof a.expiresAt !== 'string' || !Number.isFinite(Date.parse(a.expiresAt)))) {
    throw new Error('SIFT: malformed accepted release state');
  }
  if (a === null && value.rules.length) throw new Error('SIFT: unsigned cached rules');
  return value;
}
export async function readVerifiedFeedState(local) {
  const { [FEED_STATE_KEY]: value } = await local.get(FEED_STATE_KEY);
  return checkedState(value);
}

export async function recoverPendingFeed({ dnr, local }) {
  const state = await readVerifiedFeedState(local);
  if (!state.pending) return { recovered: false, sequence: state.active?.sequence ?? 0 };
  const saved = await local.get('enabled');
  await installDynamicRules(dnr, saved.enabled === false ? [] : state.rules);
  const restored = { ...state, pending: false };
  await local.set({ [FEED_STATE_KEY]: restored });
  return { recovered: true, sequence: state.active?.sequence ?? 0 };
}

export async function applyVerifiedFeed({ dnr, local }, {
  pin, now = Date.now(), maxRules = 20000,
  acquire = acquireVerifiedRelease
} = {}) {
  if (!pin?.keyId || !pin.publicKeyBase64) {
    throw new Error('SIFT: production signing identity not provisioned');
  }
  const settings = await local.get('enabled');
  if (settings.enabled === false) return { status: 'paused', installed: 0 };
  const before = await readVerifiedFeedState(local);
  if (before.pending) throw new Error('SIFT: incomplete installation requires recovery');
  if (before.active && before.active.keyId !== pin.keyId)
    throw new Error('SIFT: signing identity change requires approved rotation');

  const previous = before.active
    ? { sequence: before.active.sequence, sha256: before.active.sha256 }
    : {};
  const verified = await acquire(pin, previous, { now });
  if (!verified || !verified.release || typeof verified.sha256 !== 'string' ||
      !HEX.test(verified.sha256)) throw new Error('SIFT: incomplete signed release evidence');
  const { release, sha256 } = verified;
  if (release.keyId !== pin.keyId) throw new Error('SIFT: signing key identity mismatch');
  const { rules, stats } = compileForChromium(release.policy, { limit: maxRules });
  checkedRules(rules);
  if (!rules.length) throw new Error('SIFT: no enforceable signed rules');
  const nextActive = {
    keyId: release.keyId, sequence: release.sequence,
    sha256, expiresAt: release.expiresAt
  };

  await local.set({ [FEED_STATE_KEY]: { ...before, pending: true } });
  try {
    await installDynamicRules(dnr, rules);
    if ((await local.get('enabled')).enabled === false)
      throw new Error('SIFT: protection was paused during installation');
    await local.set({ [FEED_STATE_KEY]: {
      version: 1, active: nextActive, rules, pending: false
    } });
    return { status: 'installed', sequence: release.sequence, installed: rules.length,
      omittedDomains: stats.omittedDomains, sha256 };
  } catch (cause) {
    try {
      const settingsAfter = await local.get('enabled');
      await installDynamicRules(dnr, settingsAfter.enabled === false ? [] : before.rules);
      await local.set({ [FEED_STATE_KEY]: before });
    } catch {
      throw new Error('SIFT: release update failed and trusted protection recovery is required');
    }
    throw cause;
  }
}
