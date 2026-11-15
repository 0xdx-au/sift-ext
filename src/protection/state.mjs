import { installDynamicRules } from '../intelligence/install.mjs';

const RULESET = 'starter';
const SNAPSHOT = 'siftPausedDynamicRules';
const START = 1000;
const END = 29000;
const owned = (rule) => Number.isInteger(rule?.id) && rule.id >= START && rule.id < END;

function checkedSnapshot(value) {
  if (!Array.isArray(value) || value.length > 28000 ||
      value.some((rule) => !owned(rule)) ||
      new Set(value.map((rule) => rule.id)).size !== value.length)
    throw new Error('SIFT: invalid paused policy snapshot');
  return value;
}

export async function readProtectionStatus({ dnr, local }) {
  const active = (await dnr.getEnabledRulesets()).includes(RULESET);
  const dynamicRules = (await dnr.getDynamicRules()).filter(owned);
  const settings = await local.get('enabled');
  const paused = settings.enabled === false;
  return {
    enabled: active && !paused,
    staticActive: active,
    dynamicRules: dynamicRules.length,
    paused,
    consistent: paused ? !active && dynamicRules.length === 0 : active,
    signedFeed: 'unprovisioned'
  };
}

export async function setProtectionEnabled({ dnr, local, session }, enabled) {
  if (typeof enabled !== 'boolean') throw new Error('SIFT: invalid protection setting');
  const activeBefore = (await dnr.getEnabledRulesets()).includes(RULESET);
  const previousRules = (await dnr.getDynamicRules()).filter(owned);
  const savedSetting = await local.get('enabled');
  const sessionBefore = await session.get(SNAPSHOT);
  const existingSnapshot = sessionBefore[SNAPSHOT] === undefined
    ? null : checkedSnapshot(sessionBefore[SNAPSHOT]);

  try {
    if (!enabled) {
      if (previousRules.length) {
        await session.set({ [SNAPSHOT]: previousRules });
        await installDynamicRules(dnr, []);
      }
      if (activeBefore) await dnr.updateEnabledRulesets({ disableRulesetIds: [RULESET] });
      await local.set({ enabled: false });
    } else {
      if (existingSnapshot?.length) {
        await installDynamicRules(dnr, existingSnapshot);
      }
      if (!activeBefore) await dnr.updateEnabledRulesets({ enableRulesetIds: [RULESET] });
      await local.set({ enabled: true });
      await session.remove(SNAPSHOT);
    }
    const status = await readProtectionStatus({ dnr, local });
    if (!status.consistent || status.enabled !== enabled) {
      throw new Error('SIFT: protection state inconsistent after transition');
    }
    return status;
  } catch (error) {
    try {
      await installDynamicRules(dnr, previousRules);
      const activeAfter = (await dnr.getEnabledRulesets()).includes(RULESET);
      if (activeAfter !== activeBefore) {
        await dnr.updateEnabledRulesets(activeBefore
          ? { enableRulesetIds: [RULESET] }
          : { disableRulesetIds: [RULESET] });
      }
      if (savedSetting.enabled === undefined) await local.remove('enabled');
      else await local.set({ enabled: savedSetting.enabled });
      if (existingSnapshot === null) await session.remove(SNAPSHOT);
      else await session.set({ [SNAPSHOT]: existingSnapshot });
    } catch {
      throw new Error('SIFT: protection transition failed; previous state could not be restored');
    }
    throw error;
  }
}
