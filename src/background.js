// Local-only starter control. Signed dynamic feeds are intentionally not enabled.
const RULESET = 'starter';
const SETTING = 'enabled';
async function setEnabled(enabled) {
  const current = await chrome.declarativeNetRequest.getEnabledRulesets();
  const isActive = current.includes(RULESET);
  if (isActive !== enabled) {
    await chrome.declarativeNetRequest.updateEnabledRulesets(
      enabled ? { enableRulesetIds: [RULESET] } : { disableRulesetIds: [RULESET] }
    );
  }
  await chrome.storage.local.set({ [SETTING]: enabled });
  return { enabled, ruleset: RULESET, dynamicFeed: 'unprovisioned' };
}
async function status() {
  const active = await chrome.declarativeNetRequest.getEnabledRulesets();
  return { enabled: active.includes(RULESET), ruleset: RULESET, dynamicFeed: 'unprovisioned' };
}
async function reconcile() {
  const saved = await chrome.storage.local.get(SETTING);
  await setEnabled(saved[SETTING] !== false);
}
chrome.runtime.onInstalled.addListener(() => { reconcile().catch(console.error); });
chrome.runtime.onStartup.addListener(() => { reconcile().catch(console.error); });
chrome.runtime.onMessage.addListener((message, sender, reply) => {
  if (sender.id !== chrome.runtime.id || !['GET_STATUS', 'SET_ENABLED'].includes(message?.type))
    return false;
  (async () => {
    if (message.type === 'GET_STATUS') return await status();
    if (typeof message.enabled !== 'boolean') throw new Error('Invalid protection setting');
    return await setEnabled(message.enabled);
  })().then((result) => reply({ ok: true, result }),
            () => reply({ ok: false, error: 'Protection state could not be updated' }));
  return true;
});
