import { readProtectionStatus, setProtectionEnabled } from './protection/state.mjs';

const api = {
  dnr: chrome.declarativeNetRequest,
  local: chrome.storage.local,
  session: chrome.storage.session
};

let pending = Promise.resolve();
function serial(task) {
  const next = pending.then(task, task);
  pending = next.catch(() => {});
  return next;
}

async function reconcile() {
  const saved = await api.local.get('enabled');
  return setProtectionEnabled(api, saved.enabled !== false);
}
chrome.runtime.onInstalled.addListener(() => {
  serial(reconcile).catch((error) => console.error('SIFT: reconciliation failed', error.message));
});
chrome.runtime.onStartup.addListener(() => {
  serial(reconcile).catch((error) => console.error('SIFT: reconciliation failed', error.message));
});
chrome.runtime.onMessage.addListener((message, sender, reply) => {
  if (sender.id !== chrome.runtime.id || !['GET_STATUS','SET_ENABLED'].includes(message?.type))
    return false;
  const task = message.type === 'GET_STATUS'
    ? () => readProtectionStatus(api)
    : () => setProtectionEnabled(api, message.enabled);
  serial(task).then(
    (result) => reply({ ok: true, result }),
    () => reply({ ok: false, error: 'Protection state could not be updated' })
  );
  return true;
});
