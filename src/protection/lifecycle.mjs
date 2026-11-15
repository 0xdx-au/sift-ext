import { recoverPendingFeed } from '../intelligence/update.mjs';
import { setProtectionEnabled } from './state.mjs';

export async function reconcileProtection(api, pin = null, now = Date.now()) {
  // Manifest V3 storage is not an authentication channel; only the approved
  // package can pin a public trust identity. Never load a pin from storage.
  await api.local.setAccessLevel({ accessLevel: 'TRUSTED_CONTEXTS' });
  await api.session.setAccessLevel({ accessLevel: 'TRUSTED_CONTEXTS' });
  // Session snapshots were not independently authenticated. Do not permit
  // stale session rules to be reinstalled after browser/worker restart.
  await api.session.remove('siftPausedDynamicRules');
  const restoration = await recoverPendingFeed(api, { pin, now });
  const saved = await api.local.get('enabled');
  const protection = await setProtectionEnabled(api, saved.enabled !== false);
  return { restoration, protection };
}
