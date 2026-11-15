import { cleanTrackingUrl } from './url-cleaner.mjs';
const toggle = document.getElementById('toggle');
const clean = document.getElementById('clean');
const copy = document.getElementById('copy');
const input = document.getElementById('link');
const result = document.getElementById('result');
let output = null;
async function request(message) {
  const response = await chrome.runtime.sendMessage(message);
  if (!response?.ok) throw new Error(response?.error || 'Extension communication failed');
  return response.result;
}
function showEnabled(enabled) {
  toggle.disabled = false;
  toggle.setAttribute('aria-pressed', String(enabled));
  toggle.textContent = enabled ? 'Enabled' : 'Paused';
}
(async () => {
  try { showEnabled((await request({ type: 'GET_STATUS' })).enabled); }
  catch { toggle.textContent = 'Unavailable'; }
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab?.url?.startsWith('https://') || tab?.url?.startsWith('http://')) input.value = tab.url;
  } catch { /* No activeTab grant; user may enter a link. */ }
})();
toggle.addEventListener('click', async () => {
  toggle.disabled = true;
  try { showEnabled((await request({ type: 'SET_ENABLED', enabled: toggle.getAttribute('aria-pressed') !== 'true' })).enabled); }
  catch { toggle.textContent = 'Error'; toggle.disabled = false; }
});
clean.addEventListener('click', () => {
  output = null; copy.disabled = true;
  const attempt = cleanTrackingUrl(input.value.trim());
  result.textContent = attempt.changed ? 'Removed ' + attempt.removed + ' known tracking parameter(s).' :
    'Unchanged: ' + attempt.reason.replaceAll('-', ' ') + '.';
  if (attempt.changed) { output = attempt.value; input.value = output; copy.disabled = false; }
});
copy.addEventListener('click', async () => {
  if (!output) return;
  try { await navigator.clipboard.writeText(output); result.textContent = 'Cleaned link copied locally.'; }
  catch { result.textContent = 'Copy unavailable; select and copy the link above.'; }
});
input.addEventListener('input', () => { output = null; copy.disabled = true; result.textContent = ''; });
