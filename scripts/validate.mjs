import assert from 'node:assert/strict';
import { SIGNING_PIN } from '../src/intelligence/trust.mjs';
import { readFile } from 'node:fs/promises';
const json = async (path) => JSON.parse(await readFile(new URL('../' + path, import.meta.url), 'utf8'));
const manifest = await json('manifest.json');
assert.equal(manifest.manifest_version, 3);
assert.ok(Number(manifest.minimum_chrome_version) >= 156, 'Disallow unsupported legacy Chromium runtimes');
assert.deepEqual(manifest.permissions, ['declarativeNetRequest','storage','activeTab']);
assert.equal(manifest.host_permissions, undefined);
assert.equal(manifest.externally_connectable, undefined);
assert.equal(SIGNING_PIN, null, 'Production key pin needs independently approved release gates');
assert.equal(manifest.content_security_policy.extension_pages, "script-src 'self'; object-src 'self'");
const resources = manifest.declarative_net_request.rule_resources;
assert.equal(resources.length, 1);
const rules = await json(resources[0].path);
assert.equal(rules.length, 1);
for (const rule of rules) {
  assert.equal(rule.action.type, 'block');
  assert.equal(rule.condition.domainType, 'thirdParty');
  assert.ok(!rule.condition.resourceTypes.includes('main_frame'));
  assert.ok(rule.condition.requestDomains.length < 100);
}
for (const path of ['src/background.js','src/popup.js','src/url-cleaner.mjs','src/popup.html','src/popup.css','src/brand/admine-mark.svg','src/brand/admine-mark-light.svg']) {
  assert.ok((await readFile(new URL('../' + path, import.meta.url))).length > 0, path);
}
console.log('SIFT EXT starter manifest and resource validation passed');

for (const file of ['admine-mark.svg','admine-mark-light.svg']) {
  const source = await readFile(new URL('../src/brand/' + file, import.meta.url), 'utf8');
  assert.ok(source.includes('M116 22 H140 L240 228'), 'Use the real ADMINE contour-A silhouette');
  assert.ok(!/<script|<foreignObject|https?:\/\//i.test(source), 'Logo assets must be local and inert');
}
