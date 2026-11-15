import { chromium } from 'playwright';
import { createServer } from 'node:http';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve, join } from 'node:path';
import assert from 'node:assert/strict';
import { compileForChromium } from '../src/intelligence/compile.mjs';

const visits = [];
const server = createServer((req, res) => {
  visits.push(req.url);
  if (req.url === '/') {
    res.writeHead(200, {'content-type':'text/html','cache-control':'no-store'});
    res.end('<!doctype html><html><body><h1>SIFT LOCAL NETWORK FIXTURE</h1></body></html>');
  } else {
    res.writeHead(200, {'content-type':'image/svg+xml','cache-control':'no-store'});
    res.end('<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1"></svg>');
  }
});
await new Promise((ok) => server.listen(0, '127.0.0.1', ok));
const {port} = server.address();
const origin = 'http://127.0.0.1:' + port;
const profile = await mkdtemp(join(tmpdir(),'sift-e2e-'));
let context;
let failed = false;
function report(label, result, details='') { console.log(JSON.stringify({label,result,details})); }
async function requestImage(page, url) {
  const failure = page.waitForEvent('requestfailed', {predicate:r=>r.url()===url,timeout:15000}).catch(()=>null);
  const response = page.waitForEvent('response', {predicate:r=>r.url()===url,timeout:15000}).catch(()=>null);
  await page.evaluate((address) => {
    const image = document.createElement('img');
    image.id = 'sift-test-image-' + Math.random().toString(36).slice(2);
    image.src = address;
    document.body.append(image);
  }, url);
  return Promise.race([
    failure.then(r=>r ? {type:'failure',error:r.failure()?.errorText} : null),
    response.then(r=>r ? {type:'response',status:r.status()} : null)
  ]);
}
try {
  context = await chromium.launchPersistentContext(profile,{
    channel:'chromium',headless:true,
    args:['--disable-extensions-except=' + resolve('.'),'--load-extension=' + resolve('.')],
    ignoreHTTPSErrors:false
  });
  let workers=context.serviceWorkers();
  if(!workers.length)workers=[await context.waitForEvent('serviceworker',{timeout:20000})];
  const worker=workers[0];
  assert.ok(worker.url().startsWith('chrome-extension://'),'MV3 worker did not load');
  report('browser-version','observed',await worker.evaluate(()=>navigator.userAgent));
  const extensionId=new URL(worker.url()).hostname;
  const page=await context.newPage();
  await page.goto(origin+'/',{waitUntil:'domcontentloaded'});
  const allowedUrl=origin+'/allowed.svg';
  const allowed=await requestImage(page,allowedUrl);
  assert.equal(allowed?.type,'response','Independent local allowed network request failed');
  assert.equal(allowed.status,200);
  assert.ok(visits.includes('/allowed.svg'),'Server did not observe allowed request');
  report('independent-allowed-network-request','pass');

  const staticBlocked='http://google-analytics.com/sift-test-image';
  const blocked=await requestImage(page,staticBlocked);
  assert.equal(blocked?.type,'failure','Bundled static rule did not reject request');
  assert.match(blocked.error||'',/ERR_BLOCKED_BY_CLIENT/);
  report('bundled-static-DNR-block','pass',blocked.error);

  const policy={
    format:'admine.network-policy.v1',
    sources:[{id:'fixture',name:'Fixture',url:'https://example.org/rules',license:'fixture'}],
    groups:[{effect:'block',important:false,match:{resourceTypes:['image'],domainType:'thirdParty'},sources:['fixture'],domains:['tracker.example']}],
    stats:{totalLines:1,supportedLines:1,skippedLines:0,duplicateLines:0,domainCount:1,groupCount:1}
  };
  const compiled=compileForChromium(policy,{limit:20}).rules;
  const result=await worker.evaluate(async(rules)=>{
    const old=await chrome.declarativeNetRequest.getDynamicRules();
    await chrome.declarativeNetRequest.updateDynamicRules({removeRuleIds:old.map(r=>r.id),addRules:rules});
    const current=await chrome.declarativeNetRequest.getDynamicRules();
    if(current.length!==rules.length)throw Error('DNR browser did not retain compiled rules');
    return {installed:current.length};
  },compiled);
  assert.equal(result.installed,1);
  const dynamicBlocked='http://tracker.example/sift-test-image';
  const blockedDynamic=await requestImage(page,dynamicBlocked);
  assert.equal(blockedDynamic?.type,'failure','Compiled dynamic rule did not block');
  assert.match(blockedDynamic.error||'',/ERR_BLOCKED_BY_CLIENT/);
  report('compiled-dynamic-DNR-block','pass',blockedDynamic.error);

  const popup=await context.newPage();
  await popup.goto('chrome-extension://'+extensionId+'/src/popup.html');
  const toggle=popup.locator('#toggle');
  await toggle.waitFor();
  await toggle.click();
  await popup.waitForTimeout(300);
  let enabled=await worker.evaluate(()=>chrome.declarativeNetRequest.getEnabledRulesets());
  assert.equal(enabled.includes('starter'),false,'Toggle failed to disable static protection');
  let stored=await worker.evaluate(()=>chrome.declarativeNetRequest.getDynamicRules());
  assert.equal(stored.length,0,'Pause failed: dynamic blocking still active');
  let pausedStatus=await worker.evaluate(()=>chrome.storage.local.get('enabled'));
  assert.equal(pausedStatus.enabled,false,'Pause state not committed');
  report('popup-pause-all-DNR-layers','pass');
  await toggle.click();
  await popup.waitForTimeout(300);
  enabled=await worker.evaluate(()=>chrome.declarativeNetRequest.getEnabledRulesets());
  assert.equal(enabled.includes('starter'),true,'Toggle failed to restore static protection');
  stored=await worker.evaluate(()=>chrome.declarativeNetRequest.getDynamicRules());
  assert.equal(stored.length,1,'Resume failed to restore session dynamic protection');
  const blockedAfterResume=await requestImage(page,'http://tracker.example/after-resume');
  assert.equal(blockedAfterResume?.type,'failure');
  assert.match(blockedAfterResume.error||'',/ERR_BLOCKED_BY_CLIENT/);
  report('popup-resume-all-DNR-layers','pass');
  await popup.locator('#link').fill('https://example.org/?q=secure&utm_source=test');
  await popup.locator('#clean').click();
  assert.equal(await popup.locator('#link').inputValue(),'https://example.org/?q=secure');
  report('popup-resume-and-manual-clean','pass');
} catch(e) {
  failed=true;
  report('browser-e2e','fail',String(e.stack||e));
} finally {
  if(context)await context.close().catch(()=>{});
  await new Promise(ok=>server.close(ok));
  await rm(profile,{recursive:true,force:true});
}
if(failed)process.exitCode=1;
