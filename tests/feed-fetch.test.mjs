import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, createHash, sign } from 'node:crypto';
import { acquireVerifiedRelease } from '../src/intelligence/fetch.mjs';

const pair = generateKeyPairSync('ed25519');
const pin = {keyId:'test-feed-01', publicKeyBase64:pair.publicKey.export({format:'der',type:'spki'}).subarray(-32).toString('base64')};
const now=Date.now();
const policy={format:'admine.network-policy.v1',
  sources:[{id:'test',name:'Test',url:'https://example.org/feed.txt',license:'test'}],
  groups:[{effect:'block',important:false,match:{resourceTypes:['image']},sources:['test'],domains:['tracker.example']}],
  stats:{totalLines:1,supportedLines:1,skippedLines:0,duplicateLines:0,domainCount:1,groupCount:1}};
function fixture(){
  const release={format:'admine.sift.release.v1',keyId:pin.keyId,sequence:42,
    issuedAt:new Date(now-10000).toISOString(),expiresAt:new Date(now+86400000).toISOString(),policy};
  const payload=new TextEncoder().encode(JSON.stringify(release)+'\n');
  const proof=new TextEncoder().encode(JSON.stringify({
    format:'admine.sift.signature.v1',keyId:pin.keyId,length:payload.byteLength,
    sha256:createHash('sha256').update(payload).digest('hex'),
    signature:sign(null,payload,pair.privateKey).toString('base64')
  })+'\n');
  return {payload,proof};
}
function mock(entries,options={}){
  return async (url,request) => {
    assert.equal(request.credentials,'omit');
    assert.equal(request.redirect,'error');
    assert.equal(request.cache,'no-store');
    assert.match(url,/^https:\/\/admine\.au\/feeds\/sift\/current(?:\.sig)?\.json$/);
    const bytes = entries[url.split('/').pop()];
    const header = new Headers({'content-type':options.type ?? 'application/json'});
    if (options.declaredLength !== undefined)header.set('content-length',String(options.declaredLength));
    const response=new Response(bytes,{headers:header});
    // Simulate the unredirected fetch URL in a data-free controlled fixture.
    return {ok:true,redirected:options.redirected??false,url:options.otherUrl??url,
      headers:response.headers,body:response.body};
  };
}
test('accepts authenticated bytes only from pinned exact feed URLs',async()=>{
  const {payload,proof}=fixture();
  const candidate=await acquireVerifiedRelease(pin,{},{
    fetchImpl:mock({'current.json':payload,'current.sig.json':proof}),now
  });
  assert.equal(candidate.release.sequence,42);
});
test('unprovisioned key causes zero outbound requests',async()=>{
  let requests=0;
  await assert.rejects(acquireVerifiedRelease(null,{}, {fetchImpl:async()=>{requests++;}}));
  assert.equal(requests,0);
});
test('redirect, wrong content-type, oversize and invalid digest fail closed',async()=>{
  const {payload,proof}=fixture();
  const entries={'current.json':payload,'current.sig.json':proof};
  await assert.rejects(acquireVerifiedRelease(pin,{}, {fetchImpl:mock(entries,{redirected:true}),now}));
  await assert.rejects(acquireVerifiedRelease(pin,{}, {fetchImpl:mock(entries,{type:'text/html'}),now}));
  await assert.rejects(acquireVerifiedRelease(pin,{}, {fetchImpl:mock(entries,{declaredLength:8000001}),now}));
  await assert.rejects(acquireVerifiedRelease(pin,{}, {fetchImpl:mock(entries,{otherUrl:'https://example.org/fake'}),now}));
  const altered=payload.slice();altered[50]^=1;
  await assert.rejects(acquireVerifiedRelease(pin,{}, {fetchImpl:mock({...entries,'current.json':altered}),now}));
});
