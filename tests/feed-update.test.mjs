import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, createHash, sign } from 'node:crypto';
import { verifyRelease } from '../src/intelligence/verify.mjs';
import { applyVerifiedFeed, readVerifiedFeedState, recoverPendingFeed, FEED_STATE_KEY } from '../src/intelligence/update.mjs';

const pair=generateKeyPairSync('ed25519'); // Disposable test-only signer.
const pin={keyId:'update-fixture-01',publicKeyBase64:pair.publicKey.export({format:'der',type:'spki'}).subarray(-32).toString('base64')};
const now=Date.now();
const policy={format:'admine.network-policy.v1',
  sources:[{id:'test',name:'Fixture',url:'https://example.org/list',license:'fixture'}],
  groups:[{effect:'block',important:false,match:{resourceTypes:['image'],domainType:'thirdParty'},sources:['test'],domains:['tracker.example']}],
  stats:{totalLines:1,supportedLines:1,skippedLines:0,duplicateLines:0,domainCount:1,groupCount:1}};
function signed(sequence=1, expiry=new Date(now+86400000).toISOString()){
  const release={format:'admine.sift.release.v1',keyId:pin.keyId,sequence,
    issuedAt:new Date(now-5000).toISOString(),expiresAt:expiry,policy};
  const rawBytes=new TextEncoder().encode(JSON.stringify(release)+'\n');
  const signatureText=JSON.stringify({
    format:'admine.sift.signature.v1',keyId:pin.keyId,length:rawBytes.length,
    sha256:createHash('sha256').update(rawBytes).digest('hex'),
    signature:sign(null,rawBytes,pair.privateKey).toString('base64')
  });
  return {rawBytes,signatureText};
}
function acquisition(sequence, expiry) {
  let calls=0;
  const run=async(pub,previous,opts)=>{
    calls++;
    const {rawBytes,signatureText}=signed(sequence,expiry);
    const verified=await verifyRelease(rawBytes,signatureText,pub,previous,opts.now);
    return {...verified,rawBytes,signatureText};
  };
  return {run,calls:()=>calls};
}
function fixture(){
  const persisted={enabled:true};
  let installed=[], failDNR=false, failCommit=false;
  const api={
    dnr:{
      getDynamicRules:async()=>structuredClone(installed),
      updateDynamicRules:async({removeRuleIds,addRules})=>{
        if(failDNR)throw Error('DNR quota rejected replacement');
        installed=installed.filter(rule=>!removeRuleIds.includes(rule.id)).concat(structuredClone(addRules));
      }
    },
    local:{
      get:async key=>Object.hasOwn(persisted,key)?{[key]:structuredClone(persisted[key])}:{},
      set:async values=>{
        if(failCommit && values[FEED_STATE_KEY]?.pending===false)throw Error('storage quota');
        Object.assign(persisted,structuredClone(values));
      }
    }
  };
  return {api,installed:()=>structuredClone(installed),persisted,failDNR:()=>{failDNR=true;},
    failCommit:()=>{failCommit=true;},forceRules:(rules)=>{installed=structuredClone(rules);}};
}
async function installFirst(f,sequence=1){
  return applyVerifiedFeed(f.api,{pin,now,acquire:acquisition(sequence).run});
}
test('exact signed payload/proof is durably retained; compiled rules are not trusted cache',async()=>{
  const f=fixture();
  const result=await installFirst(f);
  assert.equal(result.installed,1);
  const state=await readVerifiedFeedState(f.api.local);
  assert.equal(state.version,2);
  assert.equal(state.pending,false);
  assert.equal(state.accepted.meta.sha256,result.sha256);
  assert.equal(state.accepted.meta.sequence,1);
  assert.equal(typeof state.accepted.payload,'string');
  assert.equal(typeof state.accepted.proof,'string');
  assert.equal(state.rules,undefined);
  assert.equal(f.installed().length,1);
});
test('signed cache is independently reverified on every startup, without network',async()=>{
  const f=fixture();
  await installFirst(f);
  f.forceRules([{id:1000,action:{type:'allow'},condition:{urlFilter:'||evil.example^'}}]);
  const restored=await recoverPendingFeed(f.api,{pin,now});
  assert.equal(restored.status,'verified');
  assert.equal(restored.installed,1);
  assert.equal(f.installed()[0].action.type,'block');
});
test('recovery of interrupted replacement restores only last signed accepted policy',async()=>{
  const f=fixture();
  await installFirst(f);
  f.persisted[FEED_STATE_KEY].pending=true;
  f.forceRules([{id:1000,action:{type:'allow'},condition:{urlFilter:'||evil.example^'}}]);
  const status=await recoverPendingFeed(f.api,{pin,now});
  assert.equal(status.recovered,true);
  assert.equal(status.sequence,1);
  assert.equal((await readVerifiedFeedState(f.api.local)).pending,false);
  assert.equal(f.installed()[0].condition.requestDomains[0],'tracker.example');
});
test('no production pin quarantines dynamic rules without network or cache activation',async()=>{
  const f=fixture();
  await installFirst(f);
  const recovered=await recoverPendingFeed(f.api,{pin:null,now});
  assert.equal(recovered.status,'unprovisioned');
  assert.equal(f.installed().length,0);
});
test('cached signed content tampering or forged metadata quarantines dynamic rules',async()=>{
  for(const mutation of [
    state=>{state.accepted.payload=state.accepted.payload.replace('tracker.example','other.example');},
    state=>{state.accepted.proof='{}';},
    state=>{state.accepted.meta.sequence=99;}
  ]){
    const f=fixture(); await installFirst(f);
    mutation(f.persisted[FEED_STATE_KEY]);
    const result=await recoverPendingFeed(f.api,{pin,now});
    assert.equal(result.status,'quarantined');
    assert.equal(f.installed().length,0);
  }
});
test('expired cached release is not restored on startup',async()=>{
  const f=fixture();
  await installFirst(f);
  const result=await recoverPendingFeed(f.api,{pin,now:now+2*86400000});
  assert.equal(result.status,'quarantined');
  assert.equal(f.installed().length,0);
});
test('paused protection does not fetch or restore dynamic rules',async()=>{
  const f=fixture(),a=acquisition(1);
  f.persisted.enabled=false;
  const result=await applyVerifiedFeed(f.api,{pin,now,acquire:a.run});
  assert.equal(result.status,'paused');
  assert.equal(a.calls(),0);
  f.persisted.enabled=true;
  await installFirst(f);
  f.persisted.enabled=false;
  const recovered=await recoverPendingFeed(f.api,{pin,now});
  assert.equal(recovered.installed,0);
  assert.equal(f.installed().length,0);
});
test('missing pin prevents acquisition',async()=>{
  const f=fixture(),a=acquisition(1);
  await assert.rejects(applyVerifiedFeed(f.api,{pin:null,now,acquire:a.run}),/not provisioned/);
  assert.equal(a.calls(),0);
});
test('rollback from old sequence is rejected before installing',async()=>{
  const f=fixture();
  await installFirst(f,3);
  const before=f.installed();
  await assert.rejects(applyVerifiedFeed(f.api,{pin,now,acquire:acquisition(2).run}),/rollback/);
  assert.deepEqual(f.installed(),before);
});
test('unsigned/unverifiable acquired summary is never installed',async()=>{
  const f=fixture();
  await assert.rejects(applyVerifiedFeed(f.api,{pin,now,acquire:async()=>({release:{policy},sha256:'0'.repeat(64)})}),/signed evidence absent/);
  assert.equal(f.installed().length,0);
});
test('DNR rejection cannot overwrite durable accepted release',async()=>{
  const f=fixture();
  await installFirst(f);
  const before=await readVerifiedFeedState(f.api.local);
  f.failDNR();
  await assert.rejects(applyVerifiedFeed(f.api,{pin,now,acquire:acquisition(2).run}),/quota|quarantined/);
  const after=await readVerifiedFeedState(f.api.local);
  assert.equal(after.accepted.meta.sequence,before.accepted.meta.sequence);
});
test('storage commit failure attempts verified rollback and quarantines on rollback failure',async()=>{
  const f=fixture();await installFirst(f);
  f.failCommit();
  await assert.rejects(applyVerifiedFeed(f.api,{pin,now,acquire:acquisition(2).run}),/storage quota|quarantined/);
  const status=await readVerifiedFeedState(f.api.local);
  assert.equal(status.accepted.meta.sequence,1);
});
test('corrupt journal is quarantined; never trusted to install old rules',async()=>{
  const f=fixture();
  f.persisted[FEED_STATE_KEY]={version:1,active:{sequence:999},rules:[{id:1000}]};
  f.forceRules([{id:1000,action:{type:'allow'},condition:{urlFilter:'||evil.example^'}}]);
  const result=await recoverPendingFeed(f.api,{pin,now});
  assert.equal(result.status,'quarantined');
  assert.equal(f.installed().length,0);
});
