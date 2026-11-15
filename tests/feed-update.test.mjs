import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,createHash,sign} from 'node:crypto';
import {verifyRelease} from '../src/intelligence/verify.mjs';
import {applyVerifiedFeed,readVerifiedFeedState,recoverPendingFeed,FEED_STATE_KEY} from '../src/intelligence/update.mjs';
const keys=generateKeyPairSync('ed25519');
const pin={keyId:'update-test-key',publicKeyBase64:keys.publicKey.export({format:'der',type:'spki'}).subarray(-32).toString('base64')};
const now=Date.now();
const policy={format:'admine.network-policy.v1',
  sources:[{id:'test',name:'Fixture',url:'https://example.org/list',license:'fixture'}],
  groups:[{effect:'block',important:false,match:{resourceTypes:['image'],domainType:'thirdParty'},sources:['test'],domains:['tracker.example']}],
  stats:{totalLines:1,supportedLines:1,skippedLines:0,duplicateLines:0,domainCount:1,groupCount:1}};
function proof(sequence=1) {
 const release={format:'admine.sift.release.v1',keyId:pin.keyId,sequence,
  issuedAt:new Date(now-5000).toISOString(),expiresAt:new Date(now+86400000).toISOString(),policy};
 const bytes=new TextEncoder().encode(JSON.stringify(release)+'\n');
 const metadata={format:'admine.sift.signature.v1',keyId:pin.keyId,length:bytes.length,
  sha256:createHash('sha256').update(bytes).digest('hex'),
  signature:sign(null,bytes,keys.privateKey).toString('base64')};
 return {bytes,metadata};
}
function acquisition(sequence) {
 let count=0;
 return {
   run:async(pub,previous,opts)=>{
     count++;
     const {bytes,metadata}=proof(sequence);
     return verifyRelease(bytes,JSON.stringify(metadata),pub,previous,opts.now);
   },
   calls:()=>count
 };
}
function fixture(){
 const persisted={enabled:true};
 let installed=[], failInstall=false, failFinalSave=false;
 const api={
  dnr:{
   getDynamicRules:async()=>structuredClone(installed),
   updateDynamicRules:async({removeRuleIds,addRules})=>{
     if(failInstall)throw Error('DNR limit rejected installation');
     installed=installed.filter(rule=>!removeRuleIds.includes(rule.id)).concat(structuredClone(addRules));
   }
  },
  local:{
   get:async key=>Object.hasOwn(persisted,key)?{[key]:structuredClone(persisted[key])}:{},
   set:async values=>{
     if(failFinalSave && values[FEED_STATE_KEY]?.pending===false)
       throw Error('storage quota exceeded');
     Object.assign(persisted,structuredClone(values));
   }
  }
 };
 return {api,installed:()=>installed,save:()=>persisted,failInstall:()=>{failInstall=true;},
   failFinalSave:()=>{failFinalSave=true;}};
}
test('new release is independently verified, installed, confirmed and anchored',async()=>{
 const f=fixture(),a=acquisition(1);
 const result=await applyVerifiedFeed(f.api,{pin,now,acquire:a.run});
 assert.equal(result.status,'installed');
 assert.equal(result.installed,1);
 assert.equal(a.calls(),1);
 const saved=await readVerifiedFeedState(f.api.local);
 assert.equal(saved.pending,false);
 assert.equal(saved.active.sequence,1);
 assert.equal(saved.active.sha256,result.sha256);
 assert.equal(f.installed().length,1);
});
test('rollback and same-sequence substitution fail before installation',async()=>{
 const f=fixture();
 await applyVerifiedFeed(f.api,{pin,now,acquire:acquisition(2).run});
 const installedBefore=structuredClone(f.installed());
 await assert.rejects(applyVerifiedFeed(f.api,{pin,now,acquire:acquisition(1).run}),/rollback/);
 assert.deepEqual(f.installed(),installedBefore);
});
test('paused protection performs no network acquisition',async()=>{
 const f=fixture(),a=acquisition(1);
 f.save().enabled=false;
 const result=await applyVerifiedFeed(f.api,{pin,now,acquire:a.run});
 assert.equal(result.status,'paused');
 assert.equal(a.calls(),0);
});
test('missing production public key cannot acquire intelligence',async()=>{
 const f=fixture(),a=acquisition(1);
 await assert.rejects(applyVerifiedFeed(f.api,{pin:null,now,acquire:a.run}),/not provisioned/);
 assert.equal(a.calls(),0);
});
test('DNR rejection leaves previous accepted policy unchanged',async()=>{
 const f=fixture();
 await applyVerifiedFeed(f.api,{pin,now,acquire:acquisition(1).run});
 const prior=await readVerifiedFeedState(f.api.local);
 const before=structuredClone(f.installed());
 f.failInstall();
 await assert.rejects(applyVerifiedFeed(f.api,{pin,now,acquire:acquisition(2).run}),/DNR limit|recovery/);
 assert.deepEqual(f.installed(),before);
 const after=await readVerifiedFeedState(f.api.local);
 assert.equal(after.active.sequence,prior.active.sequence);
});
test('storage-commit failure rolls back DNR to previous accepted rules',async()=>{
 const f=fixture();
 await applyVerifiedFeed(f.api,{pin,now,acquire:acquisition(1).run});
 // Inject the final commit failure only for a subsequent installation.
 f.failFinalSave();
 await assert.rejects(applyVerifiedFeed(f.api,{pin,now,acquire:acquisition(2).run}),/storage quota|recovery/);
 assert.equal(f.installed().length,1);
 const state=await readVerifiedFeedState(f.api.local);
 assert.equal(state.active.sequence,1);
});
test('recovery journal restores previous accepted policy after interrupted upgrade',async()=>{
 const f=fixture();
 await applyVerifiedFeed(f.api,{pin,now,acquire:acquisition(1).run});
 const good=await readVerifiedFeedState(f.api.local);
 f.save()[FEED_STATE_KEY]={...good,pending:true};
 const recovered=await recoverPendingFeed(f.api);
 assert.equal(recovered.recovered,true);
 assert.equal(recovered.sequence,1);
 assert.equal((await readVerifiedFeedState(f.api.local)).pending,false);
 assert.deepEqual(f.installed(),good.rules);
});
test('pending crash recovery respects user pause',async()=>{
 const f=fixture();
 await applyVerifiedFeed(f.api,{pin,now,acquire:acquisition(1).run});
 f.save()[FEED_STATE_KEY].pending=true;
 f.save().enabled=false;
 const result=await recoverPendingFeed(f.api);
 assert.equal(result.recovered,true);
 assert.equal(f.installed().length,0);
});
