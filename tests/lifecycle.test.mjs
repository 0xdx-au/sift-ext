import test from 'node:test';
import assert from 'node:assert/strict';
import {reconcileProtection} from '../src/protection/lifecycle.mjs';
import {FEED_STATE_KEY} from '../src/intelligence/update.mjs';
function fixture() {
 const local={enabled:true},session={siftPausedDynamicRules:[
  {id:1000,action:{type:'allow'},condition:{urlFilter:'||bad.example^'}}
 ]};
 let active=['starter'];
 let dynamic=[{id:1000,action:{type:'allow'},condition:{urlFilter:'||bad.example^'}}];
 const makeStorage=state=>({
  async setAccessLevel({accessLevel}){assert.equal(accessLevel,'TRUSTED_CONTEXTS');},
  async get(k){return k in state?{[k]:structuredClone(state[k])}:{};},
  async set(x){Object.assign(state,structuredClone(x));},
  async remove(k){delete state[k];}
 });
 const api={local:makeStorage(local),session:makeStorage(session),dnr:{
  async getDynamicRules(){return structuredClone(dynamic);},
  async updateDynamicRules({removeRuleIds,addRules}){
   dynamic=dynamic.filter(r=>!removeRuleIds.includes(r.id)).concat(structuredClone(addRules));
  },
  async getEnabledRulesets(){return [...active];},
  async updateEnabledRulesets({enableRulesetIds,disableRulesetIds}){
   active=active.filter(id=>!(disableRulesetIds || []).includes(id));
   active.push(...(enableRulesetIds || []).filter(id=>!active.includes(id)));
  }
 }};
 return {api,local,session,getDynamic:()=>dynamic,getActive:()=>active};
}
test('unprovisioned startup removes all SIFT dynamic rules and old session snapshots',async()=>{
 const f=fixture();
 const result=await reconcileProtection(f.api,null);
 assert.equal(result.restoration.status,'unprovisioned');
 assert.equal(f.getDynamic().length,0);
 assert.equal(f.session.siftPausedDynamicRules,undefined);
 assert.equal(result.protection.staticActive,true);
});
test('legacy unsigned cache is quarantined, not revived on startup',async()=>{
 const f=fixture();
 f.local[FEED_STATE_KEY]={version:1,active:{sequence:10},rules:f.getDynamic()};
 const result=await reconcileProtection(f.api,null);
 assert.equal(result.restoration.status,'quarantined');
 assert.equal(f.getDynamic().length,0);
});
test('user-paused setting is still respected when signing is not provisioned',async()=>{
 const f=fixture();
 f.local.enabled=false;
 const result=await reconcileProtection(f.api,null);
 assert.equal(result.protection.enabled,false);
 assert.equal(f.getActive().includes('starter'),false);
 assert.equal(f.getDynamic().length,0);
});
