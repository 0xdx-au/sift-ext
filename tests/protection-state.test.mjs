import test from 'node:test';
import assert from 'node:assert/strict';
import { readProtectionStatus, setProtectionEnabled } from '../src/protection/state.mjs';

const oldRule = {id:1000,priority:40,action:{type:'block'},condition:{requestDomains:['tracker.example'],resourceTypes:['image']}};
function fixture() {
  let active = true;
  let rules = [structuredClone(oldRule)];
  const local = {};
  const session = {};
  let rejectDisable = false;
  const storage = (state) => ({
    get: async (key) => ({ ...(Object.hasOwn(state,key) ? {[key]:structuredClone(state[key])} : {}) }),
    set: async (value) => { Object.assign(state,structuredClone(value)); },
    remove: async (key) => { delete state[key]; }
  });
  return {
    api:{
      dnr:{
        getEnabledRulesets:async()=>active?['starter']:[],
        updateEnabledRulesets:async({enableRulesetIds,disableRulesetIds})=>{
          if (rejectDisable && disableRulesetIds) throw Error('DNR unavailable');
          if(enableRulesetIds?.includes('starter'))active=true;
          if(disableRulesetIds?.includes('starter'))active=false;
        },
        getDynamicRules:async()=>structuredClone(rules),
        updateDynamicRules:async({removeRuleIds,addRules})=>{
          rules=rules.filter(rule=>!removeRuleIds.includes(rule.id)).concat(structuredClone(addRules));
        }
      },local:storage(local),session:storage(session)
    },
    state:()=>({active,rules,local,session}),
    rejectDisable:()=>{rejectDisable=true;}
  };
}
test('pausing removes SIFT dynamic blocks and disables bundled rules',async()=>{
  const f=fixture();
  const status=await setProtectionEnabled(f.api,false);
  assert.equal(status.enabled,false);
  assert.equal(status.consistent,true);
  assert.equal(status.dynamicRules,0);
  assert.equal(f.state().active,false);
  assert.equal(f.state().session.siftPausedDynamicRules.length,1);
});
test('resuming restores same-session dynamic rules and starter protections',async()=>{
  const f=fixture();
  await setProtectionEnabled(f.api,false);
  const restored=await setProtectionEnabled(f.api,true);
  assert.equal(restored.enabled,true);
  assert.equal(restored.dynamicRules,1);
  assert.equal(f.state().session.siftPausedDynamicRules,undefined);
  assert.deepEqual(f.state().rules,[oldRule]);
});
test('failed pause does not report success and restores original state',async()=>{
  const f=fixture();
  f.rejectDisable();
  await assert.rejects(setProtectionEnabled(f.api,false),/DNR unavailable/);
  const current=await readProtectionStatus(f.api);
  assert.equal(current.enabled,true);
  assert.equal(current.dynamicRules,1);
  assert.deepEqual(f.state().rules,[oldRule]);
});
test('browser restart with no session snapshot remains safely paused',async()=>{
  const f=fixture();
  await setProtectionEnabled(f.api,false);
  await f.api.session.remove('siftPausedDynamicRules');
  const status=await setProtectionEnabled(f.api,false);
  assert.equal(status.enabled,false);
  assert.equal(status.dynamicRules,0);
  const resumed=await setProtectionEnabled(f.api,true);
  assert.equal(resumed.dynamicRules,0);
  assert.equal(resumed.staticActive,true);
});
test('invalid paused snapshot does not activate unchecked rules',async()=>{
  const f=fixture();
  await setProtectionEnabled(f.api,false);
  await f.api.session.set({siftPausedDynamicRules:[{id:999999}]});
  await assert.rejects(setProtectionEnabled(f.api,true),/invalid paused policy snapshot/);
  assert.equal((await readProtectionStatus(f.api)).enabled,false);
});
