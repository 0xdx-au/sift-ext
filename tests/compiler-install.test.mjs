import test from 'node:test';
import assert from 'node:assert/strict';
import {compileForChromium} from '../src/intelligence/compile.mjs';
import {installDynamicRules} from '../src/intelligence/install.mjs';
const group=(effect,important,domain)=>({effect,important,match:{resourceTypes:['script'],domainType:'thirdParty'},sources:['test'],domains:[domain]});
const policy={format:'admine.network-policy.v1',sources:[{id:'test',name:'Test',url:'https://example.org/rules',license:'fixture'}],
  groups:[group('block',false,'normal.example'),group('block',true,'important.example'),group('allow',false,'exception.example')],
  stats:{totalLines:3,supportedLines:3,skippedLines:0,duplicateLines:0,domainCount:3,groupCount:3}};
test('compiler keeps allow exceptions first when quota truncates',()=>{
 const {rules,stats}=compileForChromium(policy,{limit:1});
 assert.equal(rules.length,1);
 assert.equal(rules[0].action.type,'allow');
 assert.equal(stats.truncated,true);
 assert.throws(()=>compileForChromium(policy,{target:'safari'}),/unsupported/);
});
test('important blocking priority outranks ordinary allows',()=>{
 const {rules}=compileForChromium(policy);
 assert.ok(rules.find(r=>r.condition.requestDomains.includes('important.example')).priority >
   rules.find(r=>r.action.type==='allow').priority);
});
test('DNR atomic update verified before reporting installation',async()=>{
 let installed=[{id:1000,action:{type:'block'},condition:{requestDomains:['old.example']}}];
 const dnr={
   getDynamicRules:async()=>structuredClone(installed),
   updateDynamicRules:async({removeRuleIds,addRules})=>{
     installed=installed.filter(r=>!removeRuleIds.includes(r.id)).concat(structuredClone(addRules));
   }
 };
 const candidate=compileForChromium(policy).rules;
 const result=await installDynamicRules(dnr,candidate);
 assert.equal(result.installed,3);
 assert.deepEqual(installed,candidate);
});
test('DNR failure retains prior rules and reports error',async()=>{
 const previous=[{id:1000,action:{type:'block'},condition:{requestDomains:['old.example']}}];
 const dnr={
   getDynamicRules:async()=>structuredClone(previous),
   updateDynamicRules:async()=>{throw Error('DNR quota exhausted');}
 };
 await assert.rejects(installDynamicRules(dnr,compileForChromium(policy).rules),/quota exhausted/);
 assert.equal((await dnr.getDynamicRules())[0].condition.requestDomains[0],'old.example');
});

test('Chrome-normalized object ordering is accepted without weakening rule semantics',async()=>{
 const proposed=compileForChromium(policy).rules;
 let installed=[];
 const dnr={
  getDynamicRules:async()=>installed.map(r=>({
   action:{type:r.action.type},
   condition:{domainType:r.condition.domainType,requestDomains:[...r.condition.requestDomains].reverse(),resourceTypes:[...r.condition.resourceTypes]},
   id:r.id,priority:r.priority
  })),
  updateDynamicRules:async({removeRuleIds,addRules})=>{
   installed=installed.filter(r=>!removeRuleIds.includes(r.id)).concat(structuredClone(addRules));
  }
 };
 const status=await installDynamicRules(dnr,proposed);
 assert.equal(status.installed,3);
});
test('actual change to effective DNR semantics still fails verification and restores',async()=>{
 const proposed=compileForChromium(policy).rules;
 let installed=[{id:1000,priority:40,action:{type:'block'},condition:{requestDomains:['old.example'],resourceTypes:['script']}}];
 let falsify=false;
 const dnr={
  getDynamicRules:async()=>falsify ? installed.map(r=>({...structuredClone(r),action:{type:'allow'}})) : structuredClone(installed),
  updateDynamicRules:async({removeRuleIds,addRules})=>{
   installed=installed.filter(r=>!removeRuleIds.includes(r.id)).concat(structuredClone(addRules));
   falsify=true;
  }
 };
 await assert.rejects(installDynamicRules(dnr,proposed),/installed rules differ/);
});
