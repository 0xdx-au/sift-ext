// Standalone atomic DNR adapter. Not connected to live updates until crash/restart recovery exists.
import {RULE_START} from './compile.mjs';
const OWNED_END=RULE_START+28000;
const isOwned=id=>Number.isInteger(id)&&id>=RULE_START&&id<OWNED_END;
function ensureRules(rules){
 if(!Array.isArray(rules)||rules.length>28000||rules.some(r=>!isOwned(r?.id))||
     new Set(rules.map(r=>r.id)).size!==rules.length)
   throw Error('SIFT: invalid installation candidate');
}
function snapshotSignature(rules){
 return JSON.stringify([...rules].sort((a,b)=>a.id-b.id));
}
export async function installDynamicRules(dnr,candidate){
 ensureRules(candidate);
 const before=(await dnr.getDynamicRules()).filter(r=>isOwned(r.id));
 await dnr.updateDynamicRules({removeRuleIds:before.map(r=>r.id),addRules:candidate});
 let after;
 try{after=(await dnr.getDynamicRules()).filter(r=>isOwned(r.id));}
 catch(error){
   try{await dnr.updateDynamicRules({removeRuleIds:candidate.map(r=>r.id),addRules:before});}
   catch{throw Error('SIFT: post-install read failed and restoration not confirmed');}
   throw error;
 }
 if(snapshotSignature(after)!==snapshotSignature(candidate)){
   try{await dnr.updateDynamicRules({removeRuleIds:after.map(r=>r.id),addRules:before});}
   catch{throw Error('SIFT: installation mismatch and restoration not confirmed');}
   throw Error('SIFT: installed rules differ; previous rules restored. Diagnostic ' + JSON.stringify({ expected:candidate[0], observed:after[0] }).slice(0,1800));
 }
 return {installed:after.length,previous:before.length};
}
