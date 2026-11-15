import {validatePolicy} from './verify.mjs';
const TYPES=new Set(['script','image','xmlhttprequest','sub_frame','ping','media','stylesheet','font','object','websocket','other']);
export const RULE_START=1000;
export function compileForChromium(policy,{target='chrome',limit=20000}={}){
  if(!['chrome','edge','brave'].includes(target))throw Error('SIFT: unsupported network adapter');
  if(!Number.isInteger(limit)||limit<1||limit>28000)throw Error('SIFT: invalid rule limit');
  validatePolicy(policy);
  const ordered=[...policy.groups].sort((a,b)=>{
    const rank=g=>g.effect==='allow'?0:g.important?1:2;
    return rank(a)-rank(b);
  });
  const rules=[];let omittedDomains=0,omittedGroups=0;
  for(const group of ordered){
    const match=group.match;
    if(!match.resourceTypes.every(t=>TYPES.has(t)))throw Error('SIFT: unsupported resource type');
    const condition={
      resourceTypes:[...match.resourceTypes],
      ...(match.domainType?{domainType:match.domainType}:{}),
      ...(match.initiatorDomains?{initiatorDomains:[...match.initiatorDomains]}:{}),
      ...(match.excludedInitiatorDomains?{excludedInitiatorDomains:[...match.excludedInitiatorDomains]}:{})
    };
    for(let start=0;start<group.domains.length;start+=64){
      if(rules.length>=limit){
        omittedDomains+=Math.min(64,group.domains.length-start);
        continue;
      }
      const domains=group.domains.slice(start,start+64);
      rules.push({
        id:RULE_START+rules.length,
        priority:group.effect==='allow'?140:group.important?200:40,
        action:{type:group.effect},
        condition:{requestDomains:domains,...condition}
      });
    }
    if(rules.length>=limit && omittedDomains)omittedGroups++;
  }
  return {rules,stats:{target,ruleCount:rules.length,omittedDomains,omittedGroups,truncated:omittedDomains>0}};
}
