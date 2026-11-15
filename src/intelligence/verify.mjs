// Independent public verification implementation; deliberately makes no network calls.
const TYPES=new Set(['script','image','xmlhttprequest','sub_frame','ping','media','stylesheet','font','object','websocket','other']);
const BANNED=new Set(['com','net','org','co.uk','com.au','co.nz','co.jp','github.io','pages.dev','cloudfront.net']);
const DOMAIN=/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const record=x=>x!==null&&typeof x==='object'&&!Array.isArray(x);
const only=(x,keys)=>record(x)&&Object.keys(x).every(k=>keys.includes(k));
const domain=x=>typeof x==='string'&&x.length<=253&&DOMAIN.test(x)&&!BANNED.has(x)&&!x.endsWith('.localhost');
const domains=(x,max)=>Array.isArray(x)&&x.length>0&&x.length<=max&&x.every(domain)&&new Set(x).size===x.length;
function b64(str,size){
  if(typeof str!=='string'||! /^[A-Za-z0-9+/]+={0,2}$/.test(str)||str.length%4)throw Error('SIFT: invalid encoding');
  let b;try{b=Uint8Array.from(atob(str),x=>x.charCodeAt(0));}catch{throw Error('SIFT: invalid encoding');}
  if(b.length!==size||btoa(String.fromCharCode(...b))!==str)throw Error('SIFT: noncanonical key/signature');
  return b;
}
export function validatePolicy(p){
  if(!only(p,['format','sources','groups','stats'])||p.format!=='admine.network-policy.v1'||
    !Array.isArray(p.sources)||p.sources.length<1||p.sources.length>12||
    !Array.isArray(p.groups)||p.groups.length<1||p.groups.length>20000||
    !only(p.stats,['totalLines','supportedLines','skippedLines','duplicateLines','domainCount','groupCount']))
    throw Error('SIFT: invalid policy');
  const ids=new Set();let count=0;
  for(const s of p.sources){
    if(!only(s,['id','name','url','license'])||typeof s.id!=='string'||! /^[a-z0-9-]{2,32}$/.test(s.id)||
      ids.has(s.id)||typeof s.name!=='string'||!s.name||s.name.length>100||
      typeof s.url!=='string'||!s.url.startsWith('https://')||s.url.length>512||
      typeof s.license!=='string'||s.license.length>200)throw Error('SIFT: invalid provenance');
    ids.add(s.id);
  }
  for(const g of p.groups){
    if(!only(g,['effect','important','match','sources','domains'])||!['block','allow'].includes(g.effect)||
      typeof g.important!=='boolean'||!only(g.match,['resourceTypes','domainType','initiatorDomains','excludedInitiatorDomains'])||
      !domains(g.domains,600000)||!Array.isArray(g.sources)||g.sources.length<1||
      new Set(g.sources).size!==g.sources.length||!g.sources.every(id=>ids.has(id)))
      throw Error('SIFT: invalid group');
    const m=g.match;
    if(!Array.isArray(m.resourceTypes)||m.resourceTypes.length<1||m.resourceTypes.length>TYPES.size||
      !m.resourceTypes.every(t=>TYPES.has(t))||new Set(m.resourceTypes).size!==m.resourceTypes.length||
      (m.domainType!==undefined&&!['firstParty','thirdParty'].includes(m.domainType))||
      (m.initiatorDomains!==undefined&&!domains(m.initiatorDomains,100))||
      (m.excludedInitiatorDomains!==undefined&&!domains(m.excludedInitiatorDomains,100)))
      throw Error('SIFT: invalid match');
    count+=g.domains.length;
    if(count>600000)throw Error('SIFT: policy budget exceeded');
  }
  if(Object.values(p.stats).some(v=>!Number.isSafeInteger(v)||v<0)||p.stats.groupCount!==p.groups.length)
    throw Error('SIFT: invalid statistics');
  return p;
}
function iso(s){return typeof s==='string'&&/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(s)&&Number.isFinite(Date.parse(s))&&new Date(s).toISOString()===s;}
export async function verifyRelease(bytes,proofText,pin,previous={},now=Date.now()){
  if(!(bytes instanceof Uint8Array)||bytes.length<100||bytes.length>8_000_000)throw Error('SIFT: payload size');
  if(!record(pin)||typeof pin.keyId!=='string'||! /^[a-z0-9-]{4,48}$/.test(pin.keyId)||!pin.publicKeyBase64)
    throw Error('SIFT: unprovisioned publisher');
  if(typeof proofText!=='string'||proofText.length>2048)throw Error('SIFT: signature document size');
  let proof;try{proof=JSON.parse(proofText);}catch{throw Error('SIFT: signature document invalid');}
  if(!only(proof,['format','keyId','signature','sha256','length'])||
    proof.format!=='admine.sift.signature.v1'||proof.keyId!==pin.keyId||
    !Number.isSafeInteger(proof.length)||proof.length!==bytes.length||
    typeof proof.sha256!=='string'||! /^[0-9a-f]{64}$/.test(proof.sha256))
    throw Error('SIFT: invalid signature metadata');
  const key=b64(pin.publicKeyBase64,32),signature=b64(proof.signature,64);
  const digest=await crypto.subtle.digest('SHA-256',bytes);
  const hash=Array.from(new Uint8Array(digest),b=>b.toString(16).padStart(2,'0')).join('');
  if(hash!==proof.sha256)throw Error('SIFT: digest mismatch');
  const pub=await crypto.subtle.importKey('raw',key,{name:'Ed25519'},false,['verify']);
  if(!await crypto.subtle.verify('Ed25519',pub,signature,bytes))throw Error('SIFT: invalid signature');
  let release;try{release=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));}
  catch{throw Error('SIFT: invalid signed bytes');}
  if(!only(release,['format','keyId','sequence','issuedAt','expiresAt','policy'])||
    release.format!=='admine.sift.release.v1'||release.keyId!==pin.keyId||
    !Number.isSafeInteger(release.sequence)||release.sequence<1||
    !iso(release.issuedAt)||!iso(release.expiresAt))throw Error('SIFT: invalid release');
  const issued=Date.parse(release.issuedAt), expires=Date.parse(release.expiresAt);
  if(expires<=issued||expires-issued>31*86400000||issued>now+300000||expires<=now)
    throw Error('SIFT: expired release');
  const last=previous.sequence??0;
  if(!Number.isSafeInteger(last)||last<0||release.sequence<last||
    (release.sequence===last&&previous.sha256!==hash))
    throw Error('SIFT: rollback or same-sequence substitution');
  validatePolicy(release.policy);
  return {release,sha256:hash};
}
