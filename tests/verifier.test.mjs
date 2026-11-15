import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,sign,createHash} from 'node:crypto';
import {verifyRelease} from '../src/intelligence/verify.mjs';
const pair=generateKeyPairSync('ed25519'); // Ephemeral fixture key, not a release credential.
const pin={keyId:'fixture-key-01',publicKeyBase64:pair.publicKey.export({format:'der',type:'spki'}).subarray(-32).toString('base64')};
const now=Date.now();
const policy={format:'admine.network-policy.v1',sources:[{id:'test',name:'Test',url:'https://example.org/list.txt',license:'fixture'}],
groups:[{effect:'block',important:false,match:{resourceTypes:['image']},sources:['test'],domains:['tracker.example']}],
stats:{totalLines:1,supportedLines:1,skippedLines:0,duplicateLines:0,domainCount:1,groupCount:1}};
function fixture(sequence=1,expiry=new Date(now+86400000).toISOString()){
 const body={format:'admine.sift.release.v1',keyId:pin.keyId,sequence,issuedAt:new Date(now-10000).toISOString(),expiresAt:expiry,policy};
 const bytes=new TextEncoder().encode(JSON.stringify(body)+'\n');
 const proof=JSON.stringify({format:'admine.sift.signature.v1',keyId:pin.keyId,length:bytes.length,sha256:createHash('sha256').update(bytes).digest('hex'),signature:sign(null,bytes,pair.privateKey).toString('base64')});
 return {bytes,proof};
}
test('valid Ed25519 release and repeat with matching stored digest',async()=>{
 const {bytes,proof}=fixture();
 const verified=await verifyRelease(bytes,proof,pin,{},now);
 assert.equal(verified.release.sequence,1);
 assert.equal((await verifyRelease(bytes,proof,pin,{sequence:1,sha256:verified.sha256},now)).sha256,verified.sha256);
});
test('tamper, expiry, rollback and unpinned key fail closed',async()=>{
 const {bytes,proof}=fixture();
 const corrupted=bytes.slice();corrupted[50]^=1;
 await assert.rejects(verifyRelease(corrupted,proof,pin,{},now));
 await assert.rejects(verifyRelease(bytes,proof,pin,{sequence:2},now));
 await assert.rejects(verifyRelease(bytes,proof,pin,{sequence:1},now));
 await assert.rejects(verifyRelease(bytes,proof,{keyId:'different',publicKeyBase64:pin.publicKeyBase64},{},now));
 const expired=fixture(2,new Date(now-1).toISOString());
 await assert.rejects(verifyRelease(expired.bytes,expired.proof,pin,{},now));
});
