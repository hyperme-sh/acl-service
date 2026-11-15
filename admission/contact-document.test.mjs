import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {p256} from '@noble/curves/nist.js';
import {lengthPrefixed,signWithKeyring,historyState} from 'sociacl-ids';
import {contactDocument} from './contact-document.mjs';
const now=1700000060;
const policy=JSON.parse(readFileSync(new URL('./fixture.json',import.meta.url))).policy;
const scalar=n=>{const bytes=new Uint8Array(32);bytes[31]=n;return bytes;};
const pub=n=>{const p=p256.getPublicKey(scalar(n),false);return Buffer.from(p.slice(1,33)).toString('base64url')+'.'+Buffer.from(p.slice(33)).toString('base64url');};
const owner=pub(1),member=pub(2),outsider=pub(3),witness=pub(9);
const take=r=>{if(!r.ok)throw Error(r.reason);return r.value;};
const sign=(bytes,n)=>take(signWithKeyring(scalar(n),bytes,pub(n)));
const jws=claims=>{
 const body=Buffer.from(JSON.stringify({alg:'ES256',kid:'test',typ:'JWT'})).toString('base64url')+'.'+Buffer.from(JSON.stringify(claims)).toString('base64url');
 return body+'.'+Buffer.from(p256.sign(Buffer.from(body),scalar(9),{lowS:false})).toString('base64url');
};
const jwks={keys:[{kty:'EC',crv:'P-256',kid:'test',x:witness.slice(0,43),y:witness.slice(44),alg:'ES256',use:'sig',key_ops:['verify'],notBefore:0,notAfter:now+7200}]};
const accounts=new Map([1,2,3].map(n=>{
 const principal=pub(n),epub=pub(n+10),issuedAt=now-60;
 const genesis={v:1,kind:'genesis-epub',principal,epub,issuedAt,
  keySig:sign(take(lengthPrefixed(['sociacl-genesis-epub-v1',principal,epub,String(issuedAt)])),n),
  attest:jws({typ:'sociacl-genesis-epub-attest-v1',principal,epub,iat:issuedAt,exp:now+600})};
 return [principal,{principal,genesis,rotations:[],entries:[],links:new Map(),ownRevokes:[]}];
}));
const contextFor=account=>({jwks,policy,pinnedIss:new Set(),links:account.links,revocations:[],genesisEpubBindings:[account.genesis],now,
 history:(principal,from,until)=>accounts.has(principal)?{ok:true,value:historyState(principal,[],from,until)}:{ok:false,reason:'missing-history'}});

const base=()=>({action:'write',owner,tenant:'tenant',source:'source',kind:'vault',revision:0,fence:'ef'.repeat(32),payload:Buffer.alloc(28,1).toString('base64')});
function signed(input=base(),key=1) {
 const bytes=Buffer.from(input.payload,'base64');
 return {...input,signature:sign(take(lengthPrefixed(['s3rch-contact-document-v1',input.tenant,input.source,input.owner,input.kind,String(input.revision),String(now),input.fence,createHash('sha256').update(bytes).digest('hex')])),key)};
}
test('current owner can sign encrypted state, other keys and changed scopes refuse',()=>{
 const input=signed();assert.equal(contactDocument(accounts,contextFor,now,input).currentKey,owner);
 for(const patch of [{tenant:'other'},{source:'other'},{owner:member},{kind:'descriptor'},{revision:1},{fence:'00'.repeat(32)},{payload:Buffer.alloc(28,2).toString('base64')},{signature:'bad'}])assert.throws(()=>contactDocument(accounts,contextFor,now,{...input,...patch}));
 assert.throws(()=>contactDocument(accounts,contextFor,now,signed(base(),2)));
 assert.throws(()=>contactDocument(accounts,contextFor,now+1,input));
});
test('unknown or incomplete owner history refuses',()=>{
 assert.throws(()=>contactDocument(new Map(),contextFor,now,signed()));
 for(const patch of [{frozen:true},{genesis:{}},{entries:[{issuedAt:now+1}]}]){
  const changed=new Map(accounts);changed.set(owner,{...accounts.get(owner),...patch});assert.throws(()=>contactDocument(changed,contextFor,now,signed()));
 }
});
test('signed disable retains a descriptor revision without an advertisement',()=>{
 const input=signed({...base(),kind:'descriptor',payload:Buffer.from(JSON.stringify({advertisement:null})).toString('base64')});
 assert.equal(contactDocument(accounts,contextFor,now,input).currentKey,owner);
 for(const value of [{}, {advertisement:{}}, {advertisement:null,extra:1}])assert.throws(()=>contactDocument(accounts,contextFor,now,signed({...base(),kind:'descriptor',payload:Buffer.from(JSON.stringify(value)).toString('base64')})));
});
test('active descriptor must match current owner and committed revision',async()=>{
 const {firstContactDescriptorBytes}=await import('sociacl-ids/first-contact');
 const advertisement={v:1,owner,issuedAt:now,descriptor:{channelId:'ab'.repeat(32),revision:1,encryptionEpub:accounts.get(owner).genesis.epub,expiresAt:now+300,maxLifetimeSeconds:300,maxMessageBytes:1024}};
 advertisement.sig=sign(firstContactDescriptorBytes(advertisement),1);
 const input=signed({...base(),kind:'descriptor',payload:Buffer.from(JSON.stringify({advertisement})).toString('base64')});
 assert.equal(contactDocument(accounts,contextFor,now,input).currentKey,owner);
 assert.throws(()=>contactDocument(accounts,contextFor,now,signed({...input,revision:1})));
});
