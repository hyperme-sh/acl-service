// Signature and projection contracts execute in CI.
import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {p256} from '@noble/curves/nist.js';
import {formatPrincipalKey,lengthPrefixed,objectRecordBytes,signWithKeyring,historyState} from 'sociacl-ids';
import {membershipAssentBytes,objectSetBytes,groupCancelBytes,membershipSoul,objectSetSoul} from 'sociacl/group';
import {groupAuthority,groupObjectAuthority} from './group-authority.mjs';
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
const object='media_'+formatPrincipalKey(owner)+'_'+'ab'.repeat(16),set='set_'+formatPrincipalKey(owner)+'_'+'cd'.repeat(16);
const objectRecord={object,owner,issuedAt:now};objectRecord.sig=sign(objectRecordBytes(objectRecord),1);
const owned={kind:'object',soul:object,record:objectRecord};
function assent(role,stated=1,hamState=1){const record={role,predicate:'same-group',set,member,setOwner:owner,stated,hamState,issuedAt:now,cancels:[]};record.sig=sign(membershipAssentBytes(record),role==='member'?2:1);return {kind:'membership',soul:membershipSoul(owner,'same-group',set,member),record};}
const record={owner,object,predicate:'same-group',set,stated:1,hamState:1,issuedAt:now,cancels:[]};record.sig=sign(objectSetBytes(record),1);
const edge={kind:'object-set',soul:objectSetSoul(owner,object,'same-group',set),record};
const rows=()=>[owned,assent('member'),assent('set'),edge];
const input=(values=rows())=>({object,set,predicate:'same-group',rows:values});
const run=(value=input(),identities=accounts)=>groupAuthority(identities,contextFor,now,value);
function cancel(kind='membership'){
 const record={kind,rowSoul:kind==='membership'?assent('member').soul:edge.soul,cancelId:'e'.repeat(64),prior:[],signer:kind==='membership'?member:owner,
  predicate:'same-group',set,member,setOwner:owner,issuedAt:now,...(kind==='object-set'?{object}:{})};
 record.sig=sign(groupCancelBytes(record),kind==='membership'?2:1);return {kind:'cancel',soul:record.rowSoul,record};
}
test('only jointly authenticated current members are projected, never the owner shortcut',()=>{
 assert.deepEqual(run().members,[member]);assert.ok(!run().members.includes(outsider));
 assert.deepEqual(run(input([owned,assent('member'),edge])).members,[]);
 assert.deepEqual(run(input([owned,assent('set'),edge])).members,[]);
 for(const row of [assent('member',0,2),assent('set',0,2),cancel(),cancel('object-set')])assert.deepEqual(run(input([...rows(),row])).members,[]);
 assert.deepEqual(run(input([owned])).members,[]);
});
test('scope, signatures, future records and incomplete histories refuse',()=>{
 for(const patch of [{object:'bad'},{set:'bad'},{predicate:'other'},{extra:1},{rows:Array(1025).fill(owned)}])assert.throws(()=>run({...input(),...patch}));
 for(const envelope of [null,{}, {...owned,extra:1},{kind:'other',soul:object,record:{}}, {...owned,soul:'wrong'}])assert.throws(()=>run(input([envelope])));
 for(const original of rows())for(const patch of [{sig:'bad'},{issuedAt:now+1}]){
  const bad=structuredClone(original);Object.assign(bad.record,patch);assert.throws(()=>run(input([owned,bad])));
 }
 for(const patch of [{set:set.slice(0,-2)+'ee'},{predicate:'named-circle'},{member:pub(4)}]){
  const bad=assent('member');Object.assign(bad.record,patch);assert.throws(()=>run(input([owned,bad])));
 }
 assert.throws(()=>run(input([])));assert.throws(()=>run(input(),new Map()));
 assert.throws(()=>run(input(),new Map([[member,accounts.get(member)]])));
 for(const patch of [{frozen:true},{genesis:{}},{entries:[{issuedAt:now+1}]}]){
  const changed=new Map(accounts);changed.set(owner,{...accounts.get(owner),...patch});assert.throws(()=>run(input(),changed));
 }
 const missing=new Map(accounts);missing.delete(member);assert.throws(()=>run(input(),missing));
 assert.throws(()=>run(input([owned,cancel()])));
});

test('epoch material keeps independent membership and object-set HAM and removals',()=>{
 const result=run(input([owned,assent('member',1,3),assent('set',1,7),edge]));
 assert.deepEqual(result.snapshot,{members:[{accessor:member,predicate:'same-group',setId:set,stated:1,hamState:7}],
  objectSet:{predicate:'same-group',setId:set,stated:1,hamState:1}});
 const removed=run(input([...rows(),cancel()]));
 assert.equal(removed.snapshot.members[0].stated,0);assert.equal(removed.snapshot.objectSet.stated,1);
 const detached=run(input([...rows(),cancel('object-set')]));
 assert.equal(detached.snapshot.members[0].stated,1);assert.equal(detached.snapshot.objectSet.stated,0);
 assert.equal(run(input([owned])).snapshot,null);
});

function scope(values=rows(),setId=set){return {predicate:'same-group',set:setId,rows:values};}
function competingScope(hamState=2){
 const setId=set.slice(0,-32)+'fa'.repeat(16),who=outsider;
 const values=[owned];
 for(const role of ['member','set']){
  const record={role,predicate:'same-group',set:setId,member:who,setOwner:owner,stated:1,hamState:1,issuedAt:now,cancels:[]};
  record.sig=sign(membershipAssentBytes(record),role==='member'?3:1);
  values.push({kind:'membership',soul:membershipSoul(owner,'same-group',setId,who),record});
 }
 const record={owner,object,predicate:'same-group',set:setId,stated:1,hamState,issuedAt:now,cancels:[]};
 record.sig=sign(objectSetBytes(record),1);
 values.push({kind:'object-set',soul:objectSetSoul(owner,object,'same-group',setId),record});
 return scope(values,setId);
}
const all=scopes=>groupObjectAuthority(accounts,contextFor,now,{object,scopes});
test('full object authority selects one winning group independent of scope order',()=>{
 const old=scope(),next=competingScope();
 for(const scopes of [[old,next],[next,old]]){
  const result=all(scopes);assert.equal(result.set,next.set);assert.deepEqual(result.members,[outsider]);
  assert.equal(result.snapshot.objectSet.hamState,2);
 }
 const revoked=competingScope();
 const withdrawal={kind:'membership',rowSoul:revoked.rows[1].soul,cancelId:'d'.repeat(64),prior:[],signer:outsider,
  predicate:'same-group',set:revoked.set,member:outsider,setOwner:owner,issuedAt:now};
 withdrawal.sig=sign(groupCancelBytes(withdrawal),3);
 revoked.rows.push({kind:'cancel',soul:withdrawal.rowSoul,record:withdrawal});
 assert.deepEqual(all([old,revoked]).members,[]);
 assert.deepEqual(all([scope([...rows(),cancel('object-set')]),next]).members,[outsider]);
 assert.deepEqual(all([scope([...rows(),cancel()])]).members,[]);
 assert.deepEqual(all([scope([...rows(),cancel('object-set')])]).members,[]);
 assert.deepEqual(all([scope([owned])]),{object,set:null,predicate:null,snapshot:null,members:[]});
 const tied=competingScope(1);
 assert.deepEqual(all([old,tied]),all([tied,old]));
});
test('full object authority refuses partial, duplicate and oversized scope input',()=>{
 for(const scopes of [[],Array(9).fill(scope()),[null],[{}],[scope(),scope()]])assert.throws(()=>all(scopes));
 assert.throws(()=>groupObjectAuthority(accounts,contextFor,now,{object,scopes:[scope()],extra:true}));
 assert.throws(()=>groupObjectAuthority(accounts,contextFor,now,{object,scopes:[scope([{large:'x'.repeat(1024*1024)}])]}));
 const bad=competingScope();bad.rows[1].record.sig='bad';assert.throws(()=>all([scope(),bad]));
});
