// Signature and projection contracts execute in CI.
import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {p256} from '@noble/curves/nist.js';
import {formatPrincipalKey,lengthPrefixed,objectRecordBytes,signWithKeyring,historyState,linkId} from 'sociacl-ids';
import {membershipAssentBytes,objectSetBytes,groupCancelBytes,membershipSoul,objectSetSoul} from 'sociacl/group';
import {groupAuthority,groupObjectAuthority,groupPolicyAuthority,groupConsentAuthority,groupWithdrawalAuthority,groupCohortAuthority,groupMemberStateAuthority} from './group-authority.mjs';
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

test('policy signing context belongs to the authenticated set owner, not media owner',()=>{
 assert.deepEqual(groupPolicyAuthority(accounts,contextFor,now,input()),{owner,ownerPub:owner,setId:set,predicate:'same-group'});
 const foreignSet='set_'+formatPrincipalKey(outsider)+'_'+'ef'.repeat(16);
 const foreign={object,set:foreignSet,predicate:'named-circle',rows:[owned]};
 assert.deepEqual(groupPolicyAuthority(accounts,contextFor,now,foreign),{owner:outsider,ownerPub:outsider,setId:foreignSet,predicate:'named-circle'});
 const frozen=new Map(accounts);frozen.set(outsider,{...accounts.get(outsider),frozen:true});
 assert.throws(()=>groupPolicyAuthority(frozen,contextFor,now,foreign));
 assert.throws(()=>groupPolicyAuthority(accounts,contextFor,now,{...foreign,rows:[]}));
});

test('consent preparation is member-specific and requires a current invitation',()=>{
 const prepare=(value={...input([owned,assent('set')]),member},identities=accounts)=>groupConsentAuthority(identities,contextFor,now,value);
 const held=prepare();assert.equal(held.memberPub,member);assert.equal(held.state.stated,0);
 assert.deepEqual(held.draft,{role:'member',predicate:'same-group',set,member,setOwner:owner,hamState:2,issuedAt:now,cancels:[]});
 assert.equal(prepare({...input([...rows(),assent('member',0,4)]),member}).draft.hamState,5);
 for(const value of [null,{...input(),member:outsider},{...input(),member:owner},{...input(),member:'bad'},
   {...input(),member,extra:1},{...input([owned,assent('member')]),member},
   {...input([...rows(),assent('set',0,2)]),member},{...input([...rows(),cancel()]),member},
   {...input([owned,assent('set',1,Number.MAX_SAFE_INTEGER)]),member}])assert.throws(()=>prepare(value));
 const frozen=new Map(accounts);frozen.set(member,{...accounts.get(member),frozen:true});assert.throws(()=>prepare(undefined,frozen));
});

test('withdrawal preparation needs only the member assent, including maximum HAM',()=>{
 const prepare=(value)=>groupWithdrawalAuthority(accounts,contextFor,now,{...value,member});
 const held=prepare(input([owned,assent('member',1,Number.MAX_SAFE_INTEGER),assent('set',0,2)]));
 assert.equal(held.memberPub,member);assert.equal(held.draft.hamState,Number.MAX_SAFE_INTEGER);
 assert.deepEqual(held.draft.cancels,[]);assert.equal(held.draft.role,'member');
 assert.equal(prepare(input([owned,assent('member'),cancel()])).draft.hamState,1);
 for(const value of [input([owned]),input([owned,assent('set')]),input([owned,assent('member',0,2)])])assert.throws(()=>prepare(value));
 assert.throws(()=>groupWithdrawalAuthority(accounts,contextFor,now,null));
 assert.throws(()=>groupWithdrawalAuthority(accounts,contextFor,now,{...input(),member:pub(4)}));
});


const cohortInput=(values=[assent('member'),assent('set')])=>({predicate:'same-group',set,rows:values});
const cohort=(value=cohortInput(),identities=accounts)=>groupCohortAuthority(identities,contextFor,now,value);
test('group cohort is independent of media and excludes implicit owner membership',()=>{
 const result=cohort();assert.deepEqual(result.cohort.members,[{accessor:member,stated:1,hamState:1}]);
 assert.deepEqual(Object.keys(result.bindings).sort(),[owner,member].sort());assert.ok(!result.bindings[outsider]);
 assert.equal(result.bindings[member].head,0);assert.equal(result.bindings[member].pub,member);assert.equal(result.bindings[member].epub,pub(12));
 assert.deepEqual(cohort(cohortInput([])).cohort.members,[]);
 for(const values of [[assent('member')],[assent('set')],[assent('member'),assent('set'),cancel()],
  [assent('member',0,2),assent('set')]])assert.equal(cohort(cohortInput(values)).cohort.members[0].stated,0);
 for(const row of [owned,edge,cancel('object-set'),null,{}, {...assent('member'),extra:1}])assert.throws(()=>cohort(cohortInput([row])));
});
test('group cohort refuses wrong scopes, histories and unverified signatures',()=>{
 for(const patch of [{set:'bad'},{predicate:'other'},{extra:1},{rows:Array(1025).fill(assent('member'))}])assert.throws(()=>cohort({...cohortInput(),...patch}));
 for(const patch of [{sig:'bad'},{issuedAt:now+1},{set:set.slice(0,-2)+'ee'},{predicate:'named-circle'},{member:pub(4)}]){
  const row=assent('member');Object.assign(row.record,patch);assert.throws(()=>cohort(cohortInput([row])));
 }
 assert.throws(()=>cohort(cohortInput([{...assent('member'),soul:'wrong'}])));
 assert.throws(()=>cohort(cohortInput(),new Map()));
 assert.throws(()=>cohort(cohortInput(),new Map([[member,accounts.get(member)]])));
 for(const patch of [{frozen:true},{genesis:{}},{entries:[{issuedAt:now+1}]}]){
  const changed=new Map(accounts);changed.set(owner,{...accounts.get(owner),...patch});assert.throws(()=>cohort(cohortInput(),changed));
 }
 const missing=new Map(accounts);missing.delete(member);assert.throws(()=>cohort(cohortInput(),missing));
});


test('group cohort bindings follow current signing and encryption keys after rotation',()=>{
 const f=JSON.parse(readFileSync(new URL('./fixture.json',import.meta.url))),rotations=[f['probe-v3-oidc']];
 const context={jwks:f.jwks,policy:f.policy,pinnedIss:new Set(f.pinnedIss),links:new Map([[take(linkId(f.oidc)),f.oidc]]),
  revocations:[],genesisEpubBindings:[f.binding],now:f.now,
  history:(principal,from,until)=>principal===f.genesis?{ok:true,value:historyState(principal,rotations.filter(row=>row.issuedAt<=until),from,until)}:{ok:false,reason:'missing-history'}};
 const account={principal:f.genesis,genesis:f.binding,rotations,links:context.links,ownRevokes:[],entries:[f.oidc,...rotations]};
 const group='set_'+formatPrincipalKey(f.genesis)+'_'+'ef'.repeat(16);
 const rows=['member','set'].map(role=>{
  const record={role,predicate:'same-group',set:group,member:f.genesis,setOwner:f.genesis,stated:1,hamState:1,issuedAt:f.now,cancels:[]};
  record.sig=take(signWithKeyring(scalar(2),membershipAssentBytes(record),rotations[0].nextKey));
  return {kind:'membership',soul:membershipSoul(f.genesis,'same-group',group,f.genesis),record};
 });
 const result=groupCohortAuthority(new Map([[f.genesis,account]]),()=>context,f.now,{predicate:'same-group',set:group,rows});
 assert.deepEqual(result.bindings[f.genesis],{pub:rotations[0].nextKey,epub:rotations[0].nextEpub,head:rotations[0].seq});
 assert.notEqual(result.bindings[f.genesis].epub,f.binding.epub);
 assert.equal(result.cohort.members[0].stated,1);
 rotations[0]=f['oidc-rotate'];
 const memberState=groupMemberStateAuthority(new Map([[f.genesis,account]]),()=>context,f.now,{member:f.genesis,predicate:'same-group',set:group,rows});
 assert.equal(memberState.memberPub,rotations[0].nextKey);
 assert.equal(memberState.state.stated,1);
 assert.equal('epub' in memberState,false);
 const object=group.replace('set_','media_'),record={object,owner:f.genesis,issuedAt:f.now};
 record.sig=take(signWithKeyring(scalar(2),objectRecordBytes(record),rotations[0].nextKey));
 const withdrawal=groupWithdrawalAuthority(new Map([[f.genesis,account]]),()=>context,f.now,{object,predicate:'same-group',set:group,member:f.genesis,rows:[{kind:'object',soul:object,record},...rows]});
 assert.equal(withdrawal.memberPub,rotations[0].nextKey);
 assert.equal(withdrawal.draft.hamState,1);
 assert.throws(()=>groupCohortAuthority(new Map([[f.genesis,account]]),()=>context,f.now,{predicate:'same-group',set:group,rows}),/invalid-group-history/);
});

test('independent member state exposes both parties without implying an assent',()=>{
 const view=values=>groupMemberStateAuthority(accounts,contextFor,now,{...cohortInput(values),member});
 assert.equal(view([]).state.stated,0);
 assert.equal(view([]).state.memberAssent,null);
 assert.equal(view([]).state.setAssent,null);
 assert.equal(view([assent('set')]).state.stated,0);
 assert.equal(view([assent('member'),assent('set')]).state.stated,1);
 assert.equal(view([assent('member'),assent('set'),cancel()]).state.stated,0);
 assert.equal(view([assent('member',0,2),assent('set')]).state.stated,0);
 assert.equal(view([]).ownerPub,owner);
 assert.equal(view([]).memberPub,member);
 for(const value of [null,{...cohortInput(),member:outsider,extra:1},{...cohortInput(),member:pub(4)}])
  assert.throws(()=>groupMemberStateAuthority(accounts,contextFor,now,value));
 assert.throws(()=>view([edge]));
 const forged=assent('member');forged.record.sig='forged';assert.throws(()=>view([forged]));
});
