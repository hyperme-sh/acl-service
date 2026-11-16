// Native credential authority contracts run only in CI.
import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
const f=JSON.parse(readFileSync(new URL('./fixture.json',import.meta.url)));
const trust={jwks:f.jwks,policy:f.policy,pinnedIss:f.pinnedIss};
const wallet={kind:'wallet',address:f.wallet.address};
const oidc={kind:'oidc',...f.oidc.cred};
function run(credential=wallet,entries=[f.wallet,f.oidc],extra={}) {
 const child=spawnSync(process.execPath,[new URL('./verify.mjs',import.meta.url).pathname],{
  input:JSON.stringify({principal:f.genesis,genesis:f.binding,trust,now:f.now,entries,credentialLookup:credential,...extra}),encoding:'utf8'});
 return {status:child.status,value:child.status===0?JSON.parse(child.stdout):null};
}
test('credential-scoped links retain complete authenticated domain histories',()=>{
 for(const c of [wallet,oidc]) {
  const result=run(c);assert.equal(result.status,0);
  assert.equal(result.value.snapshot.links.length,1);
  assert.equal(result.value.snapshot.links[0].kind,c.kind);
  assert.deepEqual(result.value.snapshot.credential,c);
  assert.equal(result.value.snapshot.history.links.length,2);
  assert.equal(result.value.snapshot.history.accounts[0].principal,f.genesis);
  assert.equal(result.value.heads[f.genesis],0);
 }
});
test('revoked links remain in the complete response',()=>{
 const result=run(wallet,[f.wallet,f.revoke]);assert.equal(result.status,0);
 assert.equal(result.value.snapshot.links.length,1);
 assert.equal(result.value.snapshot.revocations.length,1);
});
test('malformed selectors and foreign or incomplete histories refuse',()=>{
 for(const c of [{},{...wallet,principal:f.genesis},{kind:'wallet',address:'bad'},{...oidc,tenant:''},{kind:'other'}])
  assert.notEqual(run(c).status,0);
 for(const extra of [{genesis:{}},{now:-1},{entries:[{...f.wallet,issuedAt:f.now+1}]},
  {peers:[{principal:f.peerBinding.principal,genesis:f.peerBinding,entries:[],frozen:true}]}])
  assert.notEqual(run(wallet,undefined,extra).status,0);
});
test('competing eligible wallet principals cannot use newest-wins',()=>{
 for (const peer of [f.peerWalletTie,f.peerWalletAfterRotation]) {
  const result=run(wallet,[f.wallet],{peers:[{principal:f.peerBinding.principal,genesis:f.peerBinding,entries:[peer]}]});
  assert.notEqual(result.status,0);
 }
});
