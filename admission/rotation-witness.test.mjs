// Native owner contract runs only in CI.
import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
const f=JSON.parse(readFileSync(new URL('./fixture.json',import.meta.url)));
const trust={jwks:f.jwks,policy:f.policy,pinnedIss:f.pinnedIss};
const {attest,...request}=f['rotate-v4-wallet'];
function run(candidate=request,entries=[f.wallet],extra={}){
 const child=spawnSync(process.execPath,[new URL('./verify.mjs',import.meta.url).pathname],{
  input:JSON.stringify({principal:f.genesis,genesis:f.binding,entries,trust,now:f.now,peers:[],rotationRequest:candidate,...extra}),encoding:'utf8'});
 return {status:child.status,value:child.status===0?JSON.parse(child.stdout):null};
}
test('native wallet rotation requests produce the exact already accepted witness claims',()=>{
 const result=run();assert.equal(result.status,0);
 const claims=JSON.parse(Buffer.from(attest.split('.')[1],'base64url'));delete claims.iat;delete claims.exp;
 assert.deepEqual(result.value.claims,claims);assert.equal(result.value.issuedAt,request.issuedAt);assert.equal(result.value.heads[f.genesis],0);
});
test('present revocation, invalid request, stale history and foreign wallet ownership refuse',()=>{
 for(const candidate of [{...request,attest},{...request,nextSig:'bad'},{...request,seq:2},
  {...request,principal:f.peerBinding.principal},{...request,issuedAt:f.now+1},
  {...request,authorizer:{kind:'oidc-fresh-login',link:request.authorizer.link}}])assert.notEqual(run(candidate).status,0);
 for(const revoke of [f.revoke,f['offline-current-key-revoke']])assert.notEqual(run(request,[f.wallet,revoke]).status,0);
 for(const extra of [{now:f.now+901},{genesis:{}},{entries:[f.wallet,f['rotate-v4-wallet']]},
  {peers:[{principal:f.peerBinding.principal,genesis:f.peerBinding,entries:[f.peerWalletTie]}]},
  {peers:[{principal:f.peerBinding.principal,genesis:f.peerBinding,entries:[],frozen:true}]}])assert.notEqual(run(request,undefined,extra).status,0);
});
