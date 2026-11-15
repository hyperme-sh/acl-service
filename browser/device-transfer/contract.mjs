// Packed browser adapter contract against the actual protected-verifier module.
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
import {createAuthority} from 'acl-sea-device-authority';
import {Receiver,Sender} from 'sea-device-link';
import {importKeyring,exportKeyring,closeKeyring} from 'sociacl-ids/keyring';
const root=process.env.ACL_SOURCE, sociacl=process.env.SOCIACL_SOURCE;
const records=JSON.parse(readFileSync(sociacl+'/vectors/ids/records.json'));
const v=JSON.parse(readFileSync(sociacl+'/vectors/encrypted-discovery/browser-keyring.json')).accept[1];
const {principal,pub,epub,rotationSeq}=v.fields,identity={principal,pub,epub,rotationSeq};
const scope={tenant:'12345678-1234-1234-1234-123456789abc',application:'unit',audience:'test',sourceOrigin:'https://a.example',destinationOrigin:'https://b.example'};
let now=records.context.now*1000,changed=false,unavailable=false;
const rotations=v.rotationNames.map(n=>records.accept.find(r=>r.name===n).input);
const trust={jwks:records.context.jwks,policy:records.context.policy,pinnedIss:records.context.pinnedIss};
const entries=[...records.context.links.map(([,r])=>r).filter(r=>r.principal===principal),...rotations];
const verifierInput={principal,genesis:v.genesisBindings[0],entries,peers:[],trust,now:now/1000,deviceTransfer:true};
function verified(input=verifierInput){
 const r=spawnSync(process.execPath,[root+'/admission/verify.mjs'],{input:JSON.stringify(input),encoding:'utf8'});
 if(r.status)throw Error('owner refused');return JSON.parse(r.stdout);
}
const state=verified();assert.deepEqual(state.identity,identity);
assert.throws(()=>verified({...verifierInput,entries:[...entries,{kind:'rotate',principal,issuedAt:now/1000,nextSig:'forged'}]}));
const sent=[];
const request=async(operation,body)=>{
 sent.push(structuredClone(body));if(unavailable)throw Error('unavailable');
 const binding=body.binding??null,revision=(changed?'bb':'aa').repeat(32);
 if(body.expectedRevision&&body.expectedRevision!==revision)throw Error('changed');
 return {...state,scope,binding,trust,at:now/1000,checkpoint:{revision,validUntil:Math.min(now+5000,binding?.expiresAt??Infinity)}};
};
const authority=createAuthority({scope,request,now:()=>now});
const bytes=new Uint8Array(Buffer.from(v.encodedHex,'hex'));
const receiver=await Receiver.create(scope,{now:()=>now});
const sender=await Sender.create({request:receiver.request,expectedScope:scope,identity,keyring:bytes,authority},{now:()=>now});
await receiver.bind(sender.offer);sender.confirm(receiver.comparison);receiver.confirm(sender.comparison);
let packet,done,imported;
const transport={async send(_,p){packet=p;},async receive(){return packet;},async complete(_,c){done=c;},async completed(){return done;}};
const storage={async lookup(){return null;},async commit(input){
 await input.beforeCommit();const state=await authority.keyringState(identity);
 // Real adapters perform wrapping before their FINAL callback and atomic store.
 await input.beforeCommit();assert(!input.signal.aborted);
 imported=importKeyring(input.keyring,identity,state);
}};
await sender.send(transport);await receiver.receive(transport,authority,storage);await sender.finish(transport);
assert.deepEqual(exportKeyring(imported,await authority.keyringState(identity)),bytes);closeKeyring(imported);
assert(sent.every(body=>!('keyring'in body)&&!('history'in body)));
changed=true;await assert.rejects(authority.current(sender.binding));
unavailable=true;await assert.rejects(authority.validateKeyring(bytes,identity));unavailable=false;
const expired=await authority.keyringState(identity);now+=6000;assert.throws(expired);
await assert.rejects(authority.current({...sender.binding,scope:{...scope,audience:'wrong'}}));
authority.close();await assert.rejects(authority.keyringState(identity));
console.log('Packed ACL authority + SociACL keyring + SDK contracts passed');
