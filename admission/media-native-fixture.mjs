// CI-only signatures for the concrete source; production never executes this.
import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {p256} from '@noble/curves/nist.js';
import {lengthPrefixed,formatPrincipalKey,objectRecordBytes,signWithKeyring} from 'sociacl-ids';
const f=JSON.parse(readFileSync(new URL('./fixture.json',import.meta.url)));
const key=new Uint8Array(32);key[31]=1;
const point=p256.getPublicKey(key,false);
const ownerPub=Buffer.from(point.slice(1,33)).toString('base64url')+'.'+Buffer.from(point.slice(33)).toString('base64url');
if(ownerPub!==f.genesis)throw Error('fixture owner mismatch');
const object=`media_${formatPrincipalKey(f.genesis)}_${'ab'.repeat(16)}`;
const canonical=fields=>{const r=lengthPrefixed(fields);if(!r.ok)throw Error(r.reason);return r.value;};
const hash=fields=>createHash('sha256').update(canonical(fields)).digest('hex');
const sign=bytes=>Buffer.from(p256.sign(bytes,key,{prehash:true,lowS:true,format:'compact'})).toString('hex');
const until=(f.now+7200)*1000;
function grant(stated,grantRevision){
  const claims={object,owner:f.genesis,accessor:f.genesis,from:0,until,stated,epoch:1,grantRevision,itemCiphertextDigest:'a'.repeat(64)};
  const bytes=canonical(['s3rch-grant-payload-v1',object,f.genesis,'0',String(until),String(stated),'1',f.genesis,String(grantRevision),claims.itemCiphertextDigest]);
  return {claims,proof:{grantBytes:Buffer.from(bytes).toString('hex'),signature:sign(bytes)}};
}
const snapshot={entries:[{accessor:f.genesis,grantRevision:1,stated:1,from:0,until,scope:'direct',setId:'',hamState:0}]};
const aclSnapshot=hash(['s3rch-acl-snapshot-v1','0','','','','',f.genesis,'1','1','0',String(until),'direct','','0']);
const manifest={object,previousEpoch:0,epoch:1,deviceId:'fixture',keyCommitment:'fixture-commitment',settleWindowMs:3600000,aclSnapshot};
manifest.revisionId=hash(['s3rch-epoch-revision-v1',object,'1','0','fixture','fixture-commitment','3600000',aclSnapshot]);
manifest.signature=sign(canonical(['s3rch-epoch-manifest-sig-v1',manifest.revisionId]));
const finalization={object,previousEpoch:0,epoch:1,revisionId:manifest.revisionId,candidateRevisionIds:[manifest.revisionId],previousFinalizationId:''};
finalization.finalizationId=hash(['s3rch-epoch-finalization-v1',object,'1','0',manifest.revisionId,'',manifest.revisionId]);
finalization.signature=sign(canonical(['s3rch-epoch-finalization-sig-v1',finalization.finalizationId]));
const status={object,epoch:1,revisionId:manifest.revisionId,accessor:f.genesis,grantRevision:1,stated:1,
  signedAt:(f.now+3600)*1000,maxAgeMs:60000,zookie:{object,objectVersion:3,snapshotHash:aclSnapshot}};
status.signature=sign(canonical(['s3rch-epoch-status-v1',object,'1',manifest.revisionId,f.genesis,'1','1',
  String(status.signedAt),'60000',object,'3',aclSnapshot]));
const allocationRecord={object:object.slice(0,-32)+'cd'.repeat(16),owner:f.genesis,issuedAt:f.now};
const signed=signWithKeyring(key,objectRecordBytes(allocationRecord),f.genesis);
if(!signed.ok)throw Error(signed.reason);
allocationRecord.sig=signed.value;
const output={allocationRecord,identity:f,object,grant:grant(1,1),cancel:grant(0,2),epoch:{document:{manifest,snapshot},finalization},status,
  wrap:{reader:f.genesis,record:'e'.repeat(64),digest:'f'.repeat(64),epoch:1,revisionId:manifest.revisionId,readerEpub:f.binding.epub,itemDigest:'a'.repeat(64)}};
key.fill(0);console.log(JSON.stringify(output));
