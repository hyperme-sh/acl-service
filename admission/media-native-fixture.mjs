// CI-only signatures for the concrete source; production never executes this.
import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {p256} from '@noble/curves/nist.js';
import {lengthPrefixed,formatPrincipalKey,objectRecordBytes,signWithKeyring} from 'sociacl-ids';
import {objectSetBytes,objectSetSoul,membershipAssentBytes,membershipSoul} from 'sociacl/group';
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
const groupPolicy={owner:f.genesis,setId:object.replace('media_','set_'),predicate:'same-group',settleWindowMs:3600000,configRevision:2};
groupPolicy.signature=sign(canonical(['s3rch-group-epoch-config-v1',groupPolicy.owner,groupPolicy.setId,groupPolicy.predicate,
  String(groupPolicy.settleWindowMs),String(groupPolicy.configRevision)]));
const groupPolicyDigest=hash(['s3rch-group-epoch-config-v1',groupPolicy.owner,groupPolicy.setId,groupPolicy.predicate,
  String(groupPolicy.settleWindowMs),String(groupPolicy.configRevision)]);
const groupObjectRecord={object,owner:f.genesis,issuedAt:f.now};
const groupSigned=signWithKeyring(key,objectRecordBytes(groupObjectRecord),f.genesis);
if(!groupSigned.ok)throw Error(groupSigned.reason);
groupObjectRecord.sig=groupSigned.value;
const groupEdges=[1,0].map((stated,index)=>{
  const row={owner:f.genesis,object,predicate:groupPolicy.predicate,set:groupPolicy.setId,
    stated,hamState:index+1,issuedAt:f.now,cancels:[]};
  const signed=signWithKeyring(key,objectSetBytes(row),f.genesis);
  if(!signed.ok)throw Error(signed.reason);
  return {kind:'object-set',soul:objectSetSoul(row.owner,object,row.predicate,row.set),record:{...row,sig:signed.value}};
});
const groupInvitations=[1,0].map((stated)=>{
  const row={role:'set',predicate:groupPolicy.predicate,set:groupPolicy.setId,member:f.genesis,
    setOwner:f.genesis,stated,hamState:1,issuedAt:f.now,cancels:[]};
  const signed=signWithKeyring(key,membershipAssentBytes(row),f.genesis);
  if(!signed.ok)throw Error(signed.reason);
  return {kind:'membership',soul:membershipSoul(row.setOwner,row.predicate,row.set,row.member),record:{...row,sig:signed.value}};
});
const groupMemberRows=[1,0].map(stated=>{
  const row={role:'member',predicate:groupPolicy.predicate,set:groupPolicy.setId,member:f.genesis,
    setOwner:f.genesis,stated,hamState:2,issuedAt:f.now,cancels:[]};
  const signed=signWithKeyring(key,membershipAssentBytes(row),f.genesis);
  if(!signed.ok)throw Error(signed.reason);
  return {kind:'membership',soul:membershipSoul(row.setOwner,row.predicate,row.set,row.member),record:{...row,sig:signed.value}};
});
const groupKeySnapshot={predicate:groupPolicy.predicate,setId:groupPolicy.setId,setOwner:f.genesis,
  ownerSigningPub:f.genesis,ownerEncryptionPub:f.binding.epub,ownerIdentityHead:0,members:[]};
const groupKeySnapshotId=hash(['s3rch-group-key-snapshot-v1',groupKeySnapshot.predicate,groupKeySnapshot.setId,
  f.genesis,f.genesis,f.binding.epub,'0','0']);
const groupKeyManifest={object:groupPolicy.setId,previousEpoch:0,epoch:1,deviceId:'group-fixture',
  keyCommitment:'a'.repeat(64),settleWindowMs:groupPolicy.settleWindowMs,aclSnapshot:groupKeySnapshotId};
groupKeyManifest.revisionId=hash(['s3rch-epoch-revision-v1',groupKeyManifest.object,'1','0',groupKeyManifest.deviceId,
  groupKeyManifest.keyCommitment,String(groupKeyManifest.settleWindowMs),groupKeySnapshotId]);
groupKeyManifest.signature=sign(canonical(['s3rch-epoch-manifest-sig-v1',groupKeyManifest.revisionId]));
const groupKeyFinalization={object:groupPolicy.setId,previousEpoch:0,epoch:1,revisionId:groupKeyManifest.revisionId,
  candidateRevisionIds:[groupKeyManifest.revisionId],previousFinalizationId:''};
groupKeyFinalization.finalizationId=hash(['s3rch-epoch-finalization-v1',groupKeyFinalization.object,'1','0',
  groupKeyManifest.revisionId,'',groupKeyManifest.revisionId]);
groupKeyFinalization.signature=sign(canonical(['s3rch-epoch-finalization-sig-v1',groupKeyFinalization.finalizationId]));
const groupKeyEpoch={document:{manifest:groupKeyManifest,snapshot:groupKeySnapshot},finalization:groupKeyFinalization};
// Independent group grant commands for the same enrolled owner. Direct grants
// remain in their own journal, including when the accessor also belongs to a group.
const itemGrantClaims={object,owner:f.genesis,accessor:f.genesis,from:(f.now+3600)*1000,
  until:(f.now+10800)*1000,stated:1,epoch:2,grantRevision:1,itemCiphertextDigest:'a'.repeat(64)};
const signItemGrant=claims=>{
  const bytes=canonical(['s3rch-grant-payload-v1',claims.object,claims.accessor,String(claims.from),
    String(claims.until),String(claims.stated),String(claims.epoch),claims.owner,String(claims.grantRevision),claims.itemCiphertextDigest]);
  return {claims,proof:{grantBytes:Buffer.from(bytes).toString('hex'),signature:sign(bytes)}};
};
const itemMemberWithdrawRecord={...groupMemberRows[1].record,issuedAt:f.now+3600};
const itemMemberWithdrawSigned=signWithKeyring(key,membershipAssentBytes(itemMemberWithdrawRecord),f.genesis);
if(!itemMemberWithdrawSigned.ok)throw Error(itemMemberWithdrawSigned.reason);
const itemMemberWithdraw={...groupMemberRows[1],record:{...itemMemberWithdrawRecord,sig:itemMemberWithdrawSigned.value}};
const itemGroupGrant=signItemGrant(itemGrantClaims);
const itemGroupCancel=signItemGrant({...itemGrantClaims,stated:0,grantRevision:2});
const itemGroupFork=signItemGrant({...itemGrantClaims,until:itemGrantClaims.until-1000});
const groupOwnerStatus={...status,zookie:{...status.zookie,objectVersion:4}};
groupOwnerStatus.signature=sign(canonical(['s3rch-epoch-status-v1',object,'1',manifest.revisionId,f.genesis,'1','1',
  String(status.signedAt),'60000',object,'4',aclSnapshot]));
const output={itemMemberWithdraw,itemGroupGrant,itemGroupCancel,itemGroupFork,groupOwnerStatus,groupKeyEpoch,groupMemberRows,groupInvitations,groupEdges,groupPolicy,groupPolicyDigest,groupObjectRecord,allocationRecord,identity:f,object,grant:grant(1,1),cancel:grant(0,2),epoch:{document:{manifest,snapshot},finalization},status,
  wrap:{reader:f.genesis,record:'e'.repeat(64),digest:'f'.repeat(64),epoch:1,revisionId:manifest.revisionId,readerEpub:f.binding.epub,itemDigest:'a'.repeat(64)}};
key.fill(0);console.log(JSON.stringify(output));
