// Cross-language signature contract fixture, generated only in CI.
import {p256} from '@noble/curves/nist.js';
import {lengthPrefixed} from 'sociacl-ids';
import {createHash} from 'node:crypto';
function canonical(fields) {
  const result = lengthPrefixed(fields);
  if (!result.ok) throw Error(result.reason);
  return result.value;
}
function digest(fields) { return createHash('sha256').update(canonical(fields)).digest('hex'); }
const key = new Uint8Array(32); key[31] = 11;
const point = p256.getPublicKey(key, false);
const ownerPub = Buffer.from(point.slice(1,33)).toString('base64url') + '.' + Buffer.from(point.slice(33)).toString('base64url');
const rows = [0,1].map(stated => {
  const proof = {object:'media-object',epoch:3,revisionId:'a'.repeat(64),accessor:'reader',
    grantRevision:7,stated,signedAt:10000,maxAgeMs:2000,
    zookie:{object:'media-object',objectVersion:4,snapshotHash:'b'.repeat(64)}};
  const bytes = lengthPrefixed(['s3rch-epoch-status-v1',proof.object,String(proof.epoch),proof.revisionId,
    proof.accessor,String(proof.grantRevision),String(proof.stated),String(proof.signedAt),String(proof.maxAgeMs),
    proof.zookie.object,String(proof.zookie.objectVersion),proof.zookie.snapshotHash]);
  if (!bytes.ok) throw Error(bytes.reason);
  // Existing Rust reference signature encoding, not a SEA JSON envelope.
  proof.signature = Buffer.from(p256.sign(bytes.value,key,{prehash:true,lowS:true,format:'compact'})).toString('hex');
  const {signedAt,maxAgeMs,signature,...context} = proof;
  // Independent cross-language fixture follows the existing reference domains.
  const snapshot = {entries:[{accessor:'reader',grantRevision:1,stated,from:0,
    until:4000000000000,scope:'direct',setId:'',hamState:0}]};
  const aclSnapshot = digest(['s3rch-acl-snapshot-v1','0','','','','',
    'reader','1',String(stated),'0','4000000000000','direct','','0']);
  const manifest = {object:'media-object',epoch:1,previousEpoch:0,deviceId:'device',
    keyCommitment:'commitment',settleWindowMs:3600000,aclSnapshot};
  manifest.revisionId = digest(['s3rch-epoch-revision-v1',manifest.object,'1','0',
    manifest.deviceId,manifest.keyCommitment,'3600000',aclSnapshot]);
  manifest.signature = Buffer.from(p256.sign(canonical(['s3rch-epoch-manifest-sig-v1',
    manifest.revisionId]),key,{prehash:true,lowS:true,format:'compact'})).toString('hex');
  const manifestExpected = {ownerPub,object:manifest.object,epoch:1,revisionId:manifest.revisionId};
  const finalizationId = digest(['s3rch-epoch-finalization-v1',manifest.object,'1','0',
    manifest.revisionId,'',manifest.revisionId]);
  const finalization = {object:manifest.object,epoch:1,previousEpoch:0,revisionId:manifest.revisionId,
    candidateRevisionIds:[manifest.revisionId],previousFinalizationId:'',finalizationId,
    signature:Buffer.from(p256.sign(canonical(['s3rch-epoch-finalization-sig-v1',finalizationId]),
      key,{prehash:true,lowS:true,format:'compact'})).toString('hex')};
  const selection = {object:manifest.object,
    manifests:[{document:{manifest,snapshot},expected:manifestExpected}],
    finalizations:[{proof:finalization,ownerPub,seenAt:100}],current:snapshot,nowMs:3600100,
    anchorFinalizationId:finalizationId,minimumEpoch:1,expectedEpoch:1,expectedRevisionId:manifest.revisionId};
  const grantExpected = {ownerPub, object:'media-object',accessor:'reader',from:100,until:200,
    stated,epoch:3,owner:'owner-account',grantRevision:7,itemCiphertextDigest:'a'.repeat(64)};
  const grantBytes = canonical(['s3rch-grant-payload-v1',grantExpected.object,grantExpected.accessor,
    '100','200',String(stated),'3',grantExpected.owner,'7',grantExpected.itemCiphertextDigest]);
  const grant = {grantBytes:Buffer.from(grantBytes).toString('hex'),
    signature:Buffer.from(p256.sign(grantBytes,key,{prehash:true,lowS:true,format:'compact'})).toString('hex')};
  return {proof,expected:{ownerPub,...context},manifest:{manifest,snapshot},manifestExpected,selection,grant,grantExpected};
});
key.fill(0);
console.log(JSON.stringify(rows));
