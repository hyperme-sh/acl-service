import {readFileSync} from 'node:fs';
import {MAX_RESOLUTION_INPUT, formatPrincipalKey, objectRecordBytes, signWithKeyring, seeGrantBytes, grantSoul, postGrantBytes, postSoul} from 'sociacl-ids';
const f = JSON.parse(readFileSync(new URL('./fixture.json', import.meta.url)));
const owner = f.genesis, key = new Uint8Array(32); key[31] = 1;
const sign = bytes => { const value = signWithKeyring(key, bytes, owner); if (!value.ok) throw Error(value.reason); return value.value; };
const forum = `forum_${formatPrincipalKey(owner)}_${'01'.repeat(16)}`;
const object = `stmt_${formatPrincipalKey(owner)}_${'02'.repeat(16)}`;
function ownership(object) {
  const record = {object, owner, issuedAt:f.now}; record.sig = sign(objectRecordBytes(record));
  return {kind:'object', soul:object, record};
}
const grant = {owner, object, accessor:owner, stated:1, from:f.now, until:f.now+60, hamState:f.now, issuedAt:f.now};
grant.sig = sign(seeGrantBytes(grant));
const quotaRows = Array.from({length:129}, (_,i) => ownership(`stmt_${formatPrincipalKey(owner)}_${(i+16).toString(16).padStart(32,'0')}`));
const room = `room_${formatPrincipalKey(owner)}_${'03'.repeat(16)}`;
const roomRows = [ownership(room), ...['see','post'].map(kind => {
  const record = {...grant, object:room};
  record.sig = sign((kind === 'see' ? seeGrantBytes : postGrantBytes)(record));
  return {kind, soul:(kind === 'see' ? grantSoul : postSoul)(owner,room,owner), record};
})];
const fixtureId = '01234567-89ab-cdef-0123-456789abcdef';
const forumUpdate = {tenant:fixtureId, forumId:forum, principal:owner, botId:fixtureId,
  assignmentId:fixtureId, sessionId:fixtureId, taskId:fixtureId, deliveryId:fixtureId,
  sequence:1, statementId:object, status:'completed', signature:'SEA-fixture'};
forumUpdate.attestation = sign(Buffer.from(JSON.stringify(['s3rch-forum-update-v1',
  forumUpdate.tenant, forum, owner, fixtureId, fixtureId, fixtureId, fixtureId, fixtureId,
  1, object, forumUpdate.status, forumUpdate.signature])));
console.log(JSON.stringify({forumUpdate, room, roomRows, quotaRows, maxHistory:MAX_RESOLUTION_INPUT, forum, initial:ownership(forum), rows:[ownership(object), {kind:'see', soul:grantSoul(owner,object,owner), record:grant}]}));
