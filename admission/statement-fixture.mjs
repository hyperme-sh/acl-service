import {readFileSync} from 'node:fs';
import {MAX_RESOLUTION_INPUT, formatPrincipalKey, objectRecordBytes, signWithKeyring, seeGrantBytes, grantSoul} from 'sociacl-ids';
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
console.log(JSON.stringify({maxHistory:MAX_RESOLUTION_INPUT, forum, initial:ownership(forum), rows:[ownership(object), {kind:'see', soul:grantSoul(owner,object,owner), record:grant}]}));
