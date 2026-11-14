import test from 'node:test';
import assert from 'node:assert/strict';
import {authorizeAppObjectAppend, requireCurrentParentOwner} from './app-object-policy.mjs';
import {enforceStatementQuota} from './statement-quota.mjs';
const row = (kind='object', owner='alice', object='room_alice_1', extra={}) =>
  ({kind, soul:object, record:{owner, object, ...extra}});
const parent = (kind, principal) => principal === 'alice' || (principal === 'bob' && kind === 'see');
const grant = (kind, accessor, stated=1) => row(kind,'alice','room_alice_1',{accessor,stated,until:200});
test('a current parent writer creates a signed room and bounds its readers', () => {
  authorizeAppObjectAppend([row(),grant('see','bob')],[],parent,100);
  authorizeAppObjectAppend([grant('see','bob',0)],[row()],parent,100);
  for (const rows of [[row('object','bob')],[row('object','stranger')],[row(),grant('see','stranger')],
    [row(),grant('post','bob')],[row(),row('see','bob')],[row('object','alice','forum_alice_1')]])
    assert.throws(()=>authorizeAppObjectAppend(rows,[],parent,100));
  assert.throws(()=>authorizeAppObjectAppend([grant('see','bob')],[],parent,100),/missing-room-owner/);
});
test('parent cancellations remove room write authority; cancellation cannot grant access', () => {
  assert.throws(()=>authorizeAppObjectAppend([row()],[],()=>false,100),/denied/);
  authorizeAppObjectAppend([grant('post','stranger',0)],[row()],parent,100);
  assert.throws(()=>authorizeAppObjectAppend([row(),{...grant('see','bob'),record:{...grant('see','bob').record,until:3701}}],[],parent,100),/reader-denied/);
});
test('statement compatibility remains and post grants cannot be added to a statement', () => {
  const object='stmt_alice_1';
  authorizeAppObjectAppend([row('object','alice',object)],[],parent,100);
  assert.throws(()=>authorizeAppObjectAppend([row('post','alice',object)],[],parent,100));
});
test('rooms share the retained per-principal quota and have a bounded object count', () => {
  const rooms=Array.from({length:32},(_,i)=>row('object','alice',`room_alice_${i}`));
  assert.throws(()=>enforceStatementQuota(rooms,[row('object','alice','room_alice_33')],'alice',['alice']),/capacity/);
  enforceStatementQuota(rooms,[grant('see','bob')],'alice',['alice','bob']);
  const full=Array(128).fill(row('see','alice','stmt_alice_1'));
  assert.throws(()=>enforceStatementQuota(full,[row()],'alice',['alice']),/capacity/);
});


test('current parent selection retains history without trusting invalid-only ownership', () => {
  const old = row('object','alice','forum_alice_1'), fresh = {...old, record:{...old.record, sig:'current'}};
  const verify = candidate => { if (candidate.record.sig !== 'current') throw Error('retired-key'); };
  for (const held of [[old,fresh],[fresh,old]]) requireCurrentParentOwner(held,'forum_alice_1','alice',verify);
  for (const held of [[],[old],[{...fresh,record:{...fresh.record,owner:'bob'}}]])
    assert.throws(()=>requireCurrentParentOwner(held,'forum_alice_1','alice',verify),/missing-parent-owner/);
});

test('refreshed parent ownership survives real signing-key rotation with retained old rows', async () => {
  const {readFileSync} = await import('node:fs');
  const {formatPrincipalKey, objectRecordBytes, signWithKeyring, verifyObjectRecord, linkId, historyState, seeGrantBytes, grantSoul} = await import('sociacl-ids');
  const f = JSON.parse(readFileSync(new URL('./fixture.json', import.meta.url)));
  const forum = `forum_${formatPrincipalKey(f.genesis)}_${'04'.repeat(16)}`;
  const context = {jwks:f.jwks,policy:f.policy,pinnedIss:new Set(f.pinnedIss),
    links:new Map([[linkId(f.oidc).value,f.oidc]]),revocations:[],genesisEpubBindings:[f.binding],now:f.now};
  const rotations = [f['oidc-rotate']];
  context.history = (principal, at, until) => principal === f.genesis
    ? {ok:true,value:historyState(principal,rotations.filter(row=>row.issuedAt<=until),at,until)}
    : {ok:false,reason:'missing-history'};
  function ownership(n, issuedAt, object = forum) {
    const privateKey = new Uint8Array(32); privateKey[31] = n;
    const record = {object,owner:f.genesis,issuedAt};
    const signed = signWithKeyring(privateKey,objectRecordBytes(record),n === 1 ? f.genesis : rotations[0].nextKey);
    assert.ok(signed.ok); record.sig = signed.value;
    return {kind:'object',soul:object,record};
  }
  const old = ownership(1,1700000010), fresh = ownership(2,1700000040);
  const {statementGraph} = await import('./statement-graph.mjs');
  const room = forum.replace('forum_', 'room_'), oldRoom = ownership(1,1700000010,room), freshRoom = ownership(2,1700000040,room);
  const grant = {object:room,owner:f.genesis,accessor:f.genesis,stated:1,from:f.now,until:f.now+30,hamState:f.now,issuedAt:f.now};
  const nextSecret = new Uint8Array(32); nextSecret[31]=2;
  grant.sig=signWithKeyring(nextSecret,seeGrantBytes(grant),rotations[0].nextKey).value;
  const candidate={kind:'see',soul:grantSoul(f.genesis,room,f.genesis),record:grant};
  const account={genesis:f.binding,rotations,links:context.links,ownRevokes:[],entries:[f.oidc,...rotations]};
  const accounts=new Map([[f.genesis,account]]);
  const append = rows => statementGraph(accounts,()=>context,f.now,{forum,rows,candidates:[candidate],statementOnly:true});
  assert.throws(()=>append([old,fresh,oldRoom]),/missing-room-owner/);
  assert.equal(append([old,fresh,oldRoom,freshRoom]).snapshot.rows.length,5);

  const verify = candidate => {
    const result = verifyObjectRecord(candidate.record,rotations,context);
    if (!result.ok) throw Error(result.reason);
  };
  assert.throws(()=>verify(old)); verify(fresh);
  for (const held of [[old,fresh],[fresh,old]]) requireCurrentParentOwner(held,forum,f.genesis,verify);
  for (const held of [[old],[{...fresh,record:{...fresh.record,sig:old.record.sig}}]])
    assert.throws(()=>requireCurrentParentOwner(held,forum,f.genesis,verify),/missing-parent-owner/);
});
