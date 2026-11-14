import test from 'node:test';
import assert from 'node:assert/strict';
import {authorizeAppObjectAppend} from './app-object-policy.mjs';
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
