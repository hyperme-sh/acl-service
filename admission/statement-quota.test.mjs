import test from 'node:test';
import assert from 'node:assert/strict';
import { enforceStatementQuota } from './statement-quota.mjs';
const row = (owner='a', kind='object', extra={}) => ({kind, soul:'stmt_test', record:{object:'stmt_test',owner,...extra}});
test('retained expired and cancelled statements consume their writer share', () => {
  const held = Array.from({length:128}, (_,i)=>row('a', i%2?'see':'object',{stated:0,until:0}));
  assert.throws(()=>enforceStatementQuota(held,[row()], 'a',['a','b']), /capacity/);
  enforceStatementQuota(held,[row('b')], 'b',['a','b']);
  enforceStatementQuota(held,[], 'a',['a','b']);
});
test('account count partitions rows and duplicate principals do not reduce share', () => {
  const principals = Array.from({length:64}, (_,i)=>String(i));
  enforceStatementQuota(Array(7).fill(row('0')), [row('0')], '0',principals);
  assert.throws(()=>enforceStatementQuota(Array(8).fill(row('0')), [row('0')], '0',principals), /capacity/);
  enforceStatementQuota(Array(127).fill(row()), [row()], 'a',['a','a']);
});
test('encoded bytes are bounded independently of row count', () => {
  assert.throws(()=>enforceStatementQuota([], [row('a','object',{payload:'x'.repeat(256*1024)})], 'a',['a']), /capacity/);
  enforceStatementQuota([row('b','object',{payload:'x'.repeat(256*1024)})], [row()], 'a',['a','b']);
});
test('nonstatement records do not count and unknown/mixed writers deny', () => {
  enforceStatementQuota(Array(128).fill(row('a','post')), [row()], 'a',['a']);
  enforceStatementQuota(Array(128).fill(row('a','object',{object:'forum_test'})), [row()], 'a',['a']);
  assert.throws(()=>enforceStatementQuota([], [row()], 'a',[]), /unknown/);
  assert.throws(()=>enforceStatementQuota([], [row('b')], 'a',['a','b']), /invalid/);
});
