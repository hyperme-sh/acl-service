// Cryptographic verifier contract: CI only.
import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {execFileSync} from 'node:child_process';
import {delegationGraph} from './delegation-graph.mjs';
const f = JSON.parse(readFileSync(new URL('./fixture.json', import.meta.url)));
const records = JSON.parse(execFileSync(process.execPath, [new URL('./delegation-fixture.mjs', import.meta.url).pathname]));
const account = {principal:f.genesis, genesis:f.binding, rotations:[], links:new Map(), ownRevokes:[], entries:[]};
const accounts = new Map([[f.genesis,account]]);
const contextFor = a => ({jwks:f.jwks, policy:f.policy, pinnedIss:new Set(f.pinnedIss), links:a.links,
  revocations:a.ownRevokes, genesisEpubBindings:[a.genesis], now:f.now,
  history:()=>({ok:false,reason:'missing-history'})});
const graph = (rows=[], candidates=[]) => ({audience:records.audience, rows, candidates});
const run = (g, a=accounts) => delegationGraph(a,contextFor,f.now,g);
test('retained and candidate signatures, deduplication and permanent cancellation', () => {
  const rows = [records.delegations[0], records.revocations[0]];
  assert.equal(run(graph([],rows)).snapshot.rows.length,2);
  assert.equal(run(graph(rows,rows)).snapshot.rows.length,2);
  assert.equal(run(graph([...rows,records.revocations[0]],[])).snapshot.rows.length,2);
  assert.equal(run(graph()).snapshot.history.accounts[0].principal,f.genesis);
  for (const kind of ['rows','candidates']) {
    const bad = structuredClone(records.delegations[0]); bad.record.sig='bad';
    assert.throws(()=>run({...graph(),[kind]:[bad]}));
  }
});
test('invalid envelope, audience, owner, history and future rows deny', () => {
  for (const audience of ['bad','http://s3r.ch','https://s3r.ch/path']) assert.throws(()=>run({...graph(),audience}));
  for (const row of [null,{}, {kind:'other',record:{}}, {kind:'delegation',record:{}}, {...records.delegations[0],extra:1}])
    assert.throws(()=>run(graph([],[row])));
  for (const patch of [{audience:'https://foreign.example'},{issuedAt:f.now+1}]) {
    const row=structuredClone(records.delegations[0]); Object.assign(row.record,patch);
    assert.throws(()=>run(graph([],[row])));
  }
  assert.throws(()=>run(graph([],records.delegations.slice(0,1)),new Map()));
  for (const patch of [{frozen:true},{entries:[{issuedAt:f.now+1}]},{genesis:{}}])
    assert.throws(()=>run(graph(),new Map([[f.genesis,{...account,...patch}]])));
  assert.throws(()=>run(graph([],records.revocations.slice(0,1))));
});
test('issuance quota leaves cancellation room', () => {
  assert.throws(()=>run(graph([],records.delegations)));
  const rows=records.delegations.slice(0,64);
  assert.equal(run(graph(rows,records.revocations.slice(0,64))).snapshot.rows.length,128);
});
