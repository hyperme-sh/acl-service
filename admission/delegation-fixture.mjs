import {readFileSync} from 'node:fs';
import {p256} from '@noble/curves/nist.js';
import {agentDelegationBytes, agentRevocationBytes, parseAgentDelegation, signWithKeyring} from 'sociacl-ids';
const f = JSON.parse(readFileSync(new URL('./fixture.json', import.meta.url)));
const key = new Uint8Array(32); key[31] = 1;
const agentKey = new Uint8Array(32); agentKey[31] = 2;
const point = p256.getPublicKey(agentKey, false);
const agent = Buffer.from(point.slice(1,33)).toString('base64url') + '.' + Buffer.from(point.slice(33)).toString('base64url');
const sign = bytes => { const result = signWithKeyring(key, bytes, f.genesis); if (!result.ok) throw Error(result.reason); return result.value; };
const audience = 'https://s3r.ch';
const delegations = Array.from({length:65}, (_, i) => {
  const record = {v:1, principal:f.genesis, agent, audience, scopes:['forum:read'],
    nonce:i.toString(16).padStart(64,'0'), issuedAt:f.now, expiresAt:f.now+60};
  record.sig = sign(agentDelegationBytes(record));
  return {kind:'delegation', record};
});
const revocations = delegations.map(({record}) => {
  const parsed = parseAgentDelegation(record); if (!parsed.ok) throw Error(parsed.reason);
  const revoke = {v:1, principal:f.genesis, delegationId:parsed.value.id, issuedAt:f.now};
  revoke.sig = sign(agentRevocationBytes(revoke));
  return {kind:'revocation', record:revoke};
});
console.log(JSON.stringify({audience, delegations, revocations}));
