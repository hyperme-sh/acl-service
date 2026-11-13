import {parseAgentDelegation, parseAgentRevocation, resolveStoreAccount,
  verifySignedAt, historyState, verifyKeySignature} from 'sociacl-ids';

const take = result => { if (!result.ok) throw Error(result.reason); return result.value; };

// Called only with the adapter's complete, checkpoint-protected owner histories.
// This verifies journal admission, not agent possession or object authorization.
export function delegationGraph(accounts, contextFor, now, graph) {
  const url = new URL(graph.audience);
  if (url.protocol !== 'https:' || url.origin !== graph.audience) throw Error('bad-audience');
  const heads = {}, resolved = new Map(), history = {completeThrough: now, links: [], accounts: []};
  for (const [principal, account] of accounts) {
    if (account.frozen) throw Error('frozen-history');
    const diagnostics = [], context = contextFor(account, now);
    const head = resolveStoreAccount(principal, account.rotations, context, diagnostics);
    if (diagnostics.length || !head.bindingEpub || head.rotations.length !== account.rotations.length ||
        account.entries.some(row => row.issuedAt > now)) throw Error('invalid-history');
    heads[principal] = head.rotations.at(-1)?.seq ?? 0;
    resolved.set(principal, {head, context, account});
    history.links.push(...account.links.values());
    history.accounts.push({principal, rotations: account.rotations, revocations: account.ownRevokes,
      genesisEpubBindings: [account.genesis]});
  }
  const parse = envelope => {
    if (!envelope || Object.keys(envelope).sort().join() !== 'kind,record') throw Error('bad-envelope');
    const parser = {delegation: parseAgentDelegation, revocation: parseAgentRevocation}[envelope.kind];
    if (!parser) throw Error('unsupported-record');
    const parsed = take(parser(envelope.record)), record = parsed.delegation ?? parsed.revocation;
    if (record.issuedAt > now || (envelope.kind === 'delegation' && record.audience !== graph.audience))
      throw Error('bad-authority');
    return {kind: envelope.kind, record, bytes: parsed.bytes, id: parsed.id};
  };
  const verify = (row, candidate) => {
    const owner = resolved.get(row.record.principal);
    if (!owner || row.record.issuedAt < owner.account.genesis.issuedAt) throw Error('unknown-owner');
    if (candidate) {
      take(verifySignedAt(row.record.principal, owner.account.rotations, owner.context,
        row.bytes, row.record.sig, row.record.issuedAt));
      if (row.kind === 'delegation' && row.record.expiresAt <= now) throw Error('expired');
    } else {
      // Retained expired/retired-key records are history, never present grants.
      const historical = historyState(row.record.principal, owner.head.rotations, row.record.issuedAt, now);
      take(verifyKeySignature(historical.key, row.record.sig, row.bytes));
    }
  };
  const held = graph.rows.map(parse), proposed = graph.candidates.map(parse);
  held.forEach(row => verify(row, false));
  proposed.forEach(row => verify(row, true));
  const delegations = new Map();
  for (const row of [...held, ...proposed]) if (row.kind === 'delegation') delegations.set(row.id, row.record);
  for (const row of [...held, ...proposed]) if (row.kind === 'revocation') {
    const delegation = delegations.get(row.record.delegationId);
    if (!delegation || delegation.principal !== row.record.principal || row.record.issuedAt < delegation.issuedAt)
      throw Error('unknown-delegation');
  }
  const identity = row => JSON.stringify([row.kind, Buffer.from(row.bytes).toString('base64')]);
  const seen = new Set(), cancelled = new Set(), rows = [], counts = new Map();
  let issued = 0;
  for (const row of [...held, ...proposed]) {
    const key = identity(row);
    if (seen.has(key)) continue;
    seen.add(key);
    if (row.kind === 'revocation') {
      // One authenticated cancellation is permanent; reserve cancellation
      // capacity for every admitted delegation, even at the issuance quota.
      if (cancelled.has(row.record.delegationId)) continue;
      cancelled.add(row.record.delegationId);
    } else {
      if (++issued > 512) throw Error('graph-capacity');
      const count = (counts.get(row.record.principal) ?? 0) + 1;
      if (count > 64) throw Error('owner-capacity');
      counts.set(row.record.principal, count);
    }
    rows.push({kind: row.kind, record: row.record});
  }
  const snapshot = {completeThrough: now, audience: graph.audience, history, rows};
  if (rows.length > 1024 || Buffer.byteLength(JSON.stringify(snapshot)) > 4*1024*1024) throw Error('graph-capacity');
  return {snapshot, heads};
}
