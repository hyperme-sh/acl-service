// Uses the same authenticated identity contexts as recovery admission.
import {resolveStoreAccount, verifyObjectRecord, verifySeeGrant, verifyPostGrant,
  parseObjectRecord, parseSeeGrant, parsePostGrant, grantSoul, postSoul, objectPrincipal} from 'sociacl-ids';
const take = result => { if (!result.ok) throw Error(result.reason); return result.value; };
export function statementGraph(accounts, contextFor, now, graph) {
  const heads = {}, history = {completeThrough: now, links: [], accounts: []};
  for (const [principal, account] of accounts) {
    if (account.frozen) throw Error('frozen-history');
    const diagnostics = [], head = resolveStoreAccount(principal, account.rotations, contextFor(account, now), diagnostics);
    if (diagnostics.length || !head.bindingEpub || head.rotations.length !== account.rotations.length ||
        account.entries.some(row => row.issuedAt > now)) throw Error('invalid-history');
    heads[principal] = head.rotations.at(-1)?.seq ?? 0;
    history.links.push(...account.links.values());
    history.accounts.push({principal, rotations: account.rotations, revocations: account.ownRevokes,
      genesisEpubBindings: [account.genesis]});
  }
  const parse = envelope => {
    if (!envelope || Object.keys(envelope).sort().join() !== 'kind,record,soul') throw Error('bad-envelope');
    const {kind, record} = envelope;
    const parser = {object: parseObjectRecord, see: parseSeeGrant, post: parsePostGrant}[kind];
    if (!parser) throw Error('unsupported-acl');
    const parsed = take(parser(record)), row = parsed.record ?? parsed.grant;
    const soul = kind === 'object' ? row.object : (kind === 'see' ? grantSoul : postSoul)(row.owner, row.object, row.accessor);
    if (envelope.soul !== soul || row.issuedAt > now) throw Error('bad-address');
    return {kind, record: row, soul, bytes: parsed.bytes};
  };
  const verify = row => {
    const account = accounts.get(row.record.owner);
    if (!account) throw Error('unknown-owner');
    take(({object: verifyObjectRecord, see: verifySeeGrant, post: verifyPostGrant}[row.kind])(
      row.record, account.rotations, contextFor(account, now)));
  };
  const held = graph.rows.map(parse), proposed = graph.candidates.map(parse);
  for (const row of proposed) verify(row);
  const latest = (kind, object, accessor) => {
    const eligible = held.filter(row => row.kind === kind && row.record.object === object && row.record.accessor === accessor);
    eligible.sort((a,b) => b.record.hamState-a.record.hamState || a.record.stated-b.record.stated || Buffer.compare(a.bytes,b.bytes));
    return eligible[0];
  };
  const forumOwner = take(objectPrincipal(graph.forum));
  if (!accounts.has(forumOwner)) throw Error('unknown-forum-owner');
  const allowed = (kind, principal) => {
    if (principal === forumOwner) return true;
    const row = latest(kind, graph.forum, principal);
    if (!row || row.record.stated !== 1 || row.record.from > now || row.record.until <= now) return false;
    verify(row); return true;
  };
  if (graph.statementOnly && proposed.length) {
    const object = proposed[0].record.object, owner = proposed[0].record.owner;
    if (!object.startsWith('stmt_') || proposed.some(row => row.record.object !== object || row.record.owner !== owner || row.kind === 'post') ||
        !allowed('see', owner) || !allowed('post', owner)) throw Error('statement-denied');
    for (const row of proposed) if (row.kind === 'see' && (row.record.until > now + 3600 ||
        (row.record.stated === 1 && !allowed('see', row.record.accessor)))) throw Error('reader-denied');
  }
  // Retain every admitted cancellation and prior record. No overwriting history.
  const rows = [...held, ...proposed].map(({kind, soul, record}) => ({kind, soul, record}));
  if (rows.length > 1024) throw Error('graph-capacity');
  const snapshot = {completeThrough: now, history, rows};
  if (Buffer.byteLength(JSON.stringify(snapshot)) > 4*1024*1024) throw Error('graph-capacity');
  return {snapshot, heads};
}
