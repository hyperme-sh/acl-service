// Private subprocess protocol. Policy, snapshot, clock and grant come from the adapter.
import {readFileSync} from 'node:fs';
import {statementGraph} from './statement-graph.mjs';
import {delegationGraph} from './delegation-graph.mjs';
import {
  checkRotationPublish, historyState, lengthPrefixed, linkId, resolveCurrentKey, MAX_RESOLUTION_INPUT, resolveStoreAccount, resolveWalletLink, verifyKeySignature,
  verifyOidcLink, verifyRevoke, verifyWalletLink,
} from 'sociacl-ids';

function requireResult(result) {
  if (!result.ok) throw Error(result.reason);
  return result.value;
}

function verify({principal, trust, now, genesis, entries, record, grant, signature, peers, observe, graph, agentGraph}) {
  const accounts = new Map();
  const wallets = new Map();
  const revokes = new Map();
  for (const account of [{principal, genesis, entries}, ...(peers ?? [])]) {
    const links = new Map();
    const rotations = [];
    const ownRevokes = [];
    if (account.entries.length > MAX_RESOLUTION_INPUT) throw Error('history-limit');
    for (const entry of account.entries) {
      if (entry.principal !== account.principal) throw Error('wrong-principal');
      if (entry.kind === 'wallet' || entry.kind === 'oidc') {
        const id = requireResult(linkId(entry));
        links.set(id, entry);
        if (entry.kind === 'wallet') {
          if (!wallets.has(entry.address)) wallets.set(entry.address, new Map());
          wallets.get(entry.address).set(id, entry);
        }
      } else if (entry.kind === 'revoke') {
        ownRevokes.push(entry);
        if (!revokes.has(entry.linkId)) revokes.set(entry.linkId, []);
        revokes.get(entry.linkId).push(entry);
      } else if (entry.kind === 'rotate') rotations.push(entry);
      else throw Error('unsupported-history');
    }
    accounts.set(account.principal, {...account, rotations, links, ownRevokes});
  }
  if (!observe && !graph && !agentGraph && entries.length >= MAX_RESOLUTION_INPUT) throw Error('history-limit');

  function contextFor(account, until) {
    const links = new Map(account.links);
    for (const row of account.links.values()) {
      if (row.kind === 'wallet') {
        for (const [id, claim] of wallets.get(row.address)) links.set(id, claim);
      }
    }
    return {
      jwks: trust.jwks, policy: trust.policy, pinnedIss: new Set(trust.pinnedIss),
      links, revocations: account.ownRevokes.concat([...links.keys()].flatMap(id =>
        (revokes.get(id) ?? []).filter(row => row.principal !== account.principal))),
      genesisEpubBindings: [account.genesis], now: until, history: peerHistory,
    };
  }

  // Authenticate a competing owner's chain at the time requested by SociACL.
  // Unknown, frozen or circular evidence cannot establish an ownership winner.
  const visiting = new Set();
  const verified = new Map();
  function peerHistory(owner, at, until) {
    const account = accounts.get(owner);
    const key = JSON.stringify([owner, until]);
    const missing = {ok: false, reason: 'missing-history'};
    if (!account || account.frozen || until > now || visiting.has(key)) return missing;
    if (!verified.has(key)) {
      const prior = account.rotations.filter(row => row.issuedAt <= until);
      visiting.add(key);
      const replay = resolveCurrentKey(owner, prior, contextFor(account, until));
      visiting.delete(key);
      if (!replay.ok || !replay.value.bindingEpub || replay.value.rotations.length !== prior.length)
        return missing;
      verified.set(key, replay.value.rotations);
    }
    return {ok: true, value: historyState(owner, verified.get(key), at, until)};
  }

  if (graph) return JSON.stringify(statementGraph(accounts, contextFor, now, graph));
  if (agentGraph) return JSON.stringify(delegationGraph(accounts, contextFor, now, agentGraph));

  const account = accounts.get(principal);
  const {rotations} = account;
  const context = contextFor(account, now);
  const {links} = context;
  const diagnostics = [];
  const head = resolveStoreAccount(principal, rotations, context, diagnostics);
  if (observe) {
    if (!Array.isArray(peers) || !head.bindingEpub || rotations.some(row => row.issuedAt > now))
      throw Error('incomplete-history');
    return JSON.stringify({currentKey: head.currentKey, currentEpub: head.currentEpub,
      sequence: head.rotations.at(-1)?.seq ?? 0, diagnostics});
  }
  if (head.rotations.length !== rotations.length || !head.bindingEpub) throw Error('invalid-genesis');
  if (grant) {
    const message = requireResult(lengthPrefixed([
      'acl-service-history-enrollment-v1', grant.authority, principal, grant.nonce,
      String(grant.expires_at), requireResult(linkId(genesis)),
    ]));
    requireResult(verifyKeySignature(principal, signature, message));
    return;
  }

  if (record.principal !== principal || record.issuedAt < genesis.issuedAt ||
      record.issuedAt > now) throw Error('invalid-principal-or-time');
  if (record.kind === 'rotate') {
    const wallet = record.authorizer?.kind === 'wallet';
    if (wallet && !Array.isArray(peers)) throw Error('missing-wallet-index');
    const combined = resolveCurrentKey(principal, [...rotations, record], context);
    if (!combined.ok && combined.reason === 'rotation-fork') return 'fork';
    const next = requireResult(combined);
    if (next.rotations.length !== rotations.length + 1 || !next.bindingEpub)
      throw Error('rotation-did-not-advance');
    const publishContext = {...context, history: (owner, at, until) =>
      owner === principal && until <= now
        ? {ok: true, value: historyState(principal, head.rotations, at, until)}
        : context.history(owner, at, until)};
    if (wallet) {
      const authorizer = links.get(record.authorizer.link);
      const currentOwner = requireResult(resolveWalletLink(authorizer.address,
        [...links.values()], context.revocations, publishContext));
      if (currentOwner.principal !== principal ||
          requireResult(linkId(currentOwner)) !== record.authorizer.link) throw Error('wallet-owner');
    }
    requireResult(checkRotationPublish(record, [], principal, rotations, publishContext));
    return;
  }
  // Late evidence cannot change the historical basis of an admitted transition.
  if (head.rotations.length && record.issuedAt <= head.rotations.at(-1).issuedAt)
    throw Error('precedes-current-key');

  const key = {key: head.currentKey, currentKey: head.currentKey, retainedLinks: null};
  const id = requireResult(linkId(record));
  if (links.has(id) || context.revocations.some(r => requireResult(linkId(r)) === id))
    throw Error('duplicate-record');
  switch (record.kind) {
    case 'wallet':
      requireResult(verifyWalletLink(record, trust.jwks, trust.policy, now, key));
      break;
    case 'oidc':
      requireResult(verifyOidcLink(record, trust.jwks, context.pinnedIss, now, key));
      break;
    case 'revoke':
      requireResult(verifyRevoke(record, head.currentKey, trust.jwks, now));
      break;
    default:
      throw Error('unsupported-record');
  }
}

try {
  const outcome = verify(JSON.parse(readFileSync(0, 'utf8')));
  process.stdout.write(outcome ?? 'accepted');
} catch {
  process.exitCode = 1;
}
