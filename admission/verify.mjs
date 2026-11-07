// Private subprocess protocol. Policy, snapshot, clock and grant come from the adapter.
import {readFileSync} from 'node:fs';
import {
  checkRotationPublish, historyState, lengthPrefixed, linkId, resolveCurrentKey, MAX_RESOLUTION_INPUT, resolveStoreAccount, verifyKeySignature,
  verifyOidcLink, verifyRevoke, verifyWalletLink,
} from 'sociacl-ids';

function requireResult(result) {
  if (!result.ok) throw Error(result.reason);
  return result.value;
}

function verify({principal, trust, now, genesis, entries, record, grant, signature}) {
  const rotations = [];
  const links = new Map();
  const context = {
    jwks: trust.jwks, policy: trust.policy, pinnedIss: new Set(trust.pinnedIss),
    links, revocations: [], genesisEpubBindings: [genesis], now,
    history: () => ({ok: false, reason: 'missing-history'}),
  };
  if (entries.length >= MAX_RESOLUTION_INPUT) throw Error('history-limit');
  for (const entry of entries) {
    if (entry.principal !== principal) throw Error('wrong-principal');
    if (entry.kind === 'wallet' || entry.kind === 'oidc') {
      links.set(requireResult(linkId(entry)), entry);
    } else if (entry.kind === 'revoke') {
      context.revocations.push(entry);
    } else if (entry.kind === 'rotate') {
      rotations.push(entry);
    } else throw Error('unsupported-history');
  }
  const diagnostics = [];
  const head = resolveStoreAccount(principal, rotations, context, diagnostics);
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
    // Wallet selection spans principals. A principal-local ledger cannot prove it.
    if (record.authorizer?.kind !== 'oidc-fresh-login') throw Error('missing-wallet-index');
    const combined = resolveCurrentKey(principal, [...rotations, record], context);
    if (!combined.ok && combined.reason === 'rotation-fork') return 'fork';
    const next = requireResult(combined);
    if (next.rotations.length !== rotations.length + 1 || !next.bindingEpub)
      throw Error('rotation-did-not-advance');
    const publishContext = {...context, history: (owner, at, until) =>
      owner === principal && until <= now
        ? {ok: true, value: historyState(principal, head.rotations, at, until)}
        : {ok: false, reason: 'missing-history'}};
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
