// Private subprocess protocol. Policy, snapshot, clock and grant come from the adapter.
import {readFileSync} from 'node:fs';
import {
  lengthPrefixed, linkId, MAX_RESOLUTION_INPUT, resolveStoreAccount, verifyKeySignature,
  verifyOidcLink, verifyRevoke, verifyWalletLink,
} from 'sociacl-ids';

function requireResult(result) {
  if (!result.ok) throw Error(result.reason);
  return result.value;
}

function verify({principal, trust, now, genesis, entries, record, grant, signature}) {
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
    } else throw Error('unsupported-history');
  }
  const diagnostics = [];
  const head = resolveStoreAccount(principal, [], context, diagnostics);
  if (diagnostics.length || !head.bindingEpub) throw Error('invalid-genesis');
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
  // This adapter currently admits only pre-rotation records.
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
  verify(JSON.parse(readFileSync(0, 'utf8')));
} catch {
  process.exitCode = 1;
}
