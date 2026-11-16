import {parseEip55, parseOidcCredential, resolveStoreAccount, resolveWalletLinkNow,
  resolveOidcLinkNow, linkId} from 'sociacl-ids';
const take = result => { if (!result.ok) throw Error(result.reason); return result.value; };
export function credentialGraph(accounts, contextFor, now, credential) {
  if (!credential || typeof credential !== 'object' || Array.isArray(credential)) throw Error('credential-required');
  if (credential.kind === 'wallet') {
    if (Object.keys(credential).sort().join() !== 'address,kind') throw Error('credential-fields');
    take(parseEip55(credential.address));
  } else if (credential.kind === 'oidc') {
    if (Object.keys(credential).sort().join() !== 'iss,kind,sub,tenant') throw Error('credential-fields');
    take(parseOidcCredential({iss:credential.iss, tenant:credential.tenant, sub:credential.sub}));
  } else throw Error('credential-kind');
  if (!Number.isSafeInteger(now) || now < 0 || accounts.size < 1 || accounts.size > 64) throw Error('authority-bound');
  const heads = {}, history = {completeThrough:now, links:[], accounts:[]}, revocations = [];
  for (const [principal, account] of accounts) {
    if (account.frozen || account.entries.some(row => row.issuedAt > now)) throw Error('frozen-history');
    const diagnostics = [], head = resolveStoreAccount(principal, account.rotations, contextFor(account, now), diagnostics);
    if (diagnostics.length || !head.bindingEpub || head.rotations.length !== account.rotations.length) throw Error('invalid-history');
    heads[principal] = head.rotations.at(-1)?.seq ?? 0;
    history.links.push(...account.links.values());
    revocations.push(...account.ownRevokes);
    history.accounts.push({principal, rotations:account.rotations, revocations:account.ownRevokes, genesisEpubBindings:[account.genesis]});
  }
  const links = history.links.filter(row => credential.kind === 'wallet'
    ? row.kind === 'wallet' && row.address === credential.address
    : row.kind === 'oidc' && row.cred.iss === credential.iss && row.cred.tenant === credential.tenant && row.cred.sub === credential.sub);
  if (links.length > 128 || revocations.length > 1024 || history.links.length > 4096) throw Error('credential-capacity');
  // Test every candidate independently. Newest-wins cannot hide two eligible identities.
  const principals = new Set();
  for (const row of links) {
    const account = accounts.get(row.principal), context = contextFor(account, now);
    const result = credential.kind === 'wallet'
      ? resolveWalletLinkNow(credential.address, [row], revocations, context)
      : resolveOidcLinkNow({iss:credential.iss, tenant:credential.tenant, sub:credential.sub}, [row], revocations, context);
    if (!result.ok && result.reason !== 'revoked-link') throw Error(result.reason);
    if (result.ok) { take(linkId(result.value)); principals.add(result.value.principal); }
  }
  if (principals.size > 1) throw Error('ambiguous-credential');
  const snapshot = {completeThrough:now, credential, links, revocations, history};
  if (Buffer.byteLength(JSON.stringify(snapshot)) > 4*1024*1024) throw Error('credential-capacity');
  return {snapshot, heads};
}
