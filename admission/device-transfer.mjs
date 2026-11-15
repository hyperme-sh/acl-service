import {resolveStoreAccount} from 'sociacl-ids';

// Only protected owner snapshots reach this function. No uploaded history.
export function deviceTransferState(accounts, contextFor, now, principal) {
  if (!accounts.has(principal) || accounts.size > 64) throw Error('transfer-refused');
  const history = {completeThrough: now, links: [], accounts: []};
  let identity;
  for (const [owner, account] of accounts) {
    if (account.frozen || account.entries.some(row => row.issuedAt > now)) throw Error('transfer-refused');
    const diagnostics = [];
    const head = resolveStoreAccount(owner, account.rotations, contextFor(account, now), diagnostics);
    if (diagnostics.length || !head.bindingEpub || !head.currentEpub || head.rotations.length !== account.rotations.length)
      throw Error('transfer-refused');
    if (owner === principal) identity = {principal, pub: head.currentKey, epub: head.currentEpub, rotationSeq: head.rotations.length};
    history.links.push(...account.links.values());
    history.accounts.push({principal: owner, rotations: head.rotations, revocations: account.ownRevokes, genesisEpubBindings: [account.genesis]});
  }
  return {identity, history};
}
