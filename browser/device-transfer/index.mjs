import {historyState, linkId} from 'sociacl-ids';
import {validateKeyring} from 'sociacl-ids/keyring';
const refused = () => {throw Error('transfer-authority-refused');};
const same = (a,b) => stable(a) === stable(b);
const stable = value => JSON.stringify(value, function(_,v) {
  return v && typeof v === 'object' && !Array.isArray(v) ? Object.fromEntries(Object.keys(v).sort().map(k=>[k,v[k]])) : v;
});

/** Requests carry public identities only. This adapter never sends keyring bytes. */
export function createAuthority({scope, request, now = Date.now}) {
  scope = structuredClone(scope);
  const checkpoints = new Map();
  let closed = false;
  async function read(operation, body, identity, binding) {
    try {
      if (closed) refused();
      const raw = await request(operation, structuredClone(body));
      if (closed || JSON.stringify(raw).length > 4 * 1024 * 1024) refused();
      const value = structuredClone(raw), time = now(), checkpoint = value.checkpoint;
      if (!same(value.scope, scope) || !same(value.identity, identity) || !same(value.binding, binding)
          || !Number.isSafeInteger(value.at) || value.at * 1000 > time
          || !checkpoint || Object.keys(checkpoint).sort().join() !== 'revision,validUntil'
          || !/^[a-f0-9]{64}$/.test(checkpoint.revision) || !Number.isSafeInteger(checkpoint.validUntil)
          || checkpoint.validUntil <= time || checkpoint.validUntil > value.at * 1000 + 5000
          || (binding && checkpoint.validUntil > binding.expiresAt)) refused();
      return value;
    } catch { return refused(); }
  }
  async function keyringState(identity) {
    const value = await read('state', {scope, identity}, identity, null);
    try {
      const {history, trust} = value;
      if (history.completeThrough !== value.at || !Array.isArray(history.accounts)
          || !history.accounts.length || history.accounts.length > 64 || !Array.isArray(history.links)
          || history.links.length > 65536) refused();
      const accounts = new Map(history.accounts.map(a=>[a.principal,a]));
      if (accounts.size !== history.accounts.length || !accounts.has(identity.principal)) refused();
      const account = accounts.get(identity.principal);
      const links = new Map(history.links.map(row=>{const id=linkId(row);if(!id.ok)refused();return [id.value,row];}));
      const context = {jwks:trust.jwks, policy:trust.policy, pinnedIss:new Set(trust.pinnedIss), links,
        revocations:history.accounts.flatMap(a=>a.revocations), genesisEpubBindings:account.genesisEpubBindings,
        now:value.at, history:(principal,at,until)=>{
          const owner=accounts.get(principal);
          if (!owner || until > value.at || closed || now() >= value.checkpoint.validUntil) return {ok:false,reason:'missing-history'};
          // The protected ACL source has authenticated these complete histories.
          return {ok:true,value:historyState(principal,owner.rotations,at,until)};
        }};
      return ()=>{
        if (closed || now() < value.at * 1000 || now() >= value.checkpoint.validUntil) refused();
        return {rotations:account.rotations,context};
      };
    } catch { return refused(); }
  }
  return {
    keyringState,
    async validateKeyring(bytes, identity) {
      try { validateKeyring(bytes, identity, await keyringState(identity)); } catch { refused(); }
    },
    async current(binding) {
      try {
        if (!same(binding.scope, scope) || binding.expiresAt <= now()) refused();
        const key = binding.transcript, previous = checkpoints.get(key);
        if (!previous && checkpoints.size >= 16) refused();
        const body = {binding, ...(previous ? {expectedRevision:previous} : {})};
        const value = await read('current', body, binding.identity, binding);
        if (previous && previous !== value.checkpoint.revision) refused();
        checkpoints.set(key,value.checkpoint.revision);
        return value.checkpoint;
      } catch { return refused(); }
    },
    close() {closed=true;checkpoints.clear();},
  };
}
