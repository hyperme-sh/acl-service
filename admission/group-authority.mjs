import {resolveStoreAccount,objectPrincipal,parseObjectRecord} from 'sociacl-ids';
import {putObject} from 'sociacl/gun';
import {MemoryGroupGraph,parseMembershipAssent,parseObjectSet,parseGroupCancel,
  admitMembership,admitObjectSet,admitGroupCancel,membershipSoul,objectSetSoul,checkGroupPresentation,groupSnapshot} from 'sociacl/group';
const take=result=>{if(!result.ok)throw Error(result.reason);return result.value;};

/** Pure projection from protected rows and authenticated histories. No grants or writes. */
export function groupAuthority(accounts,contextFor,now,input) {
  if(!Number.isSafeInteger(now)||now<0||!input||Object.keys(input).sort().join()!=='object,predicate,rows,set' ||
      !['same-group','named-circle'].includes(input.predicate)||typeof input.object!=='string'||!input.object.startsWith('media_')||
      typeof input.set!=='string'||!input.set.startsWith('set_')||!Array.isArray(input.rows)||input.rows.length>1024||
      Buffer.byteLength(JSON.stringify(input))>4*1024*1024||!accounts.size||accounts.size>64)throw Error('invalid-group-input');
  const owner=take(objectPrincipal(input.object)),setOwner=take(objectPrincipal(input.set));
  if(!accounts.has(owner)||!accounts.has(setOwner))throw Error('unknown-group-owner');
  for(const account of accounts.values()) {
    const diagnostics=[],head=resolveStoreAccount(account.principal,account.rotations,contextFor(account,now),diagnostics);
    if(account.frozen||diagnostics.length||!head.bindingEpub||head.rotations.length!==account.rotations.length||
        account.entries.some(row=>row.issuedAt>now))throw Error('invalid-group-history');
  }
  const graph=new MemoryGroupGraph();
  const resolver=signer=>{
    const account=accounts.get(signer);if(!account)throw Error('unknown-group-signer');
    return {ctx:contextFor(account,now),rotations:principal=>accounts.get(principal)?.rotations};
  };
  for(const envelope of input.rows) {
    if(!envelope||Object.keys(envelope).sort().join()!=='kind,record,soul')throw Error('invalid-group-envelope');
    const {kind,record,soul}=envelope;
    let row,signer,address,admit;
    if(kind==='object') {
      row=take(parseObjectRecord(record)).record;
      if(row.object!==input.object||row.owner!==owner)throw Error('wrong-group-object');
      signer=row.owner;address=row.object;admit=putObject;
    }else if(kind==='membership') {
      row=take(parseMembershipAssent(record));
      if(!accounts.has(row.member))throw Error('unknown-group-member');
      signer=row.role==='member'?row.member:row.setOwner;
      address=membershipSoul(row.setOwner,row.predicate,row.set,row.member);admit=admitMembership;
    }else if(kind==='object-set') {
      row=take(parseObjectSet(record));
      if(row.object!==input.object||row.owner!==owner)throw Error('wrong-group-object');
      signer=row.owner;address=objectSetSoul(row.owner,row.object,row.predicate,row.set);admit=admitObjectSet;
    }else if(kind==='cancel') {
      row=take(parseGroupCancel(record));
      if(row.kind==='object-set'&&row.object!==input.object)throw Error('wrong-group-object');
      signer=row.signer;address=row.rowSoul;admit=admitGroupCancel;
    }else throw Error('unsupported-group-row');
    if(row.issuedAt>now||soul!==address||(kind!=='object'&&(row.set!==input.set||row.predicate!==input.predicate)))throw Error('wrong-group-scope');
    take(admit(graph,row,resolver(signer)));
  }
  if(!graph.hasObject(input.object))throw Error('missing-group-object');
  const members=[...accounts.keys()].filter(principal=>{
    const result=checkGroupPresentation(graph,input.set,input.object,principal,{stated:1,from:0,until:Number.MAX_SAFE_INTEGER},now,null,null);
    return result.allowed&&result.reason===input.predicate;
  }).sort();
  return {object:input.object,set:input.set,predicate:input.predicate,members,snapshot:groupSnapshot(graph,input.object)};
}
