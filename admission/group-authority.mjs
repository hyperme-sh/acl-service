import {resolveStoreAccount,objectPrincipal,parseObjectRecord} from 'sociacl-ids';
import {putObject} from 'sociacl/gun';
import {MemoryGroupGraph,parseMembershipAssent,parseObjectSet,parseGroupCancel,
  admitMembership,admitObjectSet,admitGroupCancel,membershipSoul,objectSetSoul,checkGroupPresentation,groupSnapshot,groupMembershipState,groupCohortSnapshot} from 'sociacl/group';
const take=result=>{if(!result.ok)throw Error(result.reason);return result.value;};

/** Pure projection from protected rows and authenticated histories. No grants or writes. */
function admittedGroupGraph(accounts,contextFor,now,input) {
  if(!Number.isSafeInteger(now)||now<0||!input||Object.keys(input).sort().join()!=='object,predicate,rows,set' ||
      !['same-group','named-circle'].includes(input.predicate)||typeof input.object!=='string'||!input.object.startsWith('media_')||
      typeof input.set!=='string'||!input.set.startsWith('set_')||!Array.isArray(input.rows)||input.rows.length>1024||
      Buffer.byteLength(JSON.stringify(input))>4*1024*1024||!accounts.size||accounts.size>64)throw Error('invalid-group-input');
  const owner=take(objectPrincipal(input.object)),setOwner=take(objectPrincipal(input.set));
  if(!accounts.has(owner)||!accounts.has(setOwner))throw Error('unknown-group-owner');
  for(const account of accounts.values()) {
    const diagnostics=[],head=resolveStoreAccount(account.principal,account.rotations,contextFor(account,now),diagnostics);
    if(account.frozen||diagnostics.length||!head.bindingEpub||!head.currentEpub||head.rotations.length!==account.rotations.length||
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
  return graph;
}

function membersOf(accounts,now,graph,object,set,predicate) {
  return [...accounts.keys()].filter(principal=>{
    const result=checkGroupPresentation(graph,set,object,principal,{stated:1,from:0,until:Number.MAX_SAFE_INTEGER},now,null,null);
    return result.allowed&&result.reason===predicate;
  }).sort();
}

export function groupAuthority(accounts,contextFor,now,input) {
  const graph=admittedGroupGraph(accounts,contextFor,now,input);
  return {object:input.object,set:input.set,predicate:input.predicate,
    members:membersOf(accounts,now,graph,input.object,input.set,input.predicate),snapshot:groupSnapshot(graph,input.object)};
}

/** Resolve all retained scopes before selecting the current object-set edge. */
export function groupObjectAuthority(accounts,contextFor,now,input) {
  if(!input||Object.keys(input).sort().join()!=='object,scopes'||!Array.isArray(input.scopes)||
      !input.scopes.length||input.scopes.length>8||Buffer.byteLength(JSON.stringify(input))>1024*1024)throw Error('invalid-group-object-input');
  const seen=new Set(),graphs=[];
  for(const scope of input.scopes) {
    if(!scope||Object.keys(scope).sort().join()!=='predicate,rows,set')throw Error('invalid-group-object-scope');
    const key=JSON.stringify([scope.predicate,scope.set]);
    if(seen.has(key))throw Error('duplicate-group-object-scope');seen.add(key);
    graphs.push(admittedGroupGraph(accounts,contextFor,now,{object:input.object,...scope}));
  }
  // All contexts share this source's trust policy. Include every enrolled party's
  // authenticated bindings/links so mergeFrom can reverify each signer itself.
  const contexts=[...accounts.values()].map(account=>contextFor(account,now));
  const resolver={ctx:{...contexts[0],
    links:new Map(contexts.flatMap(context=>[...context.links])),
    revocations:[...new Map(contexts.flatMap(context=>context.revocations).map(row=>[JSON.stringify(row),row])).values()],
    genesisEpubBindings:contexts.flatMap(context=>context.genesisEpubBindings)},
    rotations:principal=>accounts.get(principal)?.rotations};
  const graph=new MemoryGroupGraph();
  const owned=input.scopes[0].rows.find(row=>row.kind==='object');
  take(putObject(graph,owned.record,resolver));
  for(const admitted of graphs)graph.mergeFrom(admitted,resolver);
  const snapshot=groupSnapshot(graph,input.object);
  const set=snapshot?.objectSet.setId??null,predicate=snapshot?.objectSet.predicate??null;
  return {object:input.object,set,predicate,snapshot,
    members:snapshot?membersOf(accounts,now,graph,input.object,set,predicate):[]};
}

/** Current set-owner signing context; independent of the media owner's key. */
export function groupPolicyAuthority(accounts,contextFor,now,input) {
  admittedGroupGraph(accounts,contextFor,now,input);
  const owner=take(objectPrincipal(input.set)),account=accounts.get(owner);
  const diagnostics=[],head=resolveStoreAccount(owner,account.rotations,contextFor(account,now),diagnostics);
  if(diagnostics.length||!head.bindingEpub||head.rotations.length!==account.rotations.length)throw Error('invalid-group-policy-owner');
  return {owner,ownerPub:head.currentKey,setId:input.set,predicate:input.predicate};
}

/** Prepare only the named member's response to a currently admitted invitation. */
export function groupConsentAuthority(accounts,contextFor,now,input) {
  if(!input||Object.keys(input).sort().join()!=='member,object,predicate,rows,set'||!accounts.has(input.member))throw Error('invalid-group-member');
  const {member,...scope}=input;
  const graph=admittedGroupGraph(accounts,contextFor,now,scope);
  const state=groupMembershipState(graph,scope.predicate,scope.set,member);
  if(!state?.setAssent||state.setAssent.stated!==1||state.cancels.length>64||
      state.cancels.some(id=>!state.setAssent.cancels.includes(id)))throw Error('group-invitation-unavailable');
  const hamState=Math.max(state.memberAssent?.hamState??0,state.setAssent.hamState)+1;
  if(!Number.isSafeInteger(hamState))throw Error('group-order-exhausted');
  const account=accounts.get(member),diagnostics=[];
  const head=resolveStoreAccount(member,account.rotations,contextFor(account,now),diagnostics);
  if(diagnostics.length||!head.bindingEpub||head.rotations.length!==account.rotations.length)throw Error('invalid-group-member-history');
  return {memberPub:head.currentKey,state,draft:{role:'member',predicate:scope.predicate,set:scope.set,
    member,setOwner:state.setOwner,hamState,issuedAt:now,cancels:state.cancels}};
}

/** A member can withdraw its own active assent without a surviving invitation. */
export function groupWithdrawalAuthority(accounts,contextFor,now,input) {
  if(!input||Object.keys(input).sort().join()!=='member,object,predicate,rows,set'||!accounts.has(input.member))throw Error('invalid-group-member');
  const {member,...scope}=input;
  const graph=admittedGroupGraph(accounts,contextFor,now,scope);
  const state=groupMembershipState(graph,scope.predicate,scope.set,member);
  if(!state?.memberAssent||state.memberAssent.stated!==1)throw Error('group-assent-unavailable');
  const account=accounts.get(member),diagnostics=[];
  const head=resolveStoreAccount(member,account.rotations,contextFor(account,now),diagnostics);
  if(diagnostics.length||!head.bindingEpub||head.rotations.length!==account.rotations.length)throw Error('invalid-group-member-history');
  return {memberPub:head.currentKey,state,draft:{role:'member',predicate:scope.predicate,set:scope.set,
    member,setOwner:state.setOwner,hamState:state.memberAssent.hamState,issuedAt:now,cancels:[]}};
}


/** Current group membership without importing any media object's binding. */
export function groupCohortAuthority(accounts,contextFor,now,input) {
  if(!Number.isSafeInteger(now)||now<0||!input||Object.keys(input).sort().join()!=='predicate,rows,set'||
      !['same-group','named-circle'].includes(input.predicate)||typeof input.set!=='string'||!input.set.startsWith('set_')||
      !Array.isArray(input.rows)||input.rows.length>1024||Buffer.byteLength(JSON.stringify(input))>512*1024||
      !accounts.size||accounts.size>64)throw Error('invalid-group-cohort');
  const owner=take(objectPrincipal(input.set));
  if(!accounts.has(owner))throw Error('unknown-group-owner');
  const bindings=new Map();
  for(const account of accounts.values()) {
    const diagnostics=[],head=resolveStoreAccount(account.principal,account.rotations,contextFor(account,now),diagnostics);
    if(account.frozen||diagnostics.length||!head.bindingEpub||!head.currentEpub||head.rotations.length!==account.rotations.length||
        account.entries.some(row=>row.issuedAt>now))throw Error('invalid-group-history');
    bindings.set(account.principal,{pub:head.currentKey,epub:head.currentEpub});
  }
  const graph=new MemoryGroupGraph();
  for(const envelope of input.rows) {
    if(!envelope||Object.keys(envelope).sort().join()!=='kind,record,soul')throw Error('invalid-group-envelope');
    let row,signer,address,admit;
    if(envelope.kind==='membership') {
      row=take(parseMembershipAssent(envelope.record));
      if(!accounts.has(row.member))throw Error('unknown-group-member');
      signer=row.role==='member'?row.member:row.setOwner;
      address=membershipSoul(row.setOwner,row.predicate,row.set,row.member);admit=admitMembership;
    }else if(envelope.kind==='cancel') {
      row=take(parseGroupCancel(envelope.record));
      if(row.kind!=='membership')throw Error('media-edge-in-group-cohort');
      signer=row.signer;address=row.rowSoul;admit=admitGroupCancel;
    }else throw Error('media-edge-in-group-cohort');
    if(row.set!==input.set||row.predicate!==input.predicate||row.issuedAt>now||envelope.soul!==address)throw Error('wrong-group-scope');
    const account=accounts.get(signer);if(!account)throw Error('unknown-group-signer');
    take(admit(graph,row,{ctx:contextFor(account,now),rotations:principal=>accounts.get(principal)?.rotations}));
  }
  const cohort=groupCohortSnapshot(graph,input.predicate,input.set);
  if(!cohort)throw Error('group-cohort-unavailable');
  const named=new Set([owner,...cohort.members.map(row=>row.accessor)]);
  return {cohort,bindings:Object.fromEntries([...bindings].filter(([principal])=>named.has(principal)))};
}
