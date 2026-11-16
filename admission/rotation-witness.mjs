// Private native boundary: input history/policy is supplied by the protected source.
import {createHash} from 'node:crypto';
import {checkRotationPublish,resolveStoreAccount,resolveWalletLinkNow,linkId,lengthPrefixed} from 'sociacl-ids';
const take=result=>{if(!result.ok)throw Error(result.reason);return result.value;};
export function walletRotationWitness(accounts,contextFor,now,principal,request){
 if(!request||request.principal!==principal||request.kind!=='rotate'||request.authorizer?.kind!=='wallet'||
  Object.hasOwn(request,'attest')||!Number.isSafeInteger(now)||now<0||request.issuedAt>now||!accounts.has(principal)||accounts.size>64)throw Error('rotation-request');
 const heads={};
 for(const [owner,account] of accounts){
  if(account.frozen||account.entries.some(row=>row.issuedAt>now))throw Error('frozen-history');
  const diagnostics=[],head=resolveStoreAccount(owner,account.rotations,contextFor(account,now),diagnostics);
  if(diagnostics.length||!head.bindingEpub||head.rotations.length!==account.rotations.length)throw Error('invalid-history');
  heads[owner]=head.rotations.at(-1)?.seq??0;
 }
 const account=accounts.get(principal),context=contextFor(account,now);
 const checked=take(checkRotationPublish(request,[],principal,account.rotations,context));
 const link=context.links.get(checked.authorizer.link);
 const owner=take(resolveWalletLinkNow(link.address,[...context.links.values()],context.revocations,context));
 if(owner.principal!==principal||take(linkId(owner))!==checked.authorizer.link)throw Error('wallet-owner');
 const proof=checked.authorizer.siwe;
 const siweHash=createHash('sha256').update(take(lengthPrefixed(['sociacl-siwe-proof-v1',proof.message,proof.signature]))).digest('hex');
 return {issuedAt:checked.issuedAt,heads,claims:{typ:'sociacl-rotate-attest-v4',principal,nextKey:checked.nextKey,nextEpub:checked.nextEpub,
  seq:checked.seq,auth:'wallet',linkId:checked.authorizer.link,retainedLinks:checked.retainedLinks,siweHash}};
}
