import {createHash} from 'node:crypto';
import {lengthPrefixed, resolveStoreAccount, verifyKeySignature} from 'sociacl-ids';
import {verifyFirstContactDescriptor} from 'sociacl-ids/first-contact';

// Private verifier input: caller binds tenant/source/owner from provisioned scope.
export function contactDocument(accounts, contextFor, now, input) {
  const {owner, tenant, source, kind, revision, payload, signature} = input;
  const account = accounts.get(owner);
  if (!account || account.frozen || account.entries.some(row => row.issuedAt > now)) throw Error('unknown-contact-owner');
  const diagnostics = [], context = contextFor(account, now);
  const head = resolveStoreAccount(owner, account.rotations, context, diagnostics);
  if (diagnostics.length || !head.bindingEpub || !head.currentEpub || head.rotations.length !== account.rotations.length) throw Error('contact-authority-unavailable');
  if (input.action === 'read') return {currentKey: head.currentKey, currentEpub: head.currentEpub, sequence: head.rotations.at(-1)?.seq ?? 0};
  if (input.action !== 'write' || !['descriptor','vault'].includes(kind) || !Number.isSafeInteger(revision) || revision < 0 ||
      typeof payload !== 'string' || payload.length > 1398104 || typeof signature !== 'string') throw Error('invalid-contact-write');
  const bytes = Buffer.from(payload, 'base64');
  const [minimum,maximum] = kind === 'descriptor' ? [1,8192] : [28,1048576];
  if (bytes.toString('base64') !== payload || bytes.length < minimum || bytes.length > maximum) throw Error('invalid-contact-payload');
  const message = lengthPrefixed(['s3rch-contact-document-v1', tenant, source, owner, kind, String(revision), String(now), createHash('sha256').update(bytes).digest('hex')]);
  if (!message.ok || !verifyKeySignature(head.currentKey, signature, message.value).ok) throw Error('contact-signature-refused');
  if (kind === 'descriptor') {
    const value = JSON.parse(new TextDecoder('utf-8', {fatal:true}).decode(bytes));
    // A signed null advertisement disables discovery without erasing the floor.
    if (!value || Object.keys(value).join() !== 'advertisement') throw Error('invalid-contact-descriptor');
    if (value.advertisement !== null) {
      const result = verifyFirstContactDescriptor(value.advertisement, owner, 1, account.rotations, context);
      if (!result.ok || result.value.descriptor.revision !== revision + 1) throw Error('contact-descriptor-refused');
    }
  }
  return {currentKey: head.currentKey, currentEpub: head.currentEpub, sequence: head.rotations.at(-1)?.seq ?? 0};
}
