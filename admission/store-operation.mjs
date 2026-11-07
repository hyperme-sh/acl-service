// Internal protocol. The adapter loads head, generation and rows from trusted storage.
import {createHash, createPublicKey, verify} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {parseObjectId, parsePrincipalId} from 'sociacl-ids';

// Same serialized keyring and envelope bounds as SociACL contract/keyring-limits.ts.
const keyringMax = 512 * 1024;
const recoveryHeaderBytes = 33;
const recoveryMax = recoveryHeaderBytes + 12 + keyringMax + 16 + 64;
const deliveryMax = 1 + 65 + 12 + keyringMax + 16;

function requireValue(condition) {
  if (!condition) throw Error('store-rejected');
}

function fields(value, names) {
  requireValue(value && Object.keys(value).length === names.length &&
    names.every(name => Object.hasOwn(value, name)));
}

function hex(value, maxBytes) {
  return typeof value === 'string' && value.length > 0 && value.length <= maxBytes * 2 &&
    value.length % 2 === 0 && !/[^0-9a-f]/u.test(value);
}

// store-write-v1 uses four-byte little-endian lengths for UTF-8 fields.
function message(fields) {
  return Buffer.concat(fields.flatMap(field => {
    const bytes = Buffer.from(field, 'utf8');
    const length = Buffer.alloc(4);
    length.writeUInt32LE(bytes.length);
    return [length, bytes];
  }));
}
function digest(fields) {
  return createHash('sha256').update(message(fields)).digest('hex');
}
function recoveryHash(row) {
  return digest([row.principal, String(row.rotationSeq), row.signingPub, row.epub, row.bytesHex]);
}
function wrapHash(row) {
  return digest(['sociacl-wrap-row-v1', row.principal, row.wrapId, row.epub, row.class,
    row.ciphertextHex, row.signature]);
}

function apply({principal, kind, head, generation, rows, operation}) {
  requireValue(Number.isSafeInteger(generation) && generation >= 0 && generation < Number.MAX_SAFE_INTEGER);
  const {action, signature} = operation;
  function authorize(target, hash, predecessor, cls) {
    requireValue(hex(signature, 64) && signature.length === 128);
    // SociACL's store signature is canonical low-S P-256, compact r||s.
    const halfOrder = 0x7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8n;
    requireValue(BigInt('0x' + signature.slice(64)) <= halfOrder);
    const [x, y] = head.currentKey.split('.');
    const key = createPublicKey({key: {kty: 'EC', crv: 'P-256', x, y}, format: 'jwk'});
    const signed = message(['sociacl-store-write-v1', principal, action, String(target), hash,
      String(head.sequence), predecessor, cls, String(generation)]);
    requireValue(verify('sha256', signed, {key, dsaEncoding: 'ieee-p1363'}, Buffer.from(signature, 'hex')));
  }

  if (kind === 'wraps') {
    if (action === 'put') {
      fields(operation, ['action','row','signature']);
      const row = operation.row;
      fields(row, ['principal','wrapId','epub','class','ciphertextHex','signature']);
      requireValue(row.principal === principal && parseObjectId(row.wrapId).ok &&
        parsePrincipalId(row.epub).ok && ['genesis','delivery'].includes(row.class) &&
        hex(row.ciphertextHex, deliveryMax) && hex(row.signature, 64) && row.signature.length === 128);
      const old = rows[row.wrapId];
      requireValue(old ? old.class === row.class : Object.keys(rows).length < 64);
      authorize(row.wrapId, wrapHash(row), old ? wrapHash(old) : 'none', row.class);
      rows[row.wrapId] = row;
    } else {
      fields(operation, ['action','wrapId','signature']);
      requireValue(action === 'delete' && parseObjectId(operation.wrapId).ok);
      const old = rows[operation.wrapId];
      requireValue(old?.class === 'delivery');
      authorize(old.wrapId, wrapHash(old), wrapHash(old), old.class);
      delete rows[old.wrapId];
    }
  } else if (kind === 'recovery') {
    if (action === 'put') {
      fields(operation, ['action','row','signature']);
      const row = operation.row;
      fields(row, ['principal','rotationSeq','signingPub','epub','bytesHex']);
      requireValue(row.principal === principal && parsePrincipalId(row.signingPub).ok &&
        parsePrincipalId(row.epub).ok && hex(row.bytesHex, recoveryMax));
      const bytes = Buffer.from(row.bytesHex, 'hex');
      requireValue(bytes.length >= recoveryHeaderBytes && bytes[0] === 1 && Number.isSafeInteger(row.rotationSeq) &&
        bytes.readBigUInt64LE(25) === BigInt(row.rotationSeq));
      const current = row.rotationSeq === head.sequence;
      requireValue(current || row.rotationSeq === head.sequence + 1);
      requireValue(!rows.current || rows.current.rotationSeq <= head.sequence);
      if (current) requireValue(row.signingPub === head.currentKey &&
        (head.currentEpub === null || row.epub === head.currentEpub));
      const slot = current ? 'current' : 'pending';
      authorize(row.rotationSeq, recoveryHash(row), rows[slot] ? recoveryHash(rows[slot]) : 'none', 'none');
      rows[slot] = row;
      if (current) delete rows.pending;
    } else if (action === 'commit') {
      fields(operation, ['action','signature']);
      const row = rows.pending;
      requireValue(row && row.rotationSeq === head.sequence && row.signingPub === head.currentKey &&
        row.epub === head.currentEpub);
      authorize(head.sequence, recoveryHash(row), rows.current ? recoveryHash(rows.current) : 'none', 'none');
      rows.current = row;
      delete rows.pending;
    } else {
      fields(operation, ['action','rotationSeq','signature']);
      requireValue(action === 'delete' && Number.isSafeInteger(operation.rotationSeq));
      const slot = rows.current?.rotationSeq === operation.rotationSeq ? 'current' : 'pending';
      const row = rows[slot];
      requireValue(row && row.rotationSeq === operation.rotationSeq);
      authorize(row.rotationSeq, recoveryHash(row), recoveryHash(row), 'none');
      delete rows[slot];
    }
  } else throw Error('unknown store');
  return rows;
}

try {
  process.stdout.write(JSON.stringify(apply(JSON.parse(readFileSync(0, 'utf8')))));
} catch {
  process.exitCode = 1;
}
