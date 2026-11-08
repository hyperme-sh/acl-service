// Isolated recipient harness. Scalars 1 and 9 belong to the public admission fixture.
import assert from "node:assert/strict";
import { createECDH } from "node:crypto";
import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

const contract = pathToFileURL(join(resolve(process.env.SOCIACL_SOURCE), "typescript/contract/account-key.ts"));
const { importGenesis, sealAccountBackup, openAccountBackup } = await import(contract.href);
const identity = JSON.parse(readFileSync(new URL("./fixture.json", import.meta.url)));
const context = {
  jwks: identity.jwks, now: identity.now, links: new Map(), revocations: [],
  policy: identity.policy, pinnedIss: new Set(identity.pinnedIss), genesisEpubBindings: [identity.binding],
  history: () => ({ ok: false, reason: "missing-history" }),
};
function scalar(value) {
  const bytes = Buffer.alloc(32);
  bytes.writeUInt32BE(value, 28);
  return bytes;
}
const account = importGenesis("ab".repeat(32), identity.genesis, scalar(1).toString("base64url"),
  identity.binding.epub, scalar(9).toString("base64url"));
const target = JSON.parse(readFileSync(new URL("./store-fixture.json", import.meta.url))).genesisWrap.row.wrapId;
const recipient = scalar(23);
if (process.argv[2] === "seal") {
  const transport = createECDH("prime256v1");
  transport.setPrivateKey(recipient);
  const point = transport.getPublicKey();
  const transportPub = [point.subarray(1, 33), point.subarray(33)].map(x => x.toString("base64url")).join(".");
  let operation;
  const store = {
    publishedAccount: () => ({ rotations: [] }), writeGeneration: () => 0,
    get: () => operation?.row,
    put: (_index, row, signature) => { operation = { action: "put", row, signature }; },
  };
  sealAccountBackup(account, transportPub, target, store, [], context);
  process.stdout.write(JSON.stringify(operation));
} else {
  assert.equal(process.argv[2], "open");
  const row = JSON.parse(readFileSync(0, "utf8"));
  assert.equal(row.class, "genesis");
  assert.equal(row.wrapId, target);
  const open = (key, candidate) => openAccountBackup(key.toString("hex"), candidate, identity.genesis, [], context);
  assert.deepEqual(open(recipient, row), account);
  assert.throws(() => open(scalar(24), row), /wrap-rejected/);
  const corrupt = Buffer.from(row.ciphertextHex, "hex");
  corrupt[corrupt.length - 1] ^= 1;
  assert.throws(() => open(recipient, { ...row, ciphertextHex: corrupt.toString("hex") }), /wrap-rejected/);
}
