// CI-only signature from the fixed existing identity fixture; never an operator tool.
import {readFileSync} from 'node:fs';
import {lengthPrefixed,linkId,signWithKeyring} from 'sociacl-ids';
const f=JSON.parse(readFileSync(new URL('./fixture.json',import.meta.url)));
const grant=JSON.parse(readFileSync(0,'utf8'));
const id=linkId(f.binding);if(!id.ok)throw Error(id.reason);
const bytes=lengthPrefixed(['acl-service-history-enrollment-v1',grant.authority,f.genesis,grant.nonce,String(grant.expires_at),id.value]);
if(!bytes.ok)throw Error(bytes.reason);
const key=new Uint8Array(32);key[31]=1;
try {const signed=signWithKeyring(key,bytes.value,f.genesis);if(!signed.ok)throw Error(signed.reason);console.log(JSON.stringify(signed.value));}
finally {key.fill(0);}
