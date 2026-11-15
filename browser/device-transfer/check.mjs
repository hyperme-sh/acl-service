if(process.env.GITHUB_ACTIONS!=='true')throw Error('CI only');
import {execFileSync} from 'node:child_process';
import {mkdtempSync,writeFileSync,copyFileSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
const root=fileURLToPath(new URL('../../',import.meta.url));
const ids=process.env.SOCIACL_SOURCE+'/typescript/ids';
const sdk=process.env.SDK_SOURCE+'/packages/sea-device-link';
const temp=mkdtempSync(join(tmpdir(),'acl-device-contract-'));
try{
 const packs=[ids,sdk,root+'/browser/device-transfer'].map(cwd=>{
  const p=JSON.parse(execFileSync('npm',['pack','--ignore-scripts','--json','--pack-destination',temp],{cwd,encoding:'utf8'}));return join(temp,p[0].filename);
 });
 writeFileSync(join(temp,'package.json'),JSON.stringify({private:true,type:'module'}));
 execFileSync('npm',['install','--ignore-scripts','--no-audit','--no-fund',...packs],{cwd:temp,stdio:'inherit'});
 writeFileSync(join(temp,'consumer.ts'),`import {createAuthority} from 'acl-sea-device-authority';\nimport type {IdentityAdapter} from 'sea-device-link';\nexport const adapter:IdentityAdapter=createAuthority({scope:{sourceOrigin:'https://a.example',destinationOrigin:'https://b.example',tenant:'tenant',application:'app',audience:'test'},request:async()=>({})});`);
 execFileSync(process.execPath,[ids+'/node_modules/typescript/bin/tsc','--strict','--noEmit','--target','ES2022','--module','NodeNext','--moduleResolution','NodeNext','consumer.ts'],{cwd:temp,stdio:'inherit'});
 const {build}=await import(ids+'/node_modules/esbuild/lib/main.js');
 await build({entryPoints:[join(temp,'consumer.ts')],bundle:true,platform:'browser',format:'esm',write:false});
 copyFileSync(root+'/browser/device-transfer/contract.mjs',join(temp,'contract.mjs'));
 execFileSync(process.execPath,['contract.mjs'],{cwd:temp,stdio:'inherit',env:{...process.env,ACL_SOURCE:root}});
}finally{rmSync(temp,{recursive:true,force:true});}
