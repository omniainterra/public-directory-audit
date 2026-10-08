import fs from 'node:fs/promises';
import path from 'node:path';
import {unseal} from '../src/seal.mjs';
const [input,keyPath,output]=process.argv.slice(2);
if(!input||!keyPath||!output){console.error('Usage: node scripts/decrypt.mjs sealed-report.json /safe/location/private-key.pem /safe/location/decrypted.json');process.exit(2);}
if(path.resolve(input)===path.resolve(output))throw new Error('OUTPUT_MUST_DIFFER');
const envelope=JSON.parse(await fs.readFile(input,'utf8'));
const privatePem=await fs.readFile(keyPath,'utf8');
const data=unseal(envelope,privatePem);
await fs.writeFile(output,JSON.stringify(data,null,2)+'\n',{mode:0o600});
console.log(JSON.stringify({success:true,items:data.items?.length,warning:'PRIVATE_FILE_KEEP_OFF_PUBLIC_REPOSITORIES'}));
