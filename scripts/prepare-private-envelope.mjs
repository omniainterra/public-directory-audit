#!/usr/bin/env node
// Offline-only. Never process private archives inside public GitHub Actions or on Windows.
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {addLiveKeyFingerprint} from '../src/cloudflare-envelope-bridge.mjs';

const ROOT=fs.realpathSync(fileURLToPath(new URL('../',import.meta.url)));
const inside=(p)=>p===ROOT||p.startsWith(ROOT+path.sep);
function run(){
  if(process.env.GITHUB_ACTIONS!=='false'&&process.env.GITHUB_ACTIONS)throw new Error('GITHUB_ACTIONS_PRIVATE_DATA_BLOCKED');
  if(process.platform==='win32')throw new Error('WINDOWS_PRIVATE_DATA_BLOCKED');
  if(process.argv.length!==5)throw new Error('USAGE: node scripts/prepare-private-envelope.mjs input-sealed.json live-public.pem output-envelope.json');
  const raw=process.argv.slice(2);
  const input=fs.realpathSync(raw[0]),publicKey=fs.realpathSync(raw[1]);
  const output=path.resolve(raw[2]),outputParent=fs.realpathSync(path.dirname(output));
  if(inside(input)||inside(publicKey)||inside(outputParent))throw new Error('PUBLIC_REPOSITORY_DATA_PATH_DENIED');
  if(fs.statSync(input).size>20000)throw new Error('INPUT_TOO_LARGE');
  const obj=JSON.parse(fs.readFileSync(input,'utf8'));
  const pem=fs.readFileSync(publicKey,'utf8');
  const tagged=addLiveKeyFingerprint(obj,pem);
  fs.writeFileSync(output,JSON.stringify(tagged)+'\n',{flag:'wx',mode:0o600,encoding:'utf8'});
  process.stdout.write(JSON.stringify({ok:true,encryptedOnly:true,created:true})+'\n');
}
try{run();}catch(err){
  process.stderr.write('PRIVATE_ENVELOPE_PREPARATION_FAILED: '+String(err?.message||err)+'\n');
  process.exitCode=1;
}
