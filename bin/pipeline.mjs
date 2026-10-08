import fs from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
import {seal} from '../src/seal.mjs';
import {loadThreats} from '../src/threats.mjs';
import {auditBatch,AUDIT_KIND} from '../src/audit.mjs';

function args(argv){
  const out={};for(let i=0;i<argv.length;i+=2){
    const key=argv[i];if(!/^--[a-z-]+$/.test(key)||!argv[i+1])throw new Error('INVALID_ARGUMENT');
    out[key.slice(2)]=argv[i+1];
  }
  return out;
}
const p=args(process.argv.slice(2));
const mode=p.mode||'smoke';
if(!['smoke','live'].includes(mode))throw new Error('MODE_DENIED');
const file=p.input||'examples/synthetic-candidates.jsonl';
const output=p.output||'sealed-report.json';
if(!/^[a-zA-Z0-9_./-]+$/.test(file)||file.includes('..')||output.includes('/')||output.includes('..'))throw new Error('PATH_DENIED');
const limit=Math.max(1,Math.min(25,Number(p.limit)||10));
const content=await fs.readFile(file,'utf8');
if(Buffer.byteLength(content,'utf8')>100000)throw new Error('INPUT_TOO_LARGE');
const rows=content.split(/\r?\n/).filter(Boolean).map(s=>JSON.parse(s));
if(rows.length>50||rows.length>limit)throw new Error('INPUT_EXCEEDS_RUN_LIMIT');
let publicPem;
if(mode==='live'){
  // Never allow prospect crawling on the user's Windows device or GitHub Actions.
  // This is for a separately authorized, permitted Linux environment only.
  if(process.platform==='win32')throw new Error('WINDOWS_LIVE_SCAN_DENIED');
  if(process.env.GITHUB_ACTIONS==='true')throw new Error('GITHUB_ACTIONS_LIVE_SCAN_DENIED');
  if(process.env.ISOLATED_RESEARCH_APPROVED!=='true'||
    process.env.AUDIT_APPROVAL_PHRASE!=='I_APPROVE_PERMITTED_LINUX_RESEARCH')throw new Error('LIVE_AUDIT_NOT_APPROVED');
  if(rows.some(r=>r.source!=='OVERTURE_PUBLIC'))throw new Error('SOURCE_NOT_PUBLIC_OFFICIAL');
  // The bundled key is for offline synthetic smoke tests ONLY. Require a key
  // managed separately by the research operator before contacting real sites.
  const configured=process.env.RESEARCH_PUBLIC_KEY_PATH;
  if(!configured||!path.isAbsolute(configured))throw new Error('LIVE_PUBLIC_KEY_NOT_CONFIGURED');
  const keyFile=await fs.realpath(configured);
  const checkout=await fs.realpath(process.cwd());
  if(keyFile===checkout||keyFile.startsWith(checkout+path.sep))throw new Error('LIVE_PUBLIC_KEY_MUST_BE_OUTSIDE_REPOSITORY');
  publicPem=await fs.readFile(keyFile,'utf8');
  const key=crypto.createPublicKey(publicPem);
  if(key.asymmetricKeyType!=='rsa'||(key.asymmetricKeyDetails?.modulusLength??0)<3072){
    throw new Error('LIVE_PUBLIC_KEY_REQUIRES_RSA_3072');
  }
}else{
  publicPem=await fs.readFile('public-key.pem','utf8');
}
const inspected=mode==='smoke'?rows.map(r=>({id:r.id,status:'SYNTHETIC_OFFLINE_NO_SITE_CHECK',
  auditKind:AUDIT_KIND,sendAuthorized:false})):(await (async()=>{
  const threatSnapshot=await loadThreats();
  return auditBatch(rows,{denylist:threatSnapshot.denylist,threatSnapshot,max:limit});
})());
const counts={};for(const row of inspected)counts[row.status]=(counts[row.status]||0)+1;
const report={version:1,runMode:mode,auditKind:AUDIT_KIND,sendAuthorized:false,
  verifiedSendable:0,createdAt:new Date().toISOString(),items:inspected,counts};
const encrypted=seal(report,publicPem);
const encoded=JSON.stringify(encrypted)+'\n';
if(Buffer.byteLength(encoded,'utf8')>250000)throw new Error('ARTIFACT_EXCEEDS_CAP');
await fs.writeFile(output,encoded,{mode:0o600});
// Only aggregate numbers are logged publicly. URLs, names, contacts and sensitive data are never logged.
console.log(JSON.stringify({event:'ENCRYPTED_PUBLIC_DIRECTORY_REPORT',mode,records:inspected.length,
  countByStatus:counts,encryptedArtifact:true,sendAuthorized:false,paidApiCalls:0}));
