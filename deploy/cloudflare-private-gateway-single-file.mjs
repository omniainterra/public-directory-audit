// Bundled, import-free Cloudflare Worker entry for manual dashboard deployment.
// Public HTTPS endpoint; encrypted D1 operations fail closed until *all* secrets
// and an explicit storage-only flag are independently provisioned. No scraping.
// No browser JS execution, marketing, forms, cron, email or outbound fetch calls.
// Generated from the two already-reviewed local modules. NEVER insert secrets here.

// Cloudflare private ledger. NO outbound network or plaintext prospect storage.
// This module is intentionally NOT imported by src/cloudflare-pilot.mjs.
// Cloudflare private ledger. NO outbound network or plaintext prospect storage.
// This module is intentionally NOT imported by src/cloudflare-pilot.mjs.
export const RESERVE_SQL=[
  'INSERT INTO audit_reservations (request_id,day_utc,created_at_utc)',
  'SELECT ?,?,? WHERE',
  '(SELECT COUNT(1) FROM audit_reservations WHERE day_utc=?) < ?',
  'AND NOT EXISTS (SELECT 1 FROM audit_reservations WHERE request_id=?)',
  'RETURNING request_id'
].join(' ');
export const FIND_RESERVATION_SQL=
  'SELECT request_id,day_utc FROM audit_reservations WHERE request_id=?';
export const STORE_SQL=[
  'INSERT INTO encrypted_reports (request_id,day_utc,payload_json,payload_sha256,created_at_utc)',
  'SELECT ?,r.day_utc,?,?,? FROM audit_reservations r WHERE r.request_id=?',
  'ON CONFLICT(request_id) DO NOTHING RETURNING request_id'
].join(' ');
export const FIND_REPORT_SQL=
  'SELECT request_id,day_utc,payload_json,payload_sha256 FROM encrypted_reports WHERE request_id=?';

export function validRequestId(value){
  return typeof value==='string'&&
    /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(value);
}
export function dailyLimit(raw){
  const text=String(raw??'');
  if(!/^(?:[1-9]|1\d|2[0-5])$/.test(text))return null;
  return Number(text);
}
export function utcDay(now){
  const date=now instanceof Date?now:new Date(now);
  if(!Number.isFinite(date.getTime()))throw new Error('INVALID_CLOCK');
  return date.toISOString().slice(0,10);
}
function decode64(value,maxLength){
  if(typeof value!=='string'||value.length<4||value.length>maxLength||
     !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value))return null;
  try{return atob(value);}catch{return null;}
}
export function validateSealedEnvelope(value,expectedKeyId){
  if(!value||typeof value!=='object'||Array.isArray(value)||!(/^[0-9a-f]{64}$/.test(expectedKeyId??'')))return false;
  const keys=Object.keys(value).sort().join(',');
  if(keys!=='ciphertext,encryptedKey,format,iv,keyId,tag,version')return false;
  if(value.version!==1||value.format!=='RSA-3072-OAEP-SHA256+AES-256-GCM'||value.keyId!==expectedKeyId)return false;
  const wrapped=decode64(value.encryptedKey,512),iv=decode64(value.iv,16);
  const tag=decode64(value.tag,24),ciphertext=decode64(value.ciphertext,11000);
  if(!wrapped||wrapped.length!==384||!iv||iv.length!==12||!tag||tag.length!==16)return false;
  if(!ciphertext||ciphertext.length<1||ciphertext.length>8192)return false;
  return true;
}
export async function digestHex(bytes){
  const hashed=await crypto.subtle.digest('SHA-256',bytes);
  return [...new Uint8Array(hashed)].map(x=>x.toString(16).padStart(2,'0')).join('');
}
export async function authenticateBearer(request,sha256Hex){
  if(typeof sha256Hex!=='string'||!/^[0-9a-f]{64}$/.test(sha256Hex))return false;
  const header=request.headers.get('authorization')||'';
  const match=/^Bearer ([A-Za-z0-9_-]{43,100})$/.exec(header);
  if(!match)return false;
  const got=await digestHex(new TextEncoder().encode(match[1]));
  let diff=0;
  for(let i=0;i<64;i++)diff|=got.charCodeAt(i)^sha256Hex.charCodeAt(i);
  return diff===0;
}
export async function reserveSlot(db,requestId,now,limit){
  if(!validRequestId(requestId)||!db?.prepare||!Number.isInteger(limit)||limit<1||limit>25)throw new Error('INVALID_RESERVATION');
  const day=utcDay(now),created=(now instanceof Date?now:new Date(now)).toISOString();
  const inserted=await db.prepare(RESERVE_SQL).bind(requestId,day,created,day,limit,requestId).first();
  if(inserted?.request_id===requestId)return {code:'RESERVED',status:201};
  const prior=await db.prepare(FIND_RESERVATION_SQL).bind(requestId).first();
  if(prior)return prior.day_utc===day?{code:'ALREADY_RESERVED',status:200}:{code:'ID_REUSED_ANOTHER_DAY',status:409};
  return {code:'DAILY_LIMIT',status:429};
}
export async function storeEnvelope(db,requestId,envelope,now,keyId){
  if(!validRequestId(requestId)||!validateSealedEnvelope(envelope,keyId))return {code:'INVALID_ENVELOPE',status:400};
  const json=JSON.stringify(envelope),digest=await digestHex(new TextEncoder().encode(json));
  if(new TextEncoder().encode(json).length>15000)return {code:'INVALID_ENVELOPE',status:400};
  const created=(now instanceof Date?now:new Date(now)).toISOString();
  const inserted=await db.prepare(STORE_SQL).bind(requestId,json,digest,created,requestId).first();
  if(inserted?.request_id===requestId)return {code:'STORED_ENCRYPTED',status:201};
  const prior=await db.prepare(FIND_REPORT_SQL).bind(requestId).first();
  if(prior)return prior.payload_sha256===digest?
    {code:'ALREADY_STORED_ENCRYPTED',status:200}:{code:'CONFLICTING_ENVELOPE',status:409};
  return {code:'RESERVATION_REQUIRED',status:409};
}
export async function readSealedEnvelope(db,requestId){
  if(!validRequestId(requestId))return null;
  const found=await db.prepare(FIND_REPORT_SQL).bind(requestId).first();
  if(!found||typeof found.payload_json!=='string')return null;
  return JSON.parse(found.payload_json);
}

// Unpublished Cloudflare storage-only gateway.
// Not imported by src/cloudflare-pilot.mjs; no fetch of third-party websites.


const HEADERS=Object.freeze({
  'Content-Type':'application/json; charset=utf-8',
  'Cache-Control':'no-store',
  'X-Content-Type-Options':'nosniff',
  'Content-Security-Policy':"default-src 'none'; frame-ancestors 'none'",
  'Referrer-Policy':'no-referrer',
});
const CAP_BYTES=16384;
const PATH_RESERVE='/internal/v1/reservations';
const PATH_ENVELOPES='/internal/v1/envelopes';
function answer(status,code,extras={}){
  return new Response(JSON.stringify({ok:status<300,code,sendAuthorized:false,...extras}),{
    status,headers:HEADERS
  });
}

async function verifiedCloudflareAccess(context,env){
  // ctx.access is authenticated by the Cloudflare edge when a Worker-level
  // Access policy protects ALL production and preview URLs for this Worker.
  // A request-supplied JWT/header is intentionally never trusted.
  const access=context?.access;
  if(!access||typeof access.getIdentity!=='function')return false;
  const audience=env?.ACCESS_AUD;
  const email=env?.ACCESS_ALLOWED_EMAIL;
  if(typeof audience!=='string'||!/^[A-Za-z0-9_-]{10,128}$/.test(audience)||
     access.aud!==audience||typeof email!=='string')return false;
  const allowed=email.trim().toLowerCase();
  if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(allowed))return false;
  try{
    const identity=await access.getIdentity();
    return typeof identity?.email==='string'&&
      identity.email.trim().toLowerCase()===allowed;
  }catch{return false;}
}

function ready(env){
  return env?.STORAGE_ONLY_ENABLED==='I_UNDERSTAND_PRIVATE_STORAGE_ONLY' &&
    env.DB?.prepare && typeof env.AUTH_TOKEN_SHA256==='string' &&
    /^[a-f0-9]{64}$/.test(env.AUTH_TOKEN_SHA256) &&
    /^[a-f0-9]{64}$/.test(env.PUBLIC_KEY_FINGERPRINT??'') &&
    dailyLimit(env.MAX_REQUESTS_PER_DAY)!==null;
}
async function parseBodyStrict(request){
  const type=request.headers.get('content-type')||'';
  if(!/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(type))return null;
  const n=Number(request.headers.get('content-length')||0);
  if(!Number.isFinite(n)||n>CAP_BYTES)return null;
  const reader=request.body?.getReader();
  if(!reader)return null;
  const chunks=[];let total=0;
  try{
    while(true){
      const part=await reader.read();
      if(part.done)break;
      total+=(part.value?.byteLength||0);
      if(total>CAP_BYTES)return null;
      chunks.push(part.value);
    }
  }catch{return null;}
  finally{try{await reader.cancel();}catch{}}
  if(!total)return null;
  const result=new Uint8Array(total);let pos=0;
  for(const c of chunks){result.set(c,pos);pos+=c.byteLength;}
  try{return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(result));}
  catch{return null;}
}
function exactKeys(v,keys){
  return !!v&&typeof v==='object'&&!Array.isArray(v)&&
    Object.keys(v).sort().join(',')===keys.slice().sort().join(',');
}
export async function handlePrivateStoreRequest(request,env,{now=()=>new Date(),context}={}){
  let u;
  try{u=new URL(request.url);}catch{return answer(400,'INVALID_URL');}
  if(u.search||u.hash)return answer(404,'NOT_FOUND');
  const isReserve=u.pathname===PATH_RESERVE;
  const isPostEnvelope=u.pathname===PATH_ENVELOPES;
  const id=u.pathname.startsWith(PATH_ENVELOPES+'/')?
    u.pathname.slice(PATH_ENVELOPES.length+1):null;
  const isGetEnvelope=id!==null&&validRequestId(id);
  if(!(isReserve||isPostEnvelope||isGetEnvelope))return answer(404,'NOT_FOUND');
  if(!await verifiedCloudflareAccess(context,env))return answer(403,'CLOUDFLARE_ACCESS_REQUIRED');
  if(!ready(env))return answer(503,'PRIVATE_STORAGE_NOT_CONFIGURED');
  try{
    if(!await authenticateBearer(request,env.AUTH_TOKEN_SHA256))return answer(401,'UNAUTHORIZED');
    if(isGetEnvelope){
      if(request.method!=='GET')return answer(405,'METHOD_NOT_ALLOWED');
      const envelope=await readSealedEnvelope(env.DB,id);
      if(!envelope)return answer(404,'NOT_FOUND');
      // Ciphertext only: no cleartext domains, client names, messages or contacts.
      return answer(200,'ENCRYPTED_REPORT',{requestId:id,envelope});
    }
    if(request.method!=='POST')return answer(405,'METHOD_NOT_ALLOWED');
    const body=await parseBodyStrict(request);
    if(isReserve){
      if(!exactKeys(body,['requestId'])||!validRequestId(body.requestId))return answer(400,'INVALID_RESERVATION');
      const result=await reserveSlot(env.DB,body.requestId,now(),dailyLimit(env.MAX_REQUESTS_PER_DAY));
      return answer(result.status,result.code,{requestId:body.requestId});
    }
    if(!exactKeys(body,['requestId','envelope'])||!validRequestId(body.requestId))return answer(400,'INVALID_ENVELOPE');
    const result=await storeEnvelope(env.DB,body.requestId,body.envelope,now(),env.PUBLIC_KEY_FINGERPRINT);
    return answer(result.status,result.code,{requestId:body.requestId});
  }catch{
    // Never reflect SQL, authorization, request body or error details to the caller.
    return answer(503,'PRIVATE_STORAGE_UNAVAILABLE');
  }
}
// Health status is static and independent of the secrets or D1 contents.
export default {
  async fetch(request, env, context) {
    let u;
    try { u = new URL(request.url); }
    catch { return answer(400, 'INVALID_URL'); }
    if (u.pathname === '/health' && !u.search && (request.method === 'GET' || request.method === 'HEAD')) {
      const body = JSON.stringify({
        ok: true,
        mode: 'private-storage-only',
        thirdPartyNetworkEnabled: false,
        historicalDataLoaded: false,
        formSubmissionEnabled: false,
        emailSendingEnabled: false,
        paidApiUsed: false
      });
      return new Response(request.method === 'HEAD' ? null : body, {
        status: 200,
        headers: HEADERS
      });
    }
    return handlePrivateStoreRequest(request, env, {context});
  }
};
