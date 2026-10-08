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
