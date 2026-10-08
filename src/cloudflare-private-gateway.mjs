// Unpublished Cloudflare storage-only gateway.
// Not imported by src/cloudflare-pilot.mjs; no fetch of third-party websites.
import {
  authenticateBearer,dailyLimit,validRequestId,reserveSlot,storeEnvelope,readSealedEnvelope
} from './cloudflare-private-ledger.mjs';

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
export default {
  async fetch(request,env,context){return handlePrivateStoreRequest(request,env,{context});}
};
