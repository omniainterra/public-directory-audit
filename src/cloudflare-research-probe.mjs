// NOT IMPORTED BY THE PUBLIC WORKER. Offline-vetted single-site research prototype.
// An operator must separately provision authentication, request quotas, and encrypted storage.
const forbidden=['.localhost','.local','.internal','.test','.invalid','.example','.onion','.arpa','.workers.dev'];
function hostnameAllowed(host){
 const h=String(host||'').toLowerCase();
 if(!h||h.length>253||h==='localhost'||!h.includes('.')||forbidden.some(x=>h.endsWith(x)))return false;
 if(!/^[a-z0-9.-]+$/.test(h)||h.includes('..')||/^\d+(?:\.\d+){3}$/.test(h))return false;
 return !h.split('.').some(x=>!x||x.length>63||x.startsWith('-')||x.endsWith('-'));
}
function validate(raw,host){
 try{
  const u=new URL(raw);
  if(u.protocol!=='https:'||u.username||u.password||u.port||!hostnameAllowed(u.hostname)||u.hostname!==host)return null;
  u.hash='';
  return u;
 }catch{return null;}
}
async function getBounded(fetchImpl,url){
 const response=await fetchImpl(url,{
  method:'GET',redirect:'manual',
  headers:{'User-Agent':'PublicDirectoryAudit-Pilot/0.2','Accept':'text/html,text/plain;q=0.5'},
  signal:AbortSignal.timeout(7000)
 });
 if([301,302,303,307,308].includes(response.status))return {status:'REDIRECT_REVIEW'};
 if(response.status!==200)return {status:'HTTP_'+response.status};
 if(!/text\/(?:html|plain)/i.test(response.headers.get('content-type')||''))return {status:'NOT_HTML'};
 if(Number(response.headers.get('content-length')||0)>65536)return {status:'TOO_LARGE'};
 const reader=response.body?.getReader();
 if(!reader)return {status:'UNREADABLE'};
 const chunks=[];let length=0;
 try{
  while(true){
   const part=await reader.read();
   if(part.done)break;
   length+=part.value.byteLength;
   if(length>65536)return {status:'TOO_LARGE'};
   chunks.push(part.value);
  }
 }finally{try{await reader.cancel();}catch{}}
 const out=new Uint8Array(length);let offset=0;
 for(const c of chunks){out.set(c,offset);offset+=c.byteLength;}
 return {status:'OK',body:new TextDecoder().decode(out)};
}
function robotsAllowed(text,path){
 let active=false,hasGroup=false,bestLength=-1,allow=true;
 for(const line of String(text).split(/\r?\n/)){
  const m=/^(user-agent|disallow|allow):\s*(.*)$/i.exec(line.replace(/#.*/,'').trim());
  if(!m)continue;
  const key=m[1].toLowerCase(),v=m[2].trim();
  if(key==='user-agent'){active=v==='*'||v.toLowerCase()==='publicdirectoryaudit-pilot/0.2';hasGroup=true;continue;}
  if(!hasGroup||!active||!v)continue;
  if(/[?$*]/.test(v))return false; // no remote regex execution, fail closed
  if(path.startsWith(v)&&(v.length>bestLength||(v.length===bestLength&&key==='allow'))){
   allow=key==='allow';bestLength=v.length;
  }
 }
 return allow;
}
function formsAndLinks(html,page,host){
 if(/no\s+(?:commercial\s+)?solicitations?|unsolicited\s+marketing\s+prohibited|no\s+sales\s+pitches/i.test(html)){
  return {status:'SOLICITATION_PROHIBITED',links:[]};
 }
 let manual=/(?:mailto:|forms\.gle|typeform\.com|jotform\.com|cf-turnstile|hcaptcha|g-recaptcha|hs-form-frame)/i.test(html);
 for(const form of html.matchAll(/<form\b([^>]*)>([\s\S]*?)<\/form>/gi)){
  if(!/(?:type|name)=["']?(?:email|e-mail)/i.test(form[2])||!/<textarea\b/i.test(form[2]))continue;
  const get=(name)=>new RegExp(name+'\\s*=\\s*["\x27]([^"\x27]*)["\x27]','i').exec(form[1])?.[1];
  const method=(get('method')||'GET').toUpperCase();
  let action;
  try{action=new URL(get('action')||page.href,page.href);}catch{manual=true;continue;}
  if(method!=='POST'||!validate(action.href,host)){manual=true;continue;}
  const ctx=html.slice(Math.max(0,form.index-140),form.index)+' '+action.pathname;
  if(/appointment|booking|recruitment|patient\s+intake|support\s+ticket/i.test(ctx)){manual=true;continue;}
  return {status:'FORM_FOUND_RESEARCH_ONLY',links:[]};
 }
 const links=[];
 for(const m of html.matchAll(/<a\b[^>]*href=["']([^"']+)["'][^>]*>[\s\S]*?<\/a>/gi)){
  let url;try{url=new URL(m[1],page.href);}catch{continue;}
  if(!validate(url.href,host)||url.href===page.href)continue;
  if(!/contact|get[- /]?in[- /]?touch|reach[- /]?out|enquir|inquir/i.test(m[0]+' '+url.pathname))continue;
  if(!links.some(x=>x.href===url.href))links.push(url);
  if(links.length>=2)break;
 }
 return {status:manual?'CONTACT_REQUIRES_MANUAL_REVIEW':'NO_CONTACT_DETECTED',links};
}
export async function auditAuthorizedSite({url,approvedHost,denylist=[],fetchImpl}={}){
 const host=String(approvedHost||'').toLowerCase();
 const initial=validate(url,host);
 if(!initial)return {status:'DENIED_INPUT',requests:0,sendAuthorized:false};
 if(denylist.some(x=>host===x||host.endsWith('.'+x)))return {status:'THREAT_DENIED',requests:0,sendAuthorized:false};
 // No implicit network! Only an explicitly provided read-only transport is accepted.
 if(typeof fetchImpl!=='function')return {status:'NETWORK_DISABLED',requests:0,sendAuthorized:false};
 let requests=0;
 const result=(status)=>({status,requests,sendAuthorized:false});
 try{
  requests++;
  const robots=await getBounded(fetchImpl,new URL('/robots.txt',initial.origin).href);
  if(robots.status==='HTTP_404'||robots.status==='HTTP_410')robots.body='';
  else if(robots.status!=='OK')return result('ROBOTS_UNREADABLE');
  if(!robotsAllowed(robots.body,initial.pathname))return result('ROBOTS_DENIED');
  const queue=[initial],seen=new Set();let manual=false;
  while(queue.length&&seen.size<3){
   const page=queue.shift();
   if(seen.has(page.href)||!robotsAllowed(robots.body,page.pathname))continue;
   seen.add(page.href);requests++;
   const r=await getBounded(fetchImpl,page.href);
   if(r.status!=='OK')return result(r.status==='TOO_LARGE'?'BODY_TOO_LARGE':r.status);
   const found=formsAndLinks(r.body,page,host);
   if(found.status==='SOLICITATION_PROHIBITED'||found.status==='FORM_FOUND_RESEARCH_ONLY')return result(found.status);
   if(found.status==='CONTACT_REQUIRES_MANUAL_REVIEW')manual=true;
   for(const link of found.links)if(queue.length+seen.size<3&&!seen.has(link.href))queue.push(link);
  }
  return result(manual?'CONTACT_REQUIRES_MANUAL_REVIEW':'NO_CONTACT_DETECTED');
 }catch{return result('TECHNICAL_RETRY');}
}
