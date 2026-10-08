// NOT IMPORTED BY THE PUBLIC WORKER. Offline-vetted single-site research prototype.
// An operator must separately provision authentication, request quotas, and encrypted storage.
const forbidden=['.localhost','.local','.internal','.test','.invalid','.example','.onion','.arpa','.workers.dev'];
// These domains were blocked by the owner's endpoint security software.
// They are excluded even if a public threat feed later stops listing them.
const MANUAL_NEVER_FETCH=new Set([
  'learningforlifecenter.org','heartlandmeditation.com','nafasfitness.com',
  'roco2lab.com','covencle.com'
]);
export function verifiedThreatEvidence(snapshot,{now=Date.now()}={}){
  // This is a *format / freshness gate*, NOT a cryptographic signature.
  // A trusted operator must independently validate each downloaded source.
  if(!snapshot||typeof snapshot!=='object'||!(snapshot.domains instanceof Set)||
    snapshot.domains.size<215||typeof snapshot.validatedAt!=='string')return false;
  const published=Date.parse(snapshot.validatedAt);
  if(!Number.isFinite(published)||published>now+300000||now-published>86400000)return false;
  const counts=snapshot.sourceCounts;
  if(!counts||typeof counts!=='object')return false;
  for(const [name,min] of [['CERT_PL',100],['PHISHING_DATABASE',100],['URLHAUS',10]]){
    if(!Number.isInteger(counts[name])||counts[name]<min)return false;
  }
  for(const domain of MANUAL_NEVER_FETCH)if(!snapshot.domains.has(domain))return false;
  return true;
}
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
export function robotsAllowed(text,path,{userAgent='PublicDirectoryAudit-Pilot/0.2'}={}){
  // Robots is not an outreach permission grant. Reject unknown syntax conservatively.
  if(typeof text!=='string'||text.length>65536||typeof path!=='string'||!path.startsWith('/'))return false;
  const ua=String(userAgent).toLowerCase();
  const groups=[];
  let agents=[],rules=[],seenRules=false;
  function flush(){
    if(agents.length)groups.push({agents:[...agents],rules:[...rules]});
    agents=[];rules=[];seenRules=false;
  }
  for(const raw of text.split(/\r?\n/)){
    const line=raw.replace(/#.*/,'').trim();
    if(!line){
      if(seenRules)flush();
      continue;
    }
    const match=/^(user-agent|allow|disallow|crawl-delay):\s*(.*)$/i.exec(line);
    if(!match)continue;
    const kind=match[1].toLowerCase(),value=match[2].trim();
    if(kind==='user-agent'){
      if(seenRules)flush();
      if(value)agents.push(value.toLowerCase());
      continue;
    }
    if(!agents.length)continue;
    seenRules=true;
    // A positive crawl delay cannot safely be satisfied by this prototype's
    // immediate page fetches. Fail closed rather than silently ignore it.
    if(kind==='crawl-delay'){
      if(!/^(?:0+(?:\.0+)?|[1-9]\d*(?:\.\d+)?)$/.test(value)||Number(value)>0){
        rules.push({kind:'unsupported',value});
      }
      continue;
    }
    if(value)rules.push({kind,value});
  }
  flush();
  let specificity=-1,selected=[];
  for(const group of groups){
    for(const token of group.agents){
      const match=token==='*'||ua.startsWith(token);
      if(!match)continue;
      const score=token==='*'?0:token.length;
      if(score>specificity){specificity=score;selected=[group];}
      else if(score===specificity&&!selected.includes(group))selected.push(group);
    }
  }
  if(specificity<0)return true;
  let bestLength=-1,allowed=true;
  for(const group of selected){
    for(const rule of group.rules){
      if(rule.kind==='unsupported'||/[*$?]/.test(rule.value))return false;
      if(path.startsWith(rule.value)&&
        (rule.value.length>bestLength||
         (rule.value.length===bestLength&&rule.kind==='allow'))){
        bestLength=rule.value.length;
        allowed=rule.kind==='allow';
      }
    }
  }
  return allowed;
}

function attr(raw,name){
  for(const m of String(raw).matchAll(/(?:^|\s)([\w-]+)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/g)){
    if(m[1].toLowerCase()===name)return m[2]??m[3]??m[4];
  }
  return null;
}
function formsAndLinks(html,page,host){
  // Inspect visible wording only; escaped scripts are not evidence of permission.
  const visible=html.replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi,' ')
    .replace(/<style\b[^>]*>[\s\S]*?<\/style>/gi,' ')
    .replace(/<!--[\s\S]*?-->/g,' ');
  if(/no\s+(?:commercial\s+)?solicitations?|unsolicited\s+marketing\s+(?:is\s+)?prohibited|no\s+sales\s+pitches/i.test(visible)){
    return {status:'SOLICITATION_PROHIBITED',links:[]};
  }
  let manual=/(?:mailto:|forms\.gle|typeform\.com|jotform\.com|cf-turnstile|hcaptcha|g-recaptcha|hs-form-frame)/i.test(visible);
  for(const form of visible.matchAll(/<form\b([^>]*)>([\s\S]*?)<\/form>/gi)){
    const fields=[...form[2].matchAll(/<(?:input|textarea)\b([^>]*)>/gi)]
      .map(f=>['name','type','id','placeholder','aria-label'].map(k=>attr(f[1],k)||'').join(' '))
      .join(' ');
    if(!/(?:email|e-mail)/i.test(fields)||
       !/(?:message|comment|question|inquiry|enquiry|details)/i.test(fields))continue;
    if(/(?:captcha|data-sitekey|cf-turnstile|g-recaptcha|hcaptcha)/i.test(form[0])){
      manual=true;continue;
    }
    const method=(attr(form[1],'method')||'GET').toUpperCase();
    let action;
    try{action=new URL(attr(form[1],'action')||page.href,page.href);}
    catch{manual=true;continue;}
    if(method!=='POST'||!validate(action.href,host)){manual=true;continue;}
    const heading=visible.slice(Math.max(0,form.index-240),form.index)
      .replace(/<[^>]*>/g,' ').toLowerCase();
    const context=heading+' '+action.pathname.toLowerCase();
    if(/appointment|booking|reservation|recruitment|job\s+application|patient\s+intake|support\s+ticket/i.test(context)){
      manual=true;continue;
    }
    return {status:'FORM_FOUND_RESEARCH_ONLY',links:[]};
  }
  const links=[];
  for(const m of visible.matchAll(/<a\b[^>]*href=["']([^"']+)["'][^>]*>[\s\S]*?<\/a>/gi)){
    let url;
    try{url=new URL(m[1],page.href);}catch{continue;}
    if(!validate(url.href,host)||url.href===page.href)continue;
    if(!/contact|get[- /]?in[- /]?touch|reach[- /]?out|enquir|inquir/i.test(m[0]+' '+url.pathname))continue;
    if(!links.some(x=>x.href===url.href))links.push(url);
    if(links.length>=2)break;
  }
  return {status:manual?'CONTACT_REQUIRES_MANUAL_REVIEW':'NO_CONTACT_DETECTED',links};
}

export async function auditAuthorizedSite({url,approvedHost,denylist=[],threatEvidence,fetchImpl,now=()=>Date.now()}={}){
 const host=String(approvedHost||'').toLowerCase();
 const initial=validate(url,host);
 if(!initial)return {status:'DENIED_INPUT',requests:0,sendAuthorized:false};
 if([...MANUAL_NEVER_FETCH,...denylist].some(x=>host===x||host.endsWith('.'+x)))return {status:'THREAT_DENIED',requests:0,sendAuthorized:false};
 // No implicit network! Only an explicitly provided read-only transport is accepted.
 if(typeof fetchImpl!=='function')return {status:'NETWORK_DISABLED',requests:0,sendAuthorized:false};
 if(!verifiedThreatEvidence(threatEvidence,{now:now()}))
   return {status:'THREAT_FEED_UNAVAILABLE',requests:0,sendAuthorized:false};
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
