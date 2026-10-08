import {validThreatSnapshot} from './threats.mjs';
import {parseCandidateUrl,isDeniedHost,sameHost,safeFetch} from './network.mjs';
import {robotsPermit,checkRobots} from './robots.mjs';
import {linksOnSite,classifyContactHtml} from './classify.mjs';

export const AUDIT_KIND='RESEARCH_ONLY_NOT_AUTHORIZED_FOR_OUTREACH';
const pause=ms=>new Promise(resolve=>setTimeout(resolve,ms));
function safeRecord(row){
  return {id:String(row.id??'').slice(0,100),name:String(row.name??'').slice(0,160),
    url:String(row.url??'').slice(0,1800),state:String(row.state??'').slice(0,20),
    category:String(row.category??'').slice(0,100),source:String(row.source??'').slice(0,40),
    auditKind:AUDIT_KIND,sendAuthorized:false};
}
export async function auditOne(row,{denylist=new Set(),threatSnapshot,fetchImpl=safeFetch,delayMs=1200}={}){
  const record=safeRecord(row),candidate=parseCandidateUrl(record.url);
  if(!candidate)return {...record,status:'SOURCE_URL_INVALID'};
  const host=candidate.hostname;
  record.url=candidate.href;
  if(isDeniedHost(host,denylist))return {...record,status:'THREAT_LISTED'};
  if(!validThreatSnapshot(threatSnapshot)||threatSnapshot.denylist!==denylist)
    return {...record,status:'THREAT_FEED_UNAVAILABLE'};
  const robots=await checkRobots(candidate.href,{denylist,safeFetchImpl:fetchImpl});
  if(!robots.allowed)return {...record,status:robots.reason};
  const seen=new Set();
  const pages=[];
  try{
    const home=await fetchImpl(candidate.href,{denylist,maxBytes:160000,maxRedirects:2,timeoutMs:6500});
    if(home.status!==200||!/(html|text)/i.test(home.contentType??'')){
      return {...record,status:'SITE_HTTP_OR_CONTENT_TYPE_UNSUITABLE'};
    }
    if(!sameHost(new URL(home.url).hostname,host))return {...record,status:'HOST_CHANGED'};
    pages.push(home);seen.add(home.url);
    if(!robotsPermit(robots.robots,new URL(home.url).pathname))return {...record,status:'ROBOTS_DENIED'};
    if(!classifyContactHtml(home.body,home.url).status.startsWith('SOLICITATION_RESTRICTION')){
      for(const link of linksOnSite(home.body,home.url,{limit:2})){
        if(seen.has(link)||!robotsPermit(robots.robots,new URL(link).pathname))continue;
        await pause(delayMs);
        try{
          const page=await fetchImpl(link,{denylist,maxBytes:160000,maxRedirects:2,timeoutMs:6500});
          if(page.status===200&&/(html|text)/i.test(page.contentType??'')&&sameHost(new URL(page.url).hostname,host)){
            pages.push(page);seen.add(page.url);
          }
        }catch{/* A missing secondary page must not cause a false negative for the homepage. */}
      }
    }
    const decisions=pages.map(p=>classifyContactHtml(p.body,p.url));
    const prohib=decisions.find(x=>x.status==='SOLICITATION_RESTRICTION_DETECTED');
    if(prohib)return {...record,status:'SOLICITATION_RESTRICTION_DETECTED'};
    const form=decisions.find(x=>x.status==='PRELIMINARY_OWN_DOMAIN_CONTACT_FORM');
    if(form)return {...record,status:'PRELIMINARY_OWN_DOMAIN_CONTACT_FORM',formUrl:form.formUrl};
    const review=decisions.find(x=>x.status==='CAPTCHA_REQUIRES_MANUAL_REVIEW')||
      decisions.find(x=>x.status==='CONTACT_CHANNEL_REQUIRES_MANUAL_REVIEW');
    if(review)return {...record,status:review.status};
    const other=decisions.find(x=>x.status==='BOOKING_OR_OTHER_PURPOSE_ONLY');
    return {...record,status:other?.status??'NO_DETECTED_CONTACT_CHANNEL'};
  }catch{return {...record,status:'TECHNICAL_FAILURE_RETRY_LATER'};}
}
export async function auditBatch(rows,{denylist=new Set(),threatSnapshot,fetchImpl=safeFetch,max=25}={}){
  if(!Array.isArray(rows)||rows.length>max||max>50||max<1)throw new Error('BATCH_LIMIT');
  const out=[];
  const seen=new Set();
  for(const row of rows){
    const candidate=parseCandidateUrl(row.url);
    const key=candidate?.hostname.replace(/^www\./,'')||null;
    if(key&&seen.has(key))continue;
    if(key)seen.add(key);
    out.push(await auditOne(row,{denylist,threatSnapshot,fetchImpl}));
  }
  return out;
}
