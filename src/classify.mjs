import {parseCandidateUrl,sameHost} from './network.mjs';

function attribute(raw,key){
  const m=new RegExp('(?:^|\\s)'+key+'\\s*=\\s*(?:"([^"]*)"|\'([^\']*)\'|([^\\s>]+))','i').exec(raw);
  return m?(m[1]??m[2]??m[3]??''):null;
}
function visible(value){return String(value??'').replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi,' ')
  .replace(/<style\b[^>]*>[\s\S]*?<\/style>/gi,' ').replace(/<[^>]*>/g,' ')
  .replace(/&nbsp;/gi,' ').replace(/&amp;/gi,'&').replace(/\s+/g,' ').trim();}
export function prohibitedSolicitation(html){
  const h=visible(html).slice(0,200000);
  return /\b(?:no\s+(?:sales|marketing|commercial|business)\s+solicitations?|no\s+unsolicited\s+(?:commercial|marketing)\s+(?:messages?|inquiries)|(?:automated|marketing)\s+(?:submissions?|requests?)\s+(?:are\s+)?(?:prohibited|not\s+permitted)|do\s+not\s+use\s+(?:this\s+)?form\s+for\s+(?:marketing|sales|solicitations?))\b/i.test(h);
}
export function linksOnSite(html,pageUrl,{limit=2}={}){
  const out=[];
  for(const hit of String(html).matchAll(/<a\b([^>]*)>([\s\S]*?)<\/a>/gi)){
    const target=attribute(hit[1],'href');if(!target)continue;
    const context=target+' '+visible(hit[2]);
    if(!/(contact|get[ -]?in[ -]?touch|reach[ -]?out|inquir|enquir|say[ -]?hello)/i.test(context))continue;
    let absolute;
    try{absolute=new URL(target,pageUrl);}catch{continue;}
    const u=parseCandidateUrl(absolute.href);
    if(!u||!sameHost(u.hostname,new URL(pageUrl).hostname))continue;
    if(u.href===pageUrl||out.includes(u.href))continue;
    out.push(u.href);
    if(out.length>=limit)break;
  }
  return out;
}
export function classifyContactHtml(html,pageUrl){
  if(prohibitedSolicitation(html))return {status:'SOLICITATION_RESTRICTION_DETECTED',formUrl:null};
  const raw=String(html??'');
  const source=raw.replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi,' ').replace(/<style\b[^>]*>[\s\S]*?<\/style>/gi,' ');
  let review=false,captcha=false,wrongPurpose=false;
  for(const hit of source.matchAll(/<form\b([^>]*)>([\s\S]*?)<\/form>/gi)){
    const raw=hit[1],body=hit[2];
    const fields=[...body.matchAll(/<(?:input|textarea)\b([^>]*)>/gi)]
      .map(v=>[attribute(v[1],'name'),attribute(v[1],'id'),attribute(v[1],'placeholder'),attribute(v[1],'aria-label'),attribute(v[1],'type')].filter(Boolean).join(' ')).join(' ');
    if(!/\b(?:email|e-mail)\b/i.test(fields)||!/\b(?:message|comment|question|inquiry|enquiry|details)\b/i.test(fields))continue;
    const heading=visible(source.slice(Math.max(0,hit.index-180),hit.index)).toLowerCase();
    if(/appointment|booking|patient|employment|careers|job application|reservation|support ticket|press inquiry/.test(heading)){
      wrongPurpose=true;continue;
    }
    const hasCaptcha=/recaptcha|hcaptcha|cf-turnstile|data-sitekey|captcha/i.test(body);
    if(hasCaptcha){captcha=true;continue;}
    const method=String(attribute(raw,'method')||'GET').toUpperCase();
    let action;
    try{action=new URL(attribute(raw,'action')||pageUrl,pageUrl)}catch{review=true;continue;}
    const safe=parseCandidateUrl(action.href);
    if(method==='POST'&&safe&&sameHost(safe.hostname,new URL(pageUrl).hostname)){
      return {status:'PRELIMINARY_OWN_DOMAIN_CONTACT_FORM',formUrl:pageUrl,actionOrigin:action.origin};
    }
    review=true;
  }
  if(captcha)return {status:'CAPTCHA_REQUIRES_MANUAL_REVIEW',formUrl:null};
  if(/(?:https:\/\/)?(?:forms\.gle|jotform\.com|typeform\.com|formstack\.com|tally\.so|formspree\.io|hsforms\.com)/i.test(source)
    || /(?:hbspt\.forms\.create|wpforms-form|wpcf7-form|forminator-ui|hs-form-frame|typeform-widget)/i.test(raw)
    || /mailto:[^\s"'<>]+@[^\s"'<>]+/i.test(source))review=true;
  if(review)return {status:'CONTACT_CHANNEL_REQUIRES_MANUAL_REVIEW',formUrl:null};
  if(wrongPurpose)return {status:'BOOKING_OR_OTHER_PURPOSE_ONLY',formUrl:null};
  return {status:'NO_DETECTED_CONTACT_CHANNEL',formUrl:null};
}
