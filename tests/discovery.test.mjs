import test from 'node:test';
import assert from 'node:assert/strict';
import {classifyContactHtml,linksOnSite,prohibitedSolicitation} from '../src/classify.mjs';
import {auditOne,auditBatch} from '../src/audit.mjs';
import {MANUAL_DENY_DOMAINS} from '../src/threats.mjs';

const VALID_THREATS={
 denylist:new Set([...MANUAL_DENY_DOMAINS,...Array.from({length:230},(_,i)=>'synthetic-'+i+'.example.org')]),
 counts:{manual:MANUAL_DENY_DOMAINS.length,CERT_PL:115,PHISHING_DATABASE:115,URLHAUS:12},
 checkedAt:new Date().toISOString()
};
const form='<h2>Contact the studio</h2><form method="POST" action="/send"><input type="email" name="email" /><textarea name="message"></textarea></form>';

test('static first-party contact form detection is preliminary and never authorizes messaging',()=>{
  assert.equal(classifyContactHtml(form,'https://studio.org/contact').status,'PRELIMINARY_OWN_DOMAIN_CONTACT_FORM');
  assert.equal(classifyContactHtml('<div class="hs-form-frame">Get in touch</div>','https://studio.org/').status,'CONTACT_CHANNEL_REQUIRES_MANUAL_REVIEW');
  assert.equal(classifyContactHtml('<iframe src="https://forms.gle/xyz"></iframe>','https://studio.org/').status,'CONTACT_CHANNEL_REQUIRES_MANUAL_REVIEW');
  assert.equal(classifyContactHtml('<form method="GET"><input name="email" /><textarea name="message"></textarea></form>','https://studio.org/').status,'CONTACT_CHANNEL_REQUIRES_MANUAL_REVIEW');
  assert.equal(classifyContactHtml('<form method="POST" action="https://formspree.io/f/xy"><input name="email"/><textarea name="message"></textarea></form>','https://studio.org/').status,'CONTACT_CHANNEL_REQUIRES_MANUAL_REVIEW');
  assert.equal(classifyContactHtml('<div class="g-recaptcha"></div>'+form,'https://studio.org/contact').status,'PRELIMINARY_OWN_DOMAIN_CONTACT_FORM');
  assert.equal(classifyContactHtml(form.replace('</form>','<div class="g-recaptcha"></div></form>'),'https://studio.org/contact').status,'CAPTCHA_REQUIRES_MANUAL_REVIEW');
});

test('explicit rejection of commercial solicitation defeats otherwise eligible form',()=>{
  assert.equal(prohibitedSolicitation('<p>No sales solicitations.</p>'),true);
  assert.equal(classifyContactHtml('<p>No sales solicitations.</p>'+form,'https://studio.org/contact').status,'SOLICITATION_RESTRICTION_DETECTED');
});

test('page discovery finds same-host contact links, not external websites',()=>{
  const links='<a href="/get-in-touch">Get in touch</a><a href="https://evil.org/contact">Contact</a><a href="/contact">Contact us</a>';
  assert.deepEqual(linksOnSite(links,'https://studio.org/',{limit:2}),['https://studio.org/get-in-touch','https://studio.org/contact']);
});

test('an offline mocked audit checks robots, contact page and policy without sending',async()=>{
  const req=[];
  const fake=async(url)=>{
    req.push(url);
    if(url==='https://studio.org/robots.txt')return {status:200,body:'User-agent: *\nDisallow: /private',contentType:'text/plain',url};
    if(url==='https://studio.org/')return {status:200,body:'<h1>Yoga studio</h1><a href="/contact">Get in touch</a>',contentType:'text/html',url};
    if(url==='https://studio.org/contact')return {status:200,body:form,contentType:'text/html',url};
    throw new Error('Unexpected destination');
  };
  const record=await auditOne({id:'1',name:'Studio',url:'https://studio.org/',category:'yoga_studio',state:'CA',source:'OVERTURE_PUBLIC'},
    {fetchImpl:fake,delayMs:0,threatSnapshot:VALID_THREATS,denylist:VALID_THREATS.denylist});
  assert.equal(record.status,'PRELIMINARY_OWN_DOMAIN_CONTACT_FORM');
  assert.equal(record.sendAuthorized,false);
  assert.equal(record.formUrl,'https://studio.org/contact');
  assert.deepEqual(req,['https://studio.org/robots.txt','https://studio.org/','https://studio.org/contact']);
});

test('manual-review channels are not sent and duplicate domains are skipped',async()=>{
  let fetched=0;
  const fake=async(url)=>{
    fetched++;
    if(url.endsWith('robots.txt'))return {status:404,body:'',url};
    return {status:200,contentType:'text/html',url,body:'<a href="https://forms.gle/x">Contact us</a>'};
  };
  const rows=[
    {id:'1',name:'A',url:'https://studio.org',source:'OVERTURE_PUBLIC'},
    {id:'2',name:'B',url:'http://www.studio.org',source:'OVERTURE_PUBLIC'}
  ];
  const results=await auditBatch(rows,{fetchImpl:fake,max:25,threatSnapshot:VALID_THREATS,denylist:VALID_THREATS.denylist});
  assert.equal(results.length,1);
  assert.equal(results[0].status,'CONTACT_CHANNEL_REQUIRES_MANUAL_REVIEW');
  assert.equal(results[0].sendAuthorized,false);
  assert.equal(fetched,2);
});

test('malformed contact-link URLs are skipped rather than aborting the entire page',()=>{
  const page='<a href="https://%">Contact</a><a href="/contact">Get in touch</a>';
  assert.deepEqual(linksOnSite(page,'https://studio.org/'),['https://studio.org/contact']);
});
test('script-injected imaginary forms are never treated as verified HTML forms',()=>{
  const fake='<script>const s=`<form method="POST" action="/send"><input name="email"><textarea name="message"></textarea></form>`;</script>';
  assert.notEqual(classifyContactHtml(fake,'https://studio.org/').status,'PRELIMINARY_OWN_DOMAIN_CONTACT_FORM');
});

test('auditOne refuses network even with a mocked transport if threat evidence is missing',async()=>{
 let count=0;
 const record=await auditOne(
  {id:'t',name:'Mock',url:'https://studio.org/',source:'OVERTURE_PUBLIC'},
  {fetchImpl:async()=>{count++;throw Error('should not fetch');}}
 );
 assert.equal(record.status,'THREAT_FEED_UNAVAILABLE');
 assert.equal(record.sendAuthorized,false);
 assert.equal(count,0);
});
test('auditOne refuses known malware-alert host with no network and without loaded threat data',async()=>{
 let calls=0;
 const result=await auditOne(
  {id:'m',name:'Mock',url:'https://www.covencle.com/',source:'OVERTURE_PUBLIC'},
  {fetchImpl:async()=>{calls++;throw Error('no calls permitted');}}
 );
 assert.equal(result.status,'THREAT_LISTED');
 assert.equal(calls,0);
});
