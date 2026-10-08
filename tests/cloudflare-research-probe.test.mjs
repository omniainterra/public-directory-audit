import test from 'node:test';
import assert from 'node:assert/strict';
import {auditAuthorizedSite,robotsAllowed} from '../src/cloudflare-research-probe.mjs';
import worker from '../src/cloudflare-pilot.mjs';
const origin='https://studio.example.com';
const base={url:origin+'/',approvedHost:'studio.example.com'};
function fake(pages){
 const visited=[];
 const fetchImpl=async(url,opts)=>{
  visited.push({url,opts});
  if(!Object.hasOwn(pages,url))throw new Error('NOT_MOCKED');
  const r=pages[url];return new Response(r.body||'',{status:r.status||200,headers:{'content-type':r.type||'text/html'}});
 };
 return {visited,fetchImpl};
}
test('no transport means no external access',async()=>{
 assert.equal((await auditAuthorizedSite(base)).status,'NETWORK_DISABLED');
});
test('host restrictions and explicit denylist are fail-closed',async()=>{
 for(const item of [
  {url:'https://127.0.0.1/',approvedHost:'127.0.0.1'},
  {url:'https://user:pass@studio.example.com/',approvedHost:'studio.example.com'},
  {url:'http://studio.example.com/',approvedHost:'studio.example.com'},
  {url:'https://foreign.example.com/',approvedHost:'studio.example.com'}
 ])assert.equal((await auditAuthorizedSite(item)).status,'DENIED_INPUT');
 let used=false;
 const deny=await auditAuthorizedSite({...base,denylist:['example.com'],fetchImpl:()=>{used=true;}});
 assert.equal(deny.status,'THREAT_DENIED');assert.equal(used,false);
});
test('robots disallow prevents candidate webpage request',async()=>{
 const f=fake({[origin+'/robots.txt']:{body:'User-agent: *\nDisallow: /\n'}});
 const r=await auditAuthorizedSite({...base,fetchImpl:f.fetchImpl});
 assert.equal(r.status,'ROBOTS_DENIED');assert.equal(f.visited.length,1);
});
test('unreadable robots fails closed',async()=>{
 const f=fake({[origin+'/robots.txt']:{status:503}});
 assert.equal((await auditAuthorizedSite({...base,fetchImpl:f.fetchImpl})).status,'ROBOTS_UNREADABLE');
});
test('general-form discovery requires no POST request',async()=>{
 const f=fake({
  [origin+'/robots.txt']:{status:404},
  [origin+'/']:{body:'<a href="/get-in-touch">Get in touch</a>'},
  [origin+'/get-in-touch']:{body:'Contact <form method="POST" action="/submit"><input type="email" name="email"><textarea name="message"></textarea></form>'}
 });
 const r=await auditAuthorizedSite({...base,fetchImpl:f.fetchImpl});
 assert.equal(r.status,'FORM_FOUND_RESEARCH_ONLY');
 assert.equal(r.requests,3);
 assert.equal(r.sendAuthorized,false);
 assert.equal(f.visited.every(x=>x.opts.method==='GET'&&x.opts.redirect==='manual'),true);
});
test('external form becomes review-only',async()=>{
 const f=fake({
  [origin+'/robots.txt']:{status:404},
  [origin+'/']:{body:'Contact us <a href="https://forms.gle/abc">Send your question</a>'}
 });
 const r=await auditAuthorizedSite({...base,fetchImpl:f.fetchImpl});
 assert.equal(r.status,'CONTACT_REQUIRES_MANUAL_REVIEW');
 assert.equal(r.requests,2);
});
test('solicitation refusal blocks even when a form exists',async()=>{
 const f=fake({
  [origin+'/robots.txt']:{status:404},
  [origin+'/']:{body:'No commercial solicitations. <form method="POST" action="/contact"><input type="email" name="email"><textarea name="message"></textarea></form>'}
 });
 assert.equal((await auditAuthorizedSite({...base,fetchImpl:f.fetchImpl})).status,'SOLICITATION_PROHIBITED');
});
test('large response and redirect are never accepted',async()=>{
 const a=fake({[origin+'/robots.txt']:{status:404},[origin+'/']:{body:'a'.repeat(65537)}});
 assert.equal((await auditAuthorizedSite({...base,fetchImpl:a.fetchImpl})).status,'BODY_TOO_LARGE');
 const b=fake({[origin+'/robots.txt']:{status:404},[origin+'/']:{status:302}});
 assert.equal((await auditAuthorizedSite({...base,fetchImpl:b.fetchImpl})).status,'REDIRECT_REVIEW');
});
test('public Worker has no arbitrary research route',async()=>{
 const r=await worker.fetch(new Request('https://pilot.example/scan?url=https://studio.example.com'));
 assert.equal(r.status,404);
});

test('specific robots agent supersedes wildcard allow, preventing forbidden page fetches',async()=>{
  const robots='User-agent: *\nAllow: /private\n\nUser-agent: PublicDirectoryAudit-Pilot\nDisallow: /\n';
  assert.equal(robotsAllowed(robots,'/private'),false);
  const f=fake({[origin+'/robots.txt']:{body:robots}});
  const probe=await auditAuthorizedSite({
    url:origin+'/private',approvedHost:'studio.example.com',fetchImpl:f.fetchImpl
  });
  assert.equal(probe.status,'ROBOTS_DENIED');
  assert.equal(f.visited.length,1);
});
test('specific robots allow can override wildcard denial without authorizing marketing',()=>{
  const txt='User-agent: *\nDisallow: /\nUser-agent: PublicDirectoryAudit-Pilot\nAllow: /contact\n';
  assert.equal(robotsAllowed(txt,'/contact'),true);
  assert.equal(robotsAllowed(txt,'/anything'),true);
  const txt2='User-agent: PublicDirectoryAudit-Pilot\nDisallow: /\nAllow: /contact\n';
  assert.equal(robotsAllowed(txt2,'/contact'),true);
  assert.equal(robotsAllowed(txt2,'/hidden'),false);
});
test('robots crawl delay or complex pattern fails closed in offline pilot',()=>{
  assert.equal(robotsAllowed('User-agent: *\nCrawl-delay: 5\nAllow: /','/'),false);
  assert.equal(robotsAllowed('User-agent: *\nDisallow: /*private','/public'),false);
  assert.equal(robotsAllowed('User-agent: *\nAllow: /','/'),true);
  assert.equal(robotsAllowed('User-agent: *\nDisallow: /','/x'),false);
});
test('captcha-bearing generic enquiry form is always manual review, not automatically detected as usable',async()=>{
  const f=fake({
    [origin+'/robots.txt']:{status:404},
    [origin+'/']:{body:'<form action="/contact" method="POST"><input name="email" type="email"><textarea name="message"></textarea><div class="g-recaptcha"></div></form>'}
  });
  const res=await auditAuthorizedSite({...base,fetchImpl:f.fetchImpl});
  assert.equal(res.status,'CONTACT_REQUIRES_MANUAL_REVIEW');
  assert.equal(res.sendAuthorized,false);
});
test('forms with misleading data-action cannot masquerade as a same-host contact POST action',async()=>{
  const f=fake({
    [origin+'/robots.txt']:{status:404},
    [origin+'/']:{body:'<form method="POST" data-action="/contact" action="https://thirdparty.example.net/receive"><input name="email"><textarea name="message"></textarea></form>'}
  });
  const res=await auditAuthorizedSite({...base,fetchImpl:f.fetchImpl});
  assert.equal(res.status,'CONTACT_REQUIRES_MANUAL_REVIEW');
});
test('form field order and single-quoted HTML attributes still identify a read-only candidate',async()=>{
  const f=fake({
    [origin+'/robots.txt']:{status:404},
    [origin+'/']:{body:'<form action="/contact" method="POST"><input name="email" type="email"><textarea name="message"></textarea></form>'}
  });
  const res=await auditAuthorizedSite({...base,fetchImpl:f.fetchImpl});
  assert.equal(res.status,'FORM_FOUND_RESEARCH_ONLY');
  assert.equal(res.sendAuthorized,false);
  assert.equal(f.visited.every(x=>x.opts.method==='GET'),true);
});
