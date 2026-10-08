import test from 'node:test';
import assert from 'node:assert/strict';
import {isNonPublicIp,parseCandidateUrl,isForbiddenHost,isDeniedHost,publicDns,sameHost,safeFetch} from '../src/network.mjs';
import {robotsPermit,checkRobots} from '../src/robots.mjs';
import {loadThreats,validThreatSnapshot,MANUAL_DENY_DOMAINS} from '../src/threats.mjs';

test('non-public and reserved IP ranges are blocked without external requests',()=>{
  for(const ip of ['10.2.3.4','127.0.0.1','169.254.169.254','172.16.0.1','192.168.1.1',
    '0.0.0.0','100.64.0.1','192.0.2.1','198.19.1.3','203.0.113.7','224.1.1.1',
    '255.255.255.255','::1','::ffff:127.0.0.1','fc00::1','fe80::1','2001:db8::12',
    '2002:0a00:1::1','3fff::1','not-an-ip']){
    assert.equal(isNonPublicIp(ip),true,ip);
  }
  for(const ip of ['1.1.1.1','8.8.8.8','2001:4860:4860::8888','2606:4700:4700::1111']){
    assert.equal(isNonPublicIp(ip),false,ip);
  }
});

test('URL and domain validation refuse credential, port, non-HTTPS link schemes and local destinations',()=>{
  for(const url of ['file:///etc/passwd','javascript:alert(1)','https://a:b@studio.org/',
    'https://studio.org:8443/','http://localhost:8000/','https://something.local/',
    'https://169.254.169.254/latest/meta-data/','https://studio.test/','https://studio.example/']){
    assert.equal(parseCandidateUrl(url),null,url);
  }
  assert.equal(parseCandidateUrl('http://www.studio.org/contact').href,'https://www.studio.org/contact');
  assert.equal(isForbiddenHost('something.internal'),true);
  assert.equal(sameHost('www.studio.org','studio.org'),true);
});

test('DNS pinning rejects entire resolution if a single private IP appears',async()=>{
  await assert.rejects(()=>publicDns('studio.org',{
    resolver:async()=>[{address:'1.1.1.1',family:4},{address:'10.0.0.5',family:4}]
  }),/NON_PUBLIC_DNS_ADDRESS/);
  const r=await publicDns('studio.org',{resolver:async()=>[{address:'2001:4860:4860::8888',family:6},{address:'8.8.8.8',family:4}]});
  assert.equal(r[0].address,'8.8.8.8');
  const deny=new Set(['blocked.org']);
  assert.equal(isDeniedHost('forms.blocked.org',deny),true);
  await assert.rejects(()=>safeFetch('https://blocked.org/',{denylist:deny}),/THREAT_LISTED/);
  await assert.rejects(()=>safeFetch('https://127.0.0.1/'),/URL_UNSAFE/);
});

test('robots.txt honors specific disallow and user-agent and fails closed on non-404 errors',async()=>{
  const robots='User-agent: *\nDisallow: /private\nAllow: /private/public\n\nUser-agent: PublicDirectoryAudit\nDisallow: /no-audit\n';
  assert.equal(robotsPermit('User-agent: *\nDisallow: /blocked','/blocked/a'),false);
  assert.equal(robotsPermit(robots,'/no-audit'),false);
  assert.equal(robotsPermit(robots,'/contact'),true);
  let requests=0;
  const fetchImpl=async()=>{requests++;return {status:500,body:''}};
  const result=await checkRobots('https://studio.org/',{safeFetchImpl:fetchImpl});
  assert.equal(result.allowed,false);
  assert.equal(requests,1);
  const absent=await checkRobots('https://studio.org/',{safeFetchImpl:async()=>({status:404,body:''})});
  assert.equal(absent.allowed,true);
});

test('Node HTTPS fetch never resolves arbitrary hosts if threat feeds are missing',async()=>{
 let dnsCalls=0;
 await assert.rejects(()=>safeFetch('https://studio.org/',{
   denylist:new Set(),resolver:async()=>{dnsCalls++;return [{address:'1.1.1.1',family:4}];}
 }),/THREAT_FEED_REQUIRED/);
 assert.equal(dnsCalls,0);
 for(const domain of ['roco2lab.com','www.covencle.com']){
   await assert.rejects(()=>safeFetch('https://'+domain+'/',{denylist:new Set()}),/THREAT_LISTED/);
 }
});
test('3 validated threat feeds return a fresh snapshot without real internet calls',async()=>{
 const sourceCalls=[];
 const fake=async url=>{
   sourceCalls.push(url);
   const lines=Array.from({length:url.includes('cert.pl')?110:url.includes('github')?120:20},
      (_,i)=>'blocked-'+sourceCalls.length+'-'+i+'.example.org').join('\n');
   return {ok:true,headers:{get:()=>String(lines.length)},body:null,text:async()=>lines};
 };
 const found=await loadThreats({fetchImpl:fake});
 assert.equal(sourceCalls.length,3);
 assert.equal(validThreatSnapshot(found),true);
 assert.equal(MANUAL_DENY_DOMAINS.every(x=>found.denylist.has(x)),true);
 assert.equal(validThreatSnapshot({...found,checkedAt:'2020-01-01T00:00:00Z'}),false);
 assert.equal(validThreatSnapshot({...found,denylist:new Set([...found.denylist].filter(x=>x!=='roco2lab.com'))}),false);
});
