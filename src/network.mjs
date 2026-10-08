import dns from 'node:dns/promises';
import https from 'node:https';
import {BlockList,isIP} from 'node:net';

const blocked=new BlockList();
for(const [ip,prefix] of [
  ['0.0.0.0',8],['10.0.0.0',8],['100.64.0.0',10],
  ['127.0.0.0',8],['169.254.0.0',16],['172.16.0.0',12],
  ['192.0.0.0',24],['192.0.2.0',24],['192.88.99.0',24],
  ['192.168.0.0',16],['198.18.0.0',15],['198.51.100.0',24],
  ['203.0.113.0',24],['224.0.0.0',4],['240.0.0.0',4]
])blocked.addSubnet(ip,prefix,'ipv4');
for(const [ip,prefix] of [
  ['2001::',23],['2001:db8::',32],['2002::',16],['3fff::',20]
])blocked.addSubnet(ip,prefix,'ipv6');

export function isNonPublicIp(ip){
  const family=isIP(ip);
  if(family===4)return blocked.check(ip,'ipv4');
  if(family===6){
    // Reject ULA, link-local, loopback, IPv4-mapped, NAT64 and transition ranges.
    const first=Number.parseInt(ip.split(':')[0],16);
    if(!Number.isInteger(first)||first<0x2000||first>0x3fff)return true;
    return blocked.check(ip,'ipv6');
  }
  return true;
}
export function cleanHostname(host){
  return String(host??'').trim().toLowerCase().replace(/\.$/,'').replace(/^www\./,'');
}
export function isForbiddenHost(host){
  const h=cleanHostname(host);
  if(!h||h.length>253||!h.includes('.')||h==='localhost'||h.endsWith('.localhost')||
    h.endsWith('.local')||h.endsWith('.internal')||h.endsWith('.test')||h.endsWith('.invalid')||
    h.endsWith('.example')||h.endsWith('.onion')||/[^a-z0-9.\-]/i.test(h))return true;
  if(h.split('.').some(label=>!label||label.length>63||label.startsWith('-')||label.endsWith('-')))return true;
  if(isIP(h))return isNonPublicIp(h);
  return false;
}
export function parseCandidateUrl(raw){
  try{
    const value=String(raw??'').trim();
    if(!/^https?:\/\//i.test(value)||value.length>1800)return null;
    const u=new URL(value);
    if(!['https:','http:'].includes(u.protocol)||u.username||u.password||u.port)return null;
    // Even for websites indexed as http://, attempt verified HTTPS only.
    u.protocol='https:';
    u.hash='';
    if(isForbiddenHost(u.hostname))return null;
    return u;
  }catch{return null;}
}
export function isDeniedHost(host,denylist){
  const h=cleanHostname(host);
  if(!h)return true;
  const tokens=h.split('.');
  while(tokens.length>=2){
    if(denylist.has(tokens.join('.')))return true;
    tokens.shift();
  }
  return false;
}
export function sameHost(a,b){return cleanHostname(a)===cleanHostname(b);}
export async function publicDns(host,{resolver=dns.lookup}={}){
  if(isForbiddenHost(host))throw new Error('HOST_DENIED');
  const addresses=await resolver(host,{all:true,verbatim:true});
  if(!Array.isArray(addresses)||addresses.length===0)throw new Error('DNS_EMPTY');
  if(addresses.some(x=>![4,6].includes(x.family)||isNonPublicIp(x.address)))throw new Error('NON_PUBLIC_DNS_ADDRESS');
  return [...new Map(addresses.map(x=>[x.address,x])).values()]
    .sort((a,b)=>a.family-b.family).slice(0,2);
}

async function once(u,{timeoutMs,maxBytes,denylist,resolver}){
  if(u.protocol!=='https:'||u.port||isForbiddenHost(u.hostname)||isDeniedHost(u.hostname,denylist))throw new Error('UNSAFE_TARGET');
  const addrs=await publicDns(u.hostname,{resolver});
  // Pin TLS SNI hostname and the verified DNS address; never follow unvalidated redirects.
  const address=addrs[0];
  return await new Promise((resolve,reject)=>{
    const req=https.request({
      hostname:u.hostname,servername:u.hostname,rejectUnauthorized:true,
      autoSelectFamily:false,lookup:(_host,_opts,callback)=>callback(null,address.address,address.family),
      port:443,method:'GET',path:u.pathname+u.search,
      headers:{'User-Agent':'PublicDirectoryAudit/0.1 (read-only research)',
        'Accept':'text/html,text/plain;q=0.5','Accept-Encoding':'identity','Connection':'close'}
    },res=>{
      const status=res.statusCode??0;
      const contentType=String(res.headers['content-type']??'');
      const location=String(res.headers.location??'');
      const length=Number(res.headers['content-length']??0);
      if(length>maxBytes){res.destroy();reject(new Error('RESPONSE_TOO_LARGE'));return;}
      const chunks=[];let total=0;
      res.on('data',chunk=>{
        total+=chunk.length;
        if(total>maxBytes){res.destroy();reject(new Error('RESPONSE_TOO_LARGE'));return;}
        chunks.push(chunk);
      });
      res.on('end',()=>resolve({status,contentType,location,body:Buffer.concat(chunks).toString('utf8'),url:u.href}));
      res.on('error',e=>reject(new Error('RESPONSE_IO_ERROR:'+e.code)));
    });
    req.setTimeout(timeoutMs,()=>req.destroy(new Error('TIMEOUT')));
    req.on('error',e=>reject(e));
    req.end();
  });
}
export async function safeFetch(raw,{denylist=new Set(),timeoutMs=6500,maxBytes=160000,
  maxRedirects=2,resolver=dns.lookup}={}){
  if(!Number.isSafeInteger(maxRedirects)||maxRedirects<0||maxRedirects>3)throw new Error('REDIRECT_LIMIT');
  const start=parseCandidateUrl(raw);
  if(!start)throw new Error('URL_UNSAFE');
  if(isDeniedHost(start.hostname,denylist))throw new Error('THREAT_LISTED');
  let url=start;
  const visited=new Set();
  for(let i=0;i<=maxRedirects;i++){
    if(visited.has(url.href))throw new Error('REDIRECT_LOOP');
    visited.add(url.href);
    const page=await once(url,{timeoutMs,maxBytes,denylist,resolver});
    if([301,302,303,307,308].includes(page.status)){
      if(i>=maxRedirects)throw new Error('REDIRECT_LIMIT');
      if(!page.location)throw new Error('EMPTY_REDIRECT');
      const next=parseCandidateUrl(new URL(page.location,url).href);
      if(!next||!sameHost(url.hostname,next.hostname)||isDeniedHost(next.hostname,denylist))throw new Error('CROSS_HOST_OR_UNSAFE_REDIRECT');
      url=next;continue;
    }
    return page;
  }
  throw new Error('REDIRECT_LIMIT');
}
