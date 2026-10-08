const SOURCES=[
  {name:'CERT_PL',url:'https://hole.cert.pl/domains/v2/domains.txt',min:100},
  {name:'PHISHING_DATABASE',url:'https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-domains-ACTIVE.txt',min:100},
  {name:'URLHAUS',url:'https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-hosts-online.txt',min:10}
];
export const MANUAL_DENY_DOMAINS=Object.freeze([
 'learningforlifecenter.org','heartlandmeditation.com','nafasfitness.com',
 'roco2lab.com','covencle.com'
]);
export function validThreatSnapshot(snapshot,{now=Date.now()}={}){
  if(!snapshot||!(snapshot.denylist instanceof Set)||snapshot.denylist.size<215||
    typeof snapshot.checkedAt!=='string')return false;
  const time=Date.parse(snapshot.checkedAt);
  if(!Number.isFinite(time)||time>now+300000||now-time>86400000)return false;
  const counts=snapshot.counts||{};
  for(const [name,min] of [['CERT_PL',100],['PHISHING_DATABASE',100],['URLHAUS',10]]){
    if(!Number.isInteger(counts[name])||counts[name]<min)return false;
  }
  return MANUAL_DENY_DOMAINS.every(x=>snapshot.denylist.has(x));
}

function hostFromLine(line){
  let s=String(line).trim().toLowerCase();
  if(!s||s.startsWith('#')||s.startsWith('!'))return null;
  s=s.replace(/^\|\|/,'').replace(/\^.*$/,'');
  if(s.startsWith('0.0.0.0 ')||s.startsWith('127.0.0.1 '))s=s.split(/\s+/).at(-1);
  if(s.startsWith('https://')){try{s=new URL(s).hostname}catch{return null}}
  s=s.replace(/^www\./,'').replace(/\.$/,'');
  if(!s.includes('.')||s.length>253||!/^[a-z0-9.-]+$/.test(s))return null;
  return s;
}
export async function loadThreats({fetchImpl=fetch}={}){
  const set=new Set(MANUAL_DENY_DOMAINS);
  const counts={manual:set.size};
  for(const source of SOURCES){
    const response=await fetchImpl(source.url,{redirect:'error',signal:AbortSignal.timeout(25000)});
    if(!response.ok)throw new Error('THREAT_SOURCE_HTTP:'+source.name);
    if(Number(response.headers?.get('content-length')||0)>30000000)throw new Error('THREAT_SOURCE_OVERSIZED');
    let text='';
    if(response.body&&typeof response.body.getReader==='function'){
      const reader=response.body.getReader();
      let size=0;const chunks=[];
      try{
        while(true){
          const {done,value}=await reader.read();if(done)break;
          size+=value.byteLength;
          if(size>30000000){await reader.cancel();throw new Error('THREAT_SOURCE_OVERSIZED');}
          chunks.push(Buffer.from(value));
        }
      }finally{reader.releaseLock();}
      text=Buffer.concat(chunks).toString('utf8');
    }else{
      text=await response.text();
      if(Buffer.byteLength(text,'utf8')>30000000)throw new Error('THREAT_SOURCE_OVERSIZED');
    }
    const discovered=new Set(text.split(/\r?\n/).map(hostFromLine).filter(Boolean));
    if(discovered.size<source.min)throw new Error('THREAT_SOURCE_INVALID:'+source.name);
    for(const host of discovered)set.add(host);
    counts[source.name]=discovered.size;
  }
  return {denylist:set,counts,checkedAt:new Date().toISOString()};
}
