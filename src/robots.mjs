import {safeFetch} from './network.mjs';

export function robotsPermit(text,path,{userAgent='PublicDirectoryAudit'}={}){
  const lines=String(text??'').split(/\r?\n/);
  const groups=[];let agents=[],rules=[],inRules=false;
  function flush(){if(agents.length)groups.push({agents,rules});agents=[];rules=[];inRules=false;}
  for(let line of lines){
    line=line.replace(/#.*/,'').trim();if(!line)continue;
    const m=/^([a-z-]+):\s*(.*)$/i.exec(line);if(!m)continue;
    const key=m[1].toLowerCase(),value=m[2].trim();
    if(key==='user-agent'){
      if(inRules)flush();agents.push(value.toLowerCase());continue;
    }
    if(key==='allow'||key==='disallow'){
      inRules=true;if(agents.length)rules.push({kind:key,value});
    }
  }
  flush();
  const ua=userAgent.toLowerCase();
  const matched=groups.filter(g=>g.agents.some(x=>x!=='*'&&ua.includes(x)));
  const selected=matched.length?matched:groups.filter(g=>g.agents.includes('*'));
  let decision=true,priority=-1;
  for(const group of selected){
    for(const rule of group.rules){
      if(!rule.value)continue;
      // Conservative interpretation: wildcard/path matching requires no regular expression execution from remote content.
      const prefix=rule.value.split(/[\*$]/)[0];
      if(!prefix||!String(path).startsWith(prefix))continue;
      if(prefix.length>priority||(prefix.length===priority&&rule.kind==='allow')){
        priority=prefix.length;decision=rule.kind==='allow';
      }
    }
  }
  return decision;
}
export async function checkRobots(url,{denylist,safeFetchImpl=safeFetch}={}){
  const u=new URL(url);
  const target=`https://${u.hostname}/robots.txt`;
  try{
    const r=await safeFetchImpl(target,{denylist,maxRedirects:0,maxBytes:64000,timeoutMs:6500});
    if(r.status===404||r.status===410)return {allowed:true,reason:'ROBOTS_ABSENT',robots:r.body};
    if(r.status!==200)return {allowed:false,reason:'ROBOTS_UNREADABLE',robots:''};
    return {allowed:robotsPermit(r.body,u.pathname),reason:'ROBOTS_CHECKED',robots:r.body};
  }catch{return {allowed:false,reason:'ROBOTS_UNREACHABLE',robots:''};}
}
