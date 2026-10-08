// Cloudflare pilot. This endpoint NEVER fetches external websites or accepts private data.
const headers={
  'Content-Type':'application/json; charset=utf-8',
  'Cache-Control':'no-store',
  'X-Content-Type-Options':'nosniff',
  'Content-Security-Policy':"default-src 'none'; frame-ancestors 'none'",
  'Referrer-Policy':'no-referrer',
};
const health=JSON.stringify({
  ok:true,mode:'offline-pilot',thirdPartyNetworkEnabled:false,
  historicalDataLoaded:false,formSubmissionEnabled:false,
  emailSendingEnabled:false,paidApiUsed:false
});
export default {
  async fetch(request){
    let pathname;
    try{pathname=new URL(request.url).pathname;}
    catch{return new Response('{"ok":false}',{status:400,headers});}
    if(pathname!=='/health')return new Response('{"ok":false}',{status:404,headers});
    if(!['GET','HEAD'].includes(request.method)){
      return new Response('{"ok":false}',{status:405,headers:{...headers,Allow:'GET, HEAD'}});
    }
    return new Response(request.method==='HEAD'?null:health,{status:200,headers});
  },
};
