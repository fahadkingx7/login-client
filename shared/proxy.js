globalThis.CS = globalThis.CS || {};
CS.Proxy = (() => {
  let authInstalled=false, errorInstalled=false, testPromise=null;
  const authAttempts=new Map();
  let lastProxyError='';

  function normalize(raw){
    if(!raw || raw.mode==='direct' || raw.enabled===false ||
       !String(raw.host||'').trim() || !Number(raw.port||0)){
      return {mode:'unconfigured',healthy:false,ip:'',lastError:'Proxy is not configured.'};
    }
    const scheme=String(raw.scheme||'http').toLowerCase();
    const host=String(raw.host||'').trim();
    const port=Number(raw.port||0);
    if(!['http','https','socks4','socks5'].includes(scheme)) throw new Error('Unsupported proxy protocol.');
    if(!host || /[\s/:]/.test(host) || !Number.isInteger(port) || port<1 || port>65535) throw new Error('Invalid proxy host or port. Enter host/IP without http:// and a valid port.');
    return {mode:'fixed_servers',scheme,host,port,username:String(raw.username||''),password:String(raw.password||''),expectedIp:String(raw.expectedIp||'').trim()};
  }

  async function apply(raw){
    const p=normalize(raw);
    if(p.mode==='unconfigured') throw new Error('Proxy is not configured. Enter a working proxy before using managed access.');
    const current=await effective().catch(()=>null);
    if(current?.levelOfControl && !['controlled_by_this_extension','controllable_by_this_extension'].includes(current.levelOfControl)){
      throw new Error(`Chrome proxy settings are controlled by ${current.levelOfControl}.`);
    }
    await chrome.proxy.settings.set({
      value:{
        mode:'fixed_servers',
        rules:{singleProxy:{scheme:p.scheme,host:p.host,port:p.port},bypassList:['<local>','<-loopback>','thdxsonrjazeoadhidbx.supabase.co']}
      },
      scope:'regular'
    });
    const after=await effective().catch(()=>null);
    if(after?.value?.mode!=='fixed_servers' || after?.value?.rules?.singleProxy?.host!==p.host || Number(after?.value?.rules?.singleProxy?.port)!==p.port){
      throw new Error('Chrome did not accept the saved proxy configuration.');
    }
    lastProxyError='';
    return p;
  }

  async function clear(){
    await chrome.proxy.settings.set({value:{mode:'direct'},scope:'regular'});
    await CS.Store.remove(['activeProxyCredentials']).catch(()=>{});
  }
  async function effective(){return new Promise((resolve,reject)=>chrome.proxy.settings.get({incognito:false},x=>chrome.runtime.lastError?reject(chrome.runtime.lastError):resolve(x)));}

  function friendlyProxyError(error){
    const e=String(error||'').trim();
    const l=e.toLowerCase();
    if(l.includes('err_tunnel_connection_failed')) return 'HTTPS tunnel through the proxy failed. The proxy may be offline, rejecting CONNECT, or unable to reach the destination.';
    if(l.includes('err_proxy_connection_failed')) return 'Could not connect to the proxy server. Check the host and port.';
    if(l.includes('err_proxy_auth')) return 'Proxy authentication failed or is not supported by this proxy endpoint.';
    if(l.includes('err_connection_refused')) return 'The proxy server refused the connection. Check the host and port.';
    if(l.includes('err_connection_timed_out')) return 'The proxy connection timed out. Check that the proxy server is online.';
    if(l.includes('failed to fetch')) return 'The proxy health request could not reach the Internet through the proxy.';
    return e || 'Proxy verification failed.';
  }

  async function test(raw, options={}){
    const p=normalize(raw);
    if(p.mode==='unconfigured') return {ok:false,ip:null,reason:'Proxy is not configured.'};
    if(testPromise) return testPromise;
    testPromise=(async()=>{
      try{
        const eff=await effective();
        if(eff?.levelOfControl && !['controlled_by_this_extension','controllable_by_this_extension'].includes(eff.levelOfControl)){
          return {ok:false,ip:null,reason:`Chrome proxy settings are controlled by ${eff.levelOfControl}.`};
        }
        const timeoutMs=Math.max(1000,Math.min(20000,Number(options?.timeoutMs)||10000));
        const controller=new AbortController();
        const timer=setTimeout(()=>controller.abort(),timeoutMs);
        try{
          // Service-worker fetch goes through the active Chrome proxy without
          // opening, activating, or repeatedly creating a browser tab.
          const response=await fetch(CS.CONFIG.ipCheckUrl,{cache:'no-store',redirect:'follow',headers:{Accept:'application/json'},signal:controller.signal});
          const body=await response.text();
          if(!response.ok) throw new Error(`Proxy health endpoint returned HTTP ${response.status}.`);
          let ip='';
          try{ip=String(JSON.parse(body)?.ip||'').trim();}
          catch{const m=String(body).match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/);ip=m?m[0]:'';}
          if(!ip) throw new Error('The proxy returned no public IP. Check host, port and authentication.');
          if(p.expectedIp && ip!==p.expectedIp)return {ok:false,ip,reason:`Unexpected public IP: ${ip} (expected ${p.expectedIp}).`};
          return {ok:true,ip,reason:'Proxy is working'};
        } finally { clearTimeout(timer); }
      }catch(e){
        const base=String(e?.message||e);
        return {ok:false,ip:null,reason:friendlyProxyError(lastProxyError||base)};
      } finally { testPromise=null; }
    })();
    return testPromise;
  }

  function installAuthListener(){
    if(authInstalled||!chrome.webRequest?.onAuthRequired)return;authInstalled=true;
    chrome.webRequest.onAuthRequired.addListener((details,cb)=>{(async()=>{try{
      if(!details.isProxy)return cb({cancel:false});
      const count=authAttempts.get(details.requestId)||0;
      if(count>=2){authAttempts.delete(details.requestId);return cb({cancel:true});}
      authAttempts.set(details.requestId,count+1);setTimeout(()=>authAttempts.delete(details.requestId),15000);
      const r=await CS.Store.get('activeProxyCredentials');
      const p=r.activeProxyCredentials;
      if(!p?.username)return cb({cancel:true});
      return cb({authCredentials:{username:String(p.username),password:String(p.password||'')}});
    }catch{return cb({cancel:true});}})();return true;},{urls:['<all_urls>']},['asyncBlocking']);
  }

  function installProxyErrorListener(handler){
    if(errorInstalled||!chrome.proxy?.onProxyError)return;errorInstalled=true;
    chrome.proxy.onProxyError.addListener(d=>{
      lastProxyError=friendlyProxyError(d?.error||d?.details||'Chrome reported a proxy error.');
      try{handler?.({...d,error:lastProxyError});}catch{}
    });
  }
  async function setActiveCredentials(raw){const p=normalize(raw);await CS.Store.set({activeProxyCredentials:p.mode==='fixed_servers'?{username:p.username,password:p.password}:null});}
  return {normalize,apply,clear,effective,test,installAuthListener,installProxyErrorListener,setActiveCredentials,friendlyProxyError};
})();
