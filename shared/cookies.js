globalThis.CS = globalThis.CS || {};
CS.Cookies = (() => {
  function belongs(cookie, site) {
    // A managed site owns its host and its entire subdomain tree.
    // Include both:
    //   dat.com cookies when the managed site is auth.dat.com, and
    //   auth.dat.com cookies when the managed site is dat.com.
    // The second direction is the important part for full login/session
    // capture because authentication cookies are commonly scoped to a
    // dedicated subdomain.
    const d=String(cookie.domain||'').replace(/^\./,'').toLowerCase();
    const host=String(site?.hostname||'').replace(/^\./,'').toLowerCase();
    if(!d || !host) return false;
    return CS.Util.hostnameMatches(d,host) || CS.Util.hostnameMatches(host,d);
  }
  function cookieUrl(c) {
    const domain=String(c.domain||'').replace(/^\./,'');
    const scheme=c.secure?'https':'http';
    return `${scheme}://${domain}${c.path || '/'}`;
  }
  function key(c) {
    return JSON.stringify([c.name,c.domain,c.path,c.partitionKey||null,c.storeId||'']);
  }
  function syncScopeHostname(hostname) {
    const host=String(hostname||'').replace(/^\./,'').trim().toLowerCase();
    if(!host)return '';
    const parts=host.split('.').filter(Boolean);
    return parts.length>=3 ? parts.slice(-2).join('.') : host;
  }

  function getAllCookies(details={}) {
    return new Promise((resolve,reject)=>{
      try{
        chrome.cookies.getAll(details,rows=>{
          const err=chrome.runtime.lastError;
          if(err)reject(new Error(err.message||'Chrome cookies.getAll failed.'));
          else resolve(Array.isArray(rows)?rows:[]);
        });
      }catch(e){reject(e);}
    });
  }

  async function getForSite(site,pageUrl='') {
    const host=String(site?.hostname||'').replace(/^\./,'').trim().toLowerCase();
    const scope=syncScopeHostname(host);
    if(!scope)return [];
    const seen=new Map();
    const add=c=>{
      if(!c)return;
      const k=JSON.stringify([c.name||'',c.domain||'',c.path||'/',c.partitionKey||null,c.storeId||'']);
      if(!seen.has(k))seen.set(k,c);
    };

    // Proven legacy SyncMyCookies behavior: query the parent domain so all
    // dat.com subdomains participate when the configured site is one.dat.com.
    try{ for(const c of await getAllCookies({domain:scope})) add(c); }catch{}

    // Union URL-applicable cookies from the managed root and active page.
    try{
      const root=`${String(site.origin||'').replace(/\/$/,'')}/`;
      for(const c of await getAllCookies({url:root})) add(c);
    }catch{}
    try{
      const u=new URL(String(pageUrl||''));
      if(['http:','https:'].includes(u.protocol) &&
         (u.hostname===scope || u.hostname.endsWith(`.${scope}`))){
        for(const c of await getAllCookies({url:u.href})) add(c);
      }
    }catch{}

    return Array.from(seen.values()).map(c=>({
      name:c.name,value:c.value,domain:c.domain,path:c.path,
      hostOnly:c.hostOnly===true,secure:c.secure,httpOnly:c.httpOnly,
      sameSite:c.sameSite,expirationDate:c.expirationDate,session:c.session,
      storeId:c.storeId,partitionKey:c.partitionKey||undefined,url:cookieUrl(c)
    })).sort((a,b)=>key(a).localeCompare(key(b)));
  }

  async function closeAllBrowserTabs(options={}) {
    // Remove all existing tabs without allowing Chrome to close the browser/window.
    // Chrome windows must retain at least one tab, so create a safe replacement
    // in each normal window and remove every previous tab.
    // When a proxy rotation triggers cleanup, the replacement can be a dedicated
    // LogIn DAT setup page instead of about:blank.
    const replacementUrl=String(options?.replacementUrl||'about:blank');
    try {
      if(!chrome.windows?.getAll || !chrome.tabs?.query || !chrome.tabs?.create || !chrome.tabs?.remove){
        return{ok:false,attempted:0,closed:0,failed:1,error:'Chrome tab/window APIs are unavailable.'};
      }
      const windows=await chrome.windows.getAll({windowTypes:['normal']});
      if(!Array.isArray(windows)||!windows.length)return{ok:true,attempted:0,closed:0,failed:0};

      let attempted=0,closed=0,failed=0;
      for(const win of windows){
        const tabs=await chrome.tabs.query({windowId:win.id}).catch(()=>[]);
        if(!Array.isArray(tabs))continue;

        // One replacement tab keeps the normal browser window alive.
        let keepId=null;
        try{
          const replacement=await chrome.tabs.create({windowId:win.id,url:replacementUrl,active:Number(win.focused)===1});
          keepId=Number(replacement?.id);
        }catch(e){
          failed++;
          continue;
        }

        const removeIds=tabs
          .map(t=>Number(t.id))
          .filter(id=>Number.isInteger(id)&&id>=0&&id!==keepId);
        attempted+=removeIds.length;
        if(removeIds.length){
          try{
            await chrome.tabs.remove(removeIds);
            closed+=removeIds.length;
          }catch{
            // Some tabs can disappear during cleanup. Count remaining tabs so
            // a later retry can finish without ever closing the browser.
            for(const id of removeIds){
              const exists=await chrome.tabs.get(id).then(()=>true).catch(()=>false);
              if(exists)failed++; else closed++;
            }
          }
        }
      }
      return{ok:failed===0,attempted,closed,failed,error:failed?'Some browser tabs could not be closed.':undefined};
    }catch(e){
      return{ok:false,attempted:0,closed:0,failed:1,error:e?.message||String(e)};
    }
  }

  async function clearAllBrowserData() {
    // Full normal browser-data reset for an actual proxy rotation. Extension
    // storage is intentionally untouched so Firebase auth/device identity
    // survives. Saved passwords/autofill remain untouched.
    return chrome.browsingData.remove(
      {since:0,originTypes:{unprotectedWeb:true,protectedWeb:false,extension:false}},
      {
        appcache:true,
        cache:true,
        cacheStorage:true,
        cookies:true,
        downloads:true,
        fileSystems:true,
        formData:true,
        history:true,
        indexedDB:true,
        localStorage:true,
        serviceWorkers:true,
        webSQL:true
      }
    );
  }

  async function clearOrigin(site) {
    if (!site) return;
    const current = await getForSite(site).catch(()=>[]);
    await Promise.all(current.map(c => chrome.cookies.remove({
      url:cookieUrl(c),name:c.name,storeId:c.storeId,partitionKey:c.partitionKey
    }).catch(()=>null)));
    const origins = [site.origin];
    try {
      const u = new URL(site.origin);
      const other = `${u.protocol === 'https:' ? 'http:' : 'https:'}//${u.host}`;
      if (other !== site.origin) origins.push(other);
    } catch {}
    return chrome.browsingData.remove({origins}, {
      cache:true,cookies:true,cacheStorage:true,fileSystems:true,indexedDB:true,localStorage:true,serviceWorkers:true
    });
  }
  async function setCookie(details) {
    return new Promise(resolve=>{
      try{
        chrome.cookies.set(details,()=>{
          const err=chrome.runtime.lastError;
          resolve(err?{ok:false,error:err.message||'Cookie set failed.'}:{ok:true});
        });
      }catch(e){resolve({ok:false,error:e?.message||String(e)});}
    });
  }

  async function reconcile(site, records) {
    // True merge: match the behavior of SyncMyCookies. Never delete a client
    // cookie merely because it wasn't present in the Admin snapshot.
    let set=0,failed=0;
    const errors=[];
    for(const c of records||[]){
      const details={
        url:c.url,name:c.name,value:c.value,path:c.path,
        secure:!!c.secure,httpOnly:!!c.httpOnly
      };
      if(c.sameSite)details.sameSite=c.sameSite;
      if(c.hostOnly!==true && c.domain)details.domain=c.domain;
      if(!c.session && c.expirationDate)details.expirationDate=c.expirationDate;
      if(c.storeId)details.storeId=c.storeId;
      if(c.partitionKey)details.partitionKey=c.partitionKey;
      const r=await setCookie(details);
      if(r.ok)set++;
      else{
        failed++;
        if(errors.length<12)errors.push({name:c.name||'',domain:c.domain||'',message:r.error});
      }
    }
    return{removed:0,set,failed,errors};
  }
  async function makeSnapshot(site, version, requiredProxyVersion, requiredResetVersion, pageUrl='') {
    const cookies=await getForSite(site,pageUrl);
    const payload={siteId:site.id,origin:site.origin,version,requiredProxyVersion:Number(requiredProxyVersion||0),requiredResetVersion:Number(requiredResetVersion||0),createdAt:CS.Util.now(),cookies};
    const size=new TextEncoder().encode(JSON.stringify(payload)).byteLength;
    if(size>700000) throw new Error(`Cookie snapshot is too large (${Math.round(size/1024)} KB).`);
    return payload;
  }
  return {getForSite,clearOrigin,closeAllBrowserTabs,clearAllBrowserData,reconcile,makeSnapshot};
})();