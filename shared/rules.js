globalThis.CS = globalThis.CS || {};
CS.Rules = (() => {
  const FIREBASE_HOSTS=['thdxsonrjazeoadhidbx.supabase.co','thdxsonrjazeoadhidbx.supabase.co','thdxsonrjazeoadhidbx.supabase.co'];
  const HTTP_TYPES=['main_frame','sub_frame','xmlhttprequest','script','image','stylesheet','font','media','object','other','ping','websocket'];
  const MAIN=['main_frame'];
  async function clear(){const r=await chrome.declarativeNetRequest.getDynamicRules();if(r.length)await chrome.declarativeNetRequest.updateDynamicRules({removeRuleIds:r.map(x=>x.id)});}
  function hostRegex(host){
    const h=String(host||'').replace(/^\./,'').toLowerCase();
    const escaped=h.replace(/[.*+?^${}()|[\]\\]/g,'\\$&');
    return `^https?:\\/\\/(?:[^\\/]+\\.)?${escaped}(?::\\d+)?(?:[\\/]|$)`;
  }
  function allowHost(id,host,types=MAIN){
    return{id,priority:1000,action:{type:'allow'},condition:{regexFilter:hostRegex(host),resourceTypes:types}};
  }
  function blockAllWeb(){return{id:1,priority:1,action:{type:'block'},condition:{regexFilter:'^https?://',resourceTypes:HTTP_TYPES}};}
  function blockUnauthorizedWebsites(){
    return{
      id:1,
      priority:1,
      action:{type:'redirect',redirect:{extensionPath:'/unauthorized-website.html'}},
      condition:{regexFilter:'^https?://',resourceTypes:MAIN}
    };
  }
  function blockSecurityNavigations(warningKind='device'){
    const kind=String(warningKind||'device').toLowerCase();
    const page=kind==='extension'?'unauthorized-extension.html':'unauthorized-device.html';
    return{
      id:1,
      priority:1,
      action:{type:'redirect',redirect:{extensionPath:`/${page}`}},
      condition:{regexFilter:'^https?://',resourceTypes:MAIN}
    };
  }
  function infra(){return FIREBASE_HOSTS.map((h,i)=>allowHost(10+i,h,['xmlhttprequest','script','other']));}
  function ipTestRule(){return allowHost(20,'api.ipify.org',['main_frame','xmlhttprequest','script','other']);}
  function uniqueSites(sites){const seen=new Set();return(sites||[]).filter(s=>s&&s.hostname&&(!seen.has(s.id)&&(seen.add(s.id),true))).slice(0,100);}
  function siteScopeHostname(hostname){
    const host=String(hostname||'').replace(/^\./,'').trim().toLowerCase();
    if(!host)return '';
    const parts=host.split('.').filter(Boolean);
    return parts.length>=3 ? parts.slice(-2).join('.') : host;
  }
  function siteAllows(sites){
    return uniqueSites(sites).map((s,i)=>allowHost(100+i,siteScopeHostname(s.hostname),MAIN));
  }
  function blockedPatterns(sites){
    const rules=[];let id=2000;
    for(const site of uniqueSites(sites)) for(const pattern of (site.blockedPatterns||[]).slice(0,500)){
      rules.push({
        id:id++,
        priority:3000,
        action:{type:'redirect',redirect:{extensionPath:'/unauthorized-website.html'}},
        condition:{urlFilter:String(pattern),resourceTypes:MAIN}
      });
      if(id>=3900) return rules;
    }
    return rules;
  }
  async function applyNavigationPolicy(sites,{locked=false,testEnabled=false,warningKind='device'}={}){
    await clear();
    const rules=[locked?blockSecurityNavigations(warningKind):blockUnauthorizedWebsites(),...infra()];
    if(testEnabled) rules.push(ipTestRule());
    if(!locked) rules.push(...siteAllows(sites),...blockedPatterns(sites));
    await chrome.declarativeNetRequest.updateDynamicRules({addRules:rules});
    await CS.Store.set({networkLockdown:!!locked});
  }
  return {applyNavigationPolicy};
})();
