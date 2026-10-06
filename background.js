/* Cookie Sync Client v9.2 reset-safe device authorization + proxy recovery */
importScripts('shared/config.js','shared/util.js','shared/store.js','shared/firebase.js','shared/auth.js','shared/crypto.js','shared/cookies.js','shared/proxy.js','shared/rules.js','shared/security.js','shared/sync.js');

CS.Proxy.installAuthListener();

let runningPromise=null;
let proxyRecoveryPromise=null;
const PROXY_HEALTH_ALARM='cookie-sync-proxy-health';
const PROXY_ROTATION_CLEANUP_ALARM='cookie-sync-proxy-rotation-cleanup';
const MANUAL_SHARE_OPEN_ALARM='cookie-sync-manual-share-open';
const PROXY_RECOVERY_MAX_ATTEMPTS=4;
const PROXY_RECOVERY_DELAYS=[0,1200,3000,5000];
async function ensureManualShareOpenAlarm(){
  if(!chrome.alarms?.create)return;
  try{await chrome.alarms.create(MANUAL_SHARE_OPEN_ALARM,{delayInMinutes:0.5,periodInMinutes:0.5});}catch{}
}

async function checkManualShareOpen(){
  try{
    const me=await CS.Auth.currentProfile(false).catch(()=>null);
    if(!me?.session?.idToken)return;
    const sites=await loadSites(me,{force:false});
    if(!Array.isArray(sites)||!sites.length)return;
    const local=await CS.Store.get([
      'lastAdminBrowserRefreshAt',
      'lastAdminBrowserRefreshSubadminUid',
      'lastTargetedBrowserRefreshAt',
      'lastTargetedBrowserRefreshUid',
      'manualShareOpenedVersions',
      'clientLoginSessionStartedAt'
    ]).catch(()=>({}));
    const localSub=String(local.lastAdminBrowserRefreshSubadminUid||'');
    const localAt=Number(local.lastAdminBrowserRefreshAt||0);
    const targetedUid=String(local.lastTargetedBrowserRefreshUid||'');
    const targetedAt=Number(local.lastTargetedBrowserRefreshAt||0);
    const opened={...(local.manualShareOpenedVersions||{})};
    const sessionStartedAt=Number(local.clientLoginSessionStartedAt||0);
    // Refresh/share events are bound to the current client login session.
    // Historical requests must never replay during login or a later worker wake.
    if(!sessionStartedAt){
      await CS.Store.set({clientLoginSessionStartedAt:Date.now()}).catch(()=>{});
    }
    const activeSessionStartedAt=sessionStartedAt||Date.now();
    // Do not replay an Admin refresh signal that predates this client account.
    // A newly-created account must perform only its own first-device cleanup
    // and must not inherit an older global/targeted refresh request merely
    // because the request is still present in the latest snapshot.
    const accountCreatedAt=Date.parse(String(me.profile.createdAt||''));
    const accountCreatedMs=Number.isFinite(accountCreatedAt)?accountCreatedAt:0;
    let changed=false;
    let key=null;
    const pendingManualShares=[];

    for(const site of sites){
      const r=await CS.Firebase.getDoc(['sites',site.id,'sync','latest'],me.session.idToken).catch(()=>({exists:false,data:null}));
      if(!r.exists||!r.data)continue;
      const snap=r.data;
      const reason=String(snap.reason||'');

      if(reason.startsWith('admin-refresh-user:')){
        const signalAt=Date.parse(String(snap.publishedAt||''));
        const signal=Number.isFinite(signalAt)?signalAt:0;
        const targetUid=reason.slice('admin-refresh-user:'.length).trim();
        if(targetUid===String(me.session.uid||'') && (targetedUid!==targetUid || signal>targetedAt)){
          if(signal>0 && signal<=activeSessionStartedAt){
            await CS.Store.set({
              lastTargetedBrowserRefreshAt:signal,
              lastTargetedBrowserRefreshUid:targetUid
            }).catch(()=>{});
            continue;
          }
          if(signal>0 && accountCreatedMs>0 && signal<=accountCreatedMs){
            // This targeted refresh was published before the client account
            // existed, so acknowledge it without touching the browser.
            await CS.Store.set({
              lastTargetedBrowserRefreshAt:signal,
              lastTargetedBrowserRefreshUid:targetUid
            }).catch(()=>{});
            continue;
          }
          // A cleanup closes tabs and may recreate service-worker execution state.
          // Persist the acknowledgement before cleanup so the same command cannot
          // run again merely because the Client logs in again.
          const handledAt=signal||Date.now();
          await CS.Store.set({
            lastTargetedBrowserRefreshAt:handledAt,
            lastTargetedBrowserRefreshUid:targetUid
          }).catch(()=>{});

          const refreshed=await refreshChromeForClient({remoteAdmin:true,profileRefresh:true}).catch(()=>({ok:false}));
          if(refreshed?.ok)return;

          await CS.Store.remove([
            'lastTargetedBrowserRefreshAt',
            'lastTargetedBrowserRefreshUid'
          ]).catch(()=>{});
        }
        continue;
      }

      if(reason==='admin-refresh-users'){
        const signalAt=Date.parse(String(snap.publishedAt||''));
        const signal=Number.isFinite(signalAt)?signalAt:0;
        const refreshSubadmin=String(me.profile.subadminUid||'');
        if(localSub!==refreshSubadmin || signal>localAt){
          if(signal>0 && signal<=activeSessionStartedAt){
            await CS.Store.set({
              lastAdminBrowserRefreshAt:signal,
              lastAdminBrowserRefreshSubadminUid:refreshSubadmin
            }).catch(()=>{});
            continue;
          }
          if(signal>0 && accountCreatedMs>0 && signal<=accountCreatedMs){
            // A global refresh published before this client account was created
            // is stale for this account. Acknowledge it without a browser wipe
            // or the `chrome-refreshed.html` page.
            await CS.Store.set({
              lastAdminBrowserRefreshAt:signal,
              lastAdminBrowserRefreshSubadminUid:refreshSubadmin
            }).catch(()=>{});
            continue;
          }
          // A browser-data cleanup can close tabs and recreate execution state.
          // Mark this exact refresh signal as handled BEFORE starting cleanup so
          // signing in again cannot replay the same Admin refresh event.
          const handledAt=signal||Date.now();
          await CS.Store.set({
            lastAdminBrowserRefreshAt:handledAt,
            lastAdminBrowserRefreshSubadminUid:refreshSubadmin
          }).catch(()=>{});

          const refreshed=await refreshChromeForClient({remoteAdmin:true}).catch(()=>({ok:false}));
          if(refreshed?.ok)return;

          // Cleanup failed: remove the optimistic acknowledgement so the normal
          // background alarm can retry the same refresh event later.
          await CS.Store.remove([
            'lastAdminBrowserRefreshAt',
            'lastAdminBrowserRefreshSubadminUid'
          ]).catch(()=>{});
        }
        continue;
      }

      if(reason!=='manual')continue;
      const version=Number(snap.version||0);
      if(version<=0)continue;
      if(Number(opened[String(site.id)]||0)>=version)continue;
      const publishedAtMs=Date.parse(String(snap.publishedAt||''));
      if(Number.isFinite(publishedAtMs) && publishedAtMs<=activeSessionStartedAt){
        // Login already retrieves the latest snapshot. Only a Share Login push
        // published during this active session may trigger the special auto-open.
        continue;
      }

      // Queue the pending Share Login event. We sync once for the whole client,
      // then open each newly shared site only after its exact snapshot version
      // is confirmed as applied (or was already applied by another lifecycle).
      pendingManualShares.push({site,version});
    }

    if(pendingManualShares.length){
      const syncResult=await syncLatestCookies({fresh:false,reloadTabs:false}).catch(()=>null);
      const diagnostics=Array.isArray(syncResult?.syncDiagnostics)?syncResult.syncDiagnostics:[];

      for(const pending of pendingManualShares){
        const siteId=String(pending.site.id);
        const diag=diagnostics.find(x=>String(x?.siteId||'')===siteId && Number(x?.version||0)===pending.version);
        const synced=diag && (diag.status==='applied' || diag.status==='already-applied');
        if(!synced)continue;

        const target=String(pending.site.origin||(`https://${String(pending.site.hostname||'').replace(/^\.+/,'')}`)||'').trim();
        if(!/^https?:\/\//i.test(target))continue;

        try{
          await chrome.tabs.create({url:target,active:true});
          opened[siteId]=pending.version;
          changed=true;
        }catch{}
      }
    }

    if(changed)await CS.Store.set({manualShareOpenedVersions:opened}).catch(()=>{});
  }catch{}
}

async function ensureProxyHealthAlarm(){
  if(!chrome.alarms?.create)return;
  try{await chrome.alarms.create(PROXY_HEALTH_ALARM,{delayInMinutes:0.5,periodInMinutes:0.5});}catch{}
}
let proxyRecoveryRunning=false;

async function cachedState(){
  const s=await CS.Auth.raw();
  const p=await CS.Auth.cached();
  const c=await CS.Store.get(['clientSitesCache','clientLastState','clientLockReason','clientProxyHealth','clientSuspendedReason']);
  return{session:s?{uid:s.uid,email:s.email}:null,profile:p,sites:Array.isArray(c.clientSitesCache)?c.clientSitesCache:[],lastState:c.clientLastState||null,lockReason:c.clientLockReason||null,suspendedReason:c.clientSuspendedReason||null,proxyHealth:c.clientProxyHealth||null};
}
async function getSubStatus(me,{force=false}={}){
  if(!me.profile.subadminUid)throw new Error('This client account has no assigned Admin Extension.');
  const sub=String(me.profile.subadminUid);
  const local=await CS.Store.get(['clientSubStatusCache','clientSubStatusCacheAt','clientSubStatusCacheSubadminUid']).catch(()=>({}));
  const age=Date.now()-Number(local.clientSubStatusCacheAt||0);
  if(!force && local.clientSubStatusCacheSubadminUid===sub && age>=0 && age<15000 && local.clientSubStatusCache){
    return local.clientSubStatusCache;
  }
  const r=await CS.Firebase.getDoc(['users',sub,'control','status'],me.session.idToken);
  const status=r.exists?r.data:{active:true};
  await CS.Store.set({clientSubStatusCache:status,clientSubStatusCacheAt:Date.now(),clientSubStatusCacheSubadminUid:sub}).catch(()=>{});
  return status;
}
async function loadSites(me,{force=false}={}){
  const sub=String(me.profile.subadminUid||'').trim();
  if(!sub)throw new Error('This client account has no assigned Admin Extension.');
  const local=await CS.Store.get(['clientSitesCache','clientSitesCacheAt','clientSitesCacheSubadminUid']).catch(()=>({}));
  const age=Date.now()-Number(local.clientSitesCacheAt||0);
  if(!force && local.clientSitesCacheSubadminUid===sub && age>=0 && age<10000 && Array.isArray(local.clientSitesCache)){
    return local.clientSitesCache;
  }

  let sites=[];
  // Main Admin-created clients inherit every currently active website of their
  // assigned Admin Extension. The list is refreshed explicitly by login or
  // Fresh Sync, and is briefly cached for background/proxy recovery runs.
  if(me.profile.visibleToSubadmin===false){
    const docs=await CS.Firebase.queryDocsByField(['sites'],'subadminUid','EQUAL',sub,me.session.idToken);
    sites=docs
      .filter(d=>d.data?.active!==false&&d.data?.enabled!==false)
      .map(d=>({id:d.id,...d.data}))
      .sort((a,b)=>String(a.name||a.hostname).localeCompare(String(b.name||b.hostname)));
  }else{
    let siteIds=[];
    try{
      const access=await CS.Firebase.getDoc(['clientAccess',me.session.uid],me.session.idToken);
      if(access.exists&&Array.isArray(access.data?.siteIds))siteIds=access.data.siteIds.map(String);
    }catch{}
    if(!siteIds.length&&Array.isArray(me.profile.siteIds))siteIds=me.profile.siteIds.map(String);
    if(!siteIds.length&&me.profile.siteId)siteIds=[String(me.profile.siteId)];
    sites=(await Promise.all(siteIds.map(async siteId=>{
      const r=await CS.Firebase.getDoc(['sites',siteId],me.session.idToken).catch(()=>({exists:false}));
      if(!r.exists||r.data?.active===false||r.data?.enabled===false)return null;
      if(String(r.data?.subadminUid||'')!==sub)return null;
      return{id:siteId,...r.data};
    }))).filter(Boolean);
  }
  await CS.Store.set({clientSitesCache:sites,clientSitesCacheAt:Date.now(),clientSitesCacheSubadminUid:sub}).catch(()=>{});
  return sites;
}
async function clearAllManaged(sites, reason){
  const message=String(reason||'Access locked.');
  await CS.Store.set({
    clientLockReason:message,
    clientProxyHealth:{ok:false,ip:null,reason:message,checkedAt:Date.now()}
  }).catch(()=>{});
  for(const site of sites||[]) await CS.Cookies.clearOrigin(site).catch(()=>{});
  await CS.Rules.applyNavigationPolicy(sites||[],{locked:true,testEnabled:false}).catch(()=>{});
}

globalThis.clearAllManaged = clearAllManaged;

async function getDeviceBinding(){
  const r=await CS.Store.get(['deviceBindingUid','deviceBindingId','deviceBindingResetVersion']);
  return {
    uid:String(r.deviceBindingUid||''),
    deviceId:String(r.deviceBindingId||''),
    resetVersion:Number(r.deviceBindingResetVersion||0)
  };
}

async function rememberDeviceBinding(uid,deviceId,resetVersion){
  await CS.Store.set({
    deviceBindingUid:String(uid||''),
    deviceBindingId:String(deviceId||''),
    deviceBindingResetVersion:Number(resetVersion||0)
  });
}

async function ensureOneDatBookmark(){
  if(!chrome.bookmarks?.getTree || !chrome.bookmarks?.create || !chrome.bookmarks?.search)return false;
  try{
    const existing=await chrome.bookmarks.search({url:'https://one.dat.com/'});
    if(Array.isArray(existing) && existing.some(b=>String(b.url||'').replace(/\/$/,'')==='https://one.dat.com'))return true;

    const roots=await chrome.bookmarks.getTree();
    const bar=roots?.[0]?.children?.find(n=>n?.id==='1' || n?.title==='Bookmarks bar');
    const parentId=bar?.id||'1';
    await chrome.bookmarks.create({parentId,title:'one.dat.com',url:'https://one.dat.com/'});
    return true;
  }catch{return false;}
}

async function ensureFirstRegistrationSetup(deviceResult,{openWelcome=true}={}){
  if(!deviceResult?.newlyRegistered)return;
  await ensureOneDatBookmark().catch(()=>{});

  // Show the welcome page only once for the first successful device
  // registration. It opens as a normal browser tab and never as a popup.
  const session=await CS.Auth.raw().catch(()=>null);
  const uid=String(session?.uid||'');
  if(!uid)return;
  const flagKey=`firstRegistrationWelcomeShown:${uid}`;
  const existing=await CS.Store.get(flagKey).catch(()=>({}));
  if(existing[flagKey]||!openWelcome)return;
  try{
    // Set the durable one-time marker BEFORE opening the tab.  Multiple
    // startup/login paths can otherwise observe the missing marker at the
    // same time and each open a second welcome page.
    await CS.Store.set({[flagKey]:Date.now()});
    await chrome.tabs.create({url:chrome.runtime.getURL('welcome.html'),active:true});
  }catch{}
}

function syncScopeHostname(hostname){
  const host=String(hostname||'').replace(/^\./,'').trim().toLowerCase();
  if(!host)return '';
  const parts=host.split('.').filter(Boolean);
  return parts.length>=3 ? parts.slice(-2).join('.') : host;
}
function managedUrlForSites(url, sites){
  try{
    const u=new URL(String(url||''));
    if(!['http:','https:'].includes(u.protocol)) return false;
    return (sites||[]).some(s=>s && CS.Util.hostnameMatches(syncScopeHostname(s.hostname),u.hostname));
  }catch{return false;}
}
function waitingUrl(target){
  return `${chrome.runtime.getURL('waiting.html')}?target=${encodeURIComponent(String(target||''))}`;
}
async function holdLoadingTab(tabId, target){
  try{
    if(!Number.isInteger(Number(tabId)) || Number(tabId)<0)return;
    await chrome.tabs.update(Number(tabId),{url:waitingUrl(target)});
  }catch{}
}
async function holdCurrentlyLoadingTabs(sites){
  try{
    const tabs=await chrome.tabs.query({});
    for(const tab of tabs){
      if(tab?.id==null || tab.status!=='loading' || !managedUrlForSites(tab.url,sites)) continue;
      await holdLoadingTab(tab.id,tab.url);
    }
  }catch{}
}

// A managed tab can occasionally remain in Chrome's loading state after a
// transient proxy/tunnel failure without emitting a useful proxy error event.
// Watch only managed top-level navigations and only intervene after a sustained
// 15-second loading state. A healthy proxy leaves the page completely alone.
const loadingWatchTimers=new Map();
function clearLoadingWatch(tabId){
  const id=Number(tabId);
  const timer=loadingWatchTimers.get(id);
  if(timer){clearTimeout(timer);loadingWatchTimers.delete(id);}
}
async function cachedManagedSites(){
  const r=await CS.Store.get('clientSitesCache').catch(()=>({}));
  return Array.isArray(r.clientSitesCache)?r.clientSitesCache:[];
}
function watchManagedLoadingTab(tabId,target){
  const id=Number(tabId);
  if(!Number.isInteger(id)||id<0||!/^https?:\/\//i.test(String(target||'')))return;
  clearLoadingWatch(id);
  const timer=setTimeout(async()=>{
    loadingWatchTimers.delete(id);
    try{
      const tab=await chrome.tabs.get(id);
      const sites=await cachedManagedSites();
      if(!tab || tab.status!=='loading' || !managedUrlForSites(tab.url,sites))return;
      const r=await CS.Store.get('lastSavedProxyConfig').catch(()=>({}));
      const proxy=r.lastSavedProxyConfig;
      if(!proxy || proxy.mode!=='fixed_servers')return;
      const health=await CS.Proxy.test(proxy,{timeoutMs:8000});
      if(health?.ok===true)return;
      await beginProxyRecovery(health?.reason||'Managed website remained loading while the proxy was unavailable.');
      const current=await chrome.tabs.get(id).catch(()=>null);
      if(current && current.status==='loading')await holdLoadingTab(id,current.url||target);
    }catch{}
  },15000);
  loadingWatchTimers.set(id,timer);
}
chrome.tabs?.onRemoved?.addListener(tabId=>clearLoadingWatch(tabId));
async function saveProxyRecoveryState(patch={}){
  const r=await CS.Store.get('proxyRecoveryState').catch(()=>({}));
  const prev=r.proxyRecoveryState||{};
  const sameIncident=prev.active===true;
  const next={
    active:true,
    startedAt:sameIncident ? (Number(prev.startedAt)||Date.now()) : Date.now(),
    attempts:sameIncident ? (Number(prev.attempts)||0) : 0,
    lastError:sameIncident ? String(prev.lastError||'') : '',
    confirmedFailed:false,
    ...patch
  };
  await CS.Store.set({proxyRecoveryState:next,clientProxyHealth:{ok:false,pending:true,ip:null,reason:String(next.lastError||'Reconnecting to proxy…'),checkedAt:Date.now()}}).catch(()=>{});
  return next;
}
async function beginProxyRecovery(reason){
  const sites=(await CS.Store.get('clientSitesCache')).clientSitesCache||[];
  await saveProxyRecoveryState({lastError:String(reason||'Proxy connection interrupted.')});
  await CS.Store.remove(['clientLockReason']).catch(()=>{});
  // Do not block the managed sites immediately. Hold/redirect only the tabs
  // that are actually trying to navigate while the background reconnect runs.
  await CS.Rules.applyNavigationPolicy(sites,{locked:false,testEnabled:false}).catch(()=>{});
  await holdCurrentlyLoadingTabs(sites);
  ensureProxyHealthAlarm().catch(()=>{});
  if(!proxyRecoveryPromise) setTimeout(()=>recoverProxyInBackground().catch(()=>{}),0);
}
async function confirmProxyFailure(reason){
  const sites=(await CS.Store.get('clientSitesCache')).clientSitesCache||[];
  const message=String(reason||'Proxy could not be restored after repeated checks.');
  await CS.Store.set({
    proxyRecoveryState:{active:false,confirmedFailed:true,startedAt:Date.now(),attempts:PROXY_RECOVERY_MAX_ATTEMPTS,lastError:message},
    clientProxyHealth:{ok:false,pending:false,ip:null,reason:message,checkedAt:Date.now()}
  }).catch(()=>{});
  // Only after repeated failed checks do we fail closed. The health endpoint
  // remains reachable so a later manual/background check can recover.
  await CS.Rules.applyNavigationPolicy(sites,{locked:true,testEnabled:true}).catch(()=>{});
}
async function recoverProxyInBackground(){
  if(proxyRecoveryPromise)return proxyRecoveryPromise;
  const existing=await CS.Store.get('proxyRecoveryState').catch(()=>({}));
  if(existing.proxyRecoveryState?.active!==true && existing.proxyRecoveryState?.confirmedFailed!==true)return null;
  proxyRecoveryPromise=(async()=>{
    proxyRecoveryRunning=true;
    try{
      let lastReason='Proxy is not working.';
      for(let i=0;i<PROXY_RECOVERY_MAX_ATTEMPTS;i++){
        if(i) await CS.Util.sleep(PROXY_RECOVERY_DELAYS[i]||1500);
        const state=await saveProxyRecoveryState({attempts:i,lastError:lastReason});
        if(Date.now()-Number(state.startedAt||Date.now())>30000)break;
        try{
          const result=await clientStep({forceProxyTest:true,freshSync:false,deferProxyTest:false,allowDeviceReset:false,recoveryAttempt:true,syncCookies:false});
          if(result?.health?.ok===true){
            await CS.Store.set({proxyRecoveryState:{active:false,confirmedFailed:false,startedAt:state.startedAt,attempts:i+1,lastError:''},clientProxyHealth:{...result.health,pending:false}}).catch(()=>{});
            return result;
          }
          lastReason=String(result?.health?.reason||result?.error||'Proxy is not working.');
        }catch(e){ lastReason=String(e?.message||e||lastReason); }
      }
      await confirmProxyFailure(lastReason);
      return{ok:true,proxyFailed:true,health:{ok:false,pending:false,reason:lastReason}};
    }finally{
      proxyRecoveryRunning=false;
      proxyRecoveryPromise=null;
    }
  })();
  return proxyRecoveryPromise;
}
async function lockForProxyFailure(reason){
  await beginProxyRecovery(reason);
}

async function ensureProxyRotationCleanupAlarm(){
  if(!chrome.alarms?.create)return;
  try{await chrome.alarms.create(PROXY_ROTATION_CLEANUP_ALARM,{delayInMinutes:0.5});}catch{}
}

async function cleanupAfterProxyRotation(subadminId,proxyVersion){
  const sub=String(subadminId||'');
  const version=Number(proxyVersion||0);
  if(!sub || !version)return{ok:true};
  const rotationCloseKey=`proxyRotationTabsClosed:${sub}`;
  const rotationClearKey=`proxyRotationDataCleared:${sub}`;
  const pendingKey='proxyRotationCleanupPending';
  const local=await CS.Store.get([rotationCloseKey,rotationClearKey,pendingKey]).catch(()=>({}));

  let tabsClosedVersion=Number(local[rotationCloseKey]||0);
  let dataClearedVersion=Number(local[rotationClearKey]||0);

  if(tabsClosedVersion<version){
    const setupUrl=chrome.runtime.getURL(`proxy-setup.html?version=${encodeURIComponent(String(version))}`);
    const result=await CS.Cookies.closeAllBrowserTabs({replacementUrl:setupUrl}).catch(e=>({ok:false,error:e?.message||String(e)}));
    if(!result?.ok){
      await CS.Store.set({[pendingKey]:{subadminUid:sub,version,phase:'tabs',lastError:result?.error||`${result?.failed||1} browser tab(s) could not be closed.`,updatedAt:Date.now()}}).catch(()=>{});
      await ensureProxyRotationCleanupAlarm();
      return{ok:false,phase:'tabs',reason:result?.error||'Some browser tabs could not be closed.'};
    }
    tabsClosedVersion=version;
    await CS.Store.set({[rotationCloseKey]:version}).catch(()=>{});
  }

  if(dataClearedVersion<version){
    let clearError='';
    for(let attempt=0;attempt<2;attempt++){
      try{
        await CS.Cookies.clearAllBrowserData();
        clearError='';
        break;
      }catch(e){
        clearError=String(e?.message||e||'Browser data cleanup failed.');
        if(attempt===0)await CS.Util.sleep(750);
      }
    }
    if(clearError){
      await CS.Store.set({[pendingKey]:{subadminUid:sub,version,phase:'browser-data',lastError:clearError,updatedAt:Date.now()}}).catch(()=>{});
      await ensureProxyRotationCleanupAlarm();
      return{ok:false,phase:'browser-data',reason:clearError};
    }
    dataClearedVersion=version;
    await CS.Store.set({[rotationClearKey]:version}).catch(()=>{});
  }

  await CS.Store.remove([pendingKey]).catch(()=>{});
  return{ok:true,version,tabsClosedVersion,dataClearedVersion};
}

async function ensureDevice(me,{fast=false}={}){
  const uid=String(me.session.uid);
  const identity=await CS.Crypto.ensureDeviceIdentity();

  // Proxy recovery is a local retry loop. Reuse a recently validated device
  // record instead of hitting Firestore for the immutable claim + device
  // document on every retry. Normal login/startup/device-gate remains remote-
  // verified, and the recovery path still re-reads control/reset metadata.
  if(fast){
    const local=await CS.Store.get(['clientDeviceCache','clientDeviceCacheAt','clientDeviceCacheUid']).catch(()=>({}));
    const age=Date.now()-Number(local.clientDeviceCacheAt||0);
    const d=local.clientDeviceCache;
    if(local.clientDeviceCacheUid===uid && d &&
       age>=0 && age<15000 &&
       String(d.deviceId||'')===String(identity.deviceId||'') &&
       String(d.subadminUid||'')===String(me.profile.subadminUid||'') &&
       d.status!=='revoked'){
      return{device:d,identity};
    }
  }

  // deviceClaims is an immutable server-side claim. Unlike the old design,
  // deleting/missing /devices/{uid} can never silently make another Chrome
  // installation the owner of an already-claimed account.
  const claim=await CS.Firebase.getDoc(['deviceClaims',uid],me.session.idToken);
  const existing=await CS.Firebase.getDoc(['devices',uid],me.session.idToken);

  if(claim.exists){
    const claimedId=String(claim.data?.deviceId||'');
    if(!claimedId || claimedId!==String(identity.deviceId||'')){
      const e=new Error('This account is already registered on another Chrome device. Use Reset Device before moving it.');
      e.code='DEVICE_ALREADY_CLAIMED';
      throw e;
    }

    // A claim without a device record is an inconsistent/partially reset state.
    // Recreate only with the exact claimed device identity; never allow a new
    // installation to take over the account.
    if(!existing.exists){
      const doc={
        uid,
        subadminUid:me.profile.subadminUid,
        deviceId:identity.deviceId,
        status:'active',
        extensionVersion:CS.CONFIG.version,
        lastSeenAt:CS.Util.now(),
        lastProxyVersion:0,lastResetVersion:0,lastSyncVersion:0,
        lastSyncVersionBySite:{},lastSyncAt:'',lastIp:'',proxyHealthy:false,
        claimedAt:claim.data?.claimedAt||CS.Util.now()
      };
      try{ await CS.Firebase.createDoc(['devices',uid],doc,me.session.idToken); await cacheDevice(doc); return{device:doc,identity,newlyRegistered:true}; }
      catch(e){
        const fresh=await CS.Firebase.getDoc(['devices',uid],me.session.idToken);
        if(!fresh.exists) throw e;
        if(String(fresh.data?.deviceId||'')!==String(identity.deviceId)){
          const x=new Error('This account is already registered on another Chrome device. Use Reset Device before moving it.');
          x.code='DEVICE_ALREADY_CLAIMED'; throw x;
        }
        return validateExisting(fresh.data,identity,me);
      }
    }

    return validateExisting(existing.data,identity,me);
  }

  // Legacy migration: an existing device record is authoritative. Only that
  // exact device can create the immutable claim.
  if(existing.exists){
    if(String(existing.data?.deviceId||'')!==String(identity.deviceId||'')){
      const e=new Error('This account is already registered on another Chrome device. Use Reset Device before moving it.');
      e.code='DEVICE_ALREADY_CLAIMED'; throw e;
    }
    await createClaimOrValidate(identity,existing.data);
    return validateExisting(existing.data,identity,me);
  }

  // Truly unclaimed account. Creating the claim is atomic in Firestore, so if
  // two Chrome installations race, exactly one becomes the owner.
  const claimDoc={uid,deviceId:identity.deviceId,claimedAt:CS.Util.now(),status:'claimed'};
  try{
    await CS.Firebase.createDoc(['deviceClaims',uid],claimDoc,me.session.idToken);
  }catch(e){
    const fresh=await CS.Firebase.getDoc(['deviceClaims',uid],me.session.idToken);
    if(!fresh.exists) throw e;
    if(String(fresh.data?.deviceId||'')!==String(identity.deviceId||'')){
      const x=new Error('This account is already registered on another Chrome device. Use Reset Device before moving it.');
      x.code='DEVICE_ALREADY_CLAIMED'; throw x;
    }
  }

  const doc={
    uid,subadminUid:me.profile.subadminUid,deviceId:identity.deviceId,status:'active',
    extensionVersion:CS.CONFIG.version,lastSeenAt:CS.Util.now(),
    lastProxyVersion:0,lastResetVersion:0,lastSyncVersion:0,lastSyncVersionBySite:{},
    lastSyncAt:'',lastIp:'',proxyHealthy:false,claimedAt:claimDoc.claimedAt
  };
  try{
    await CS.Firebase.createDoc(['devices',uid],doc,me.session.idToken);
    await cacheDevice(doc);
    return{device:doc,identity,newlyRegistered:true};
  }catch(e){
    const fresh=await CS.Firebase.getDoc(['devices',uid],me.session.idToken);
    if(!fresh.exists) throw e;
    return validateExisting(fresh.data,identity,me);
  }

  async function createClaimOrValidate(ident,d){
    const claimData={uid,deviceId:ident.deviceId,claimedAt:d.claimedAt||CS.Util.now(),status:'claimed'};
    try{await CS.Firebase.createDoc(['deviceClaims',uid],claimData,me.session.idToken);}
    catch(e){
      const fresh=await CS.Firebase.getDoc(['deviceClaims',uid],me.session.idToken);
      if(!fresh.exists) throw e;
      if(String(fresh.data?.deviceId||'')!==String(ident.deviceId||'')){
        const x=new Error('This account is already registered on another Chrome device. Use Reset Device before moving it.');
        x.code='DEVICE_ALREADY_CLAIMED'; throw x;
      }
    }
  }

  async function cacheDevice(d){
    if(!d)return;
    await CS.Store.set({
      clientDeviceCache:d,
      clientDeviceCacheAt:Date.now(),
      clientDeviceCacheUid:uid
    }).catch(()=>{});
  }

  async function validateExisting(d,ident,user){
    if(String(d?.deviceId||'')!==String(ident?.deviceId||'')){
      const e=new Error('This account is already registered on another Chrome device. Use Reset Device before moving it.');
      e.code='DEVICE_ALREADY_CLAIMED'; throw e;
    }
    if(String(d?.subadminUid||'')!==String(user.profile.subadminUid||'')){
      const e=new Error('Device assignment does not match this account.'); e.code='DEVICE_ASSIGNMENT_MISMATCH'; throw e;
    }
    if(d.status==='revoked'){
      const e=new Error('This device has been revoked. Use Reset Device before signing in again.'); e.code='DEVICE_REVOKED'; throw e;
    }
    await cacheDevice(d);
    return{device:d,identity:ident};
  }
}
async function deviceGate(){
  const me=await CS.Auth.currentProfile(true);
  if(!me) return {ok:false,loggedIn:false};
  if(me.profile?.role!=='client') throw new Error('This account is not a client account.');
  if(me.profile?.active===false) return {ok:true,suspended:true,profile:me.profile};

  const sub=await getSubStatus(me,{force:true});
  if(sub.active===false) return {ok:true,suspended:true,profile:me.profile};

  const sites=await loadSites(me,{force:true});
  if(!sites.length) return {ok:true,profile:me.profile,sites,waitingForSite:true,locked:true};

  const device=await ensureDevice(me);
  if(device.resetRequired) return {ok:true,profile:me.profile,sites,waitingForDevice:true,locked:true,deviceReset:true};
  await ensureFirstRegistrationSetup(device);

  await CS.Store.set({clientSitesCache:sites});
  return {ok:true,loggedIn:true,profile:me.profile,sites,device:device.device};
}

function clientProxyIdentity(raw){
  const p=CS.Proxy.normalize(raw);
  if(p.mode==='unconfigured')return '';
  // Chrome's effective proxy API does not expose the authenticated proxy
  // username/password, so including credentials here makes the same proxy
  // look different on every startup. That caused the client to treat every
  // popup/startup as a new proxy rotation and reopen proxy-setup.html.
  // Rotation identity is therefore based on the actual connection endpoint.
  return JSON.stringify([p.mode,p.scheme,p.host,Number(p.port)]);
}
function effectiveProxyDoc(eff){
  const sp=eff?.value?.mode==='fixed_servers' ? eff.value?.rules?.singleProxy : null;
  if(!sp?.host || !Number(sp.port))return null;
  return {mode:'fixed_servers',scheme:String(sp.scheme||'http').toLowerCase(),host:String(sp.host||'').trim(),port:Number(sp.port),username:'',password:''};
}
function usableProxyDoc(d){
  if(!d || d.mode==='direct' || d.enabled===false) return false;
  return !!String(d.host||'').trim() && Number.isInteger(Number(d.port)) && Number(d.port)>0;
}
function proxyDocRank(d){
  const version=Number(d?.version||0);
  const updated=Date.parse(d?.updatedAt||'') || 0;
  const checked=Date.parse(d?.lastCheckedAt||'') || 0;
  return [version, updated, checked];
}
function pickProxyDoc(docs){
  const usable=docs.filter(usableProxyDoc);
  usable.sort((a,b)=>{
    const ar=proxyDocRank(a), br=proxyDocRank(b);
    for(let i=0;i<ar.length;i++) if(br[i]!==ar[i]) return br[i]-ar[i];
    if(Boolean(b.healthy)!==Boolean(a.healthy)) return Number(b.healthy)-Number(a.healthy);
    return 0;
  });
  return usable[0]||null;
}
async function getControl(me,{force=false}={}){
  const subId=String(me.profile.subadminUid||'').trim();
  if(!subId)throw new Error('This client account has no assigned Admin Extension.');

  const local=await CS.Store.get([
    'clientControlCache','clientControlCacheAt','clientControlCacheSubadminUid',
    'lastSavedProxyConfig','lastSavedProxySubadminUid'
  ]).catch(()=>({}));
  const age=Date.now()-Number(local.clientControlCacheAt||0);
  if(!force && local.clientControlCacheSubadminUid===subId && age>=0 && age<10000 && local.clientControlCache){
    return local.clientControlCache;
  }

  const stateR=await CS.Firebase.getDoc(['users',subId,'control','state'],me.session.idToken).catch(()=>({exists:false,data:null}));
  const controlState=stateR.exists&&stateR.data?stateR.data:{};
  const stateProxyVersion=Number(controlState.proxyVersion||0);
  const stateResetVersion=Number(controlState.resetVersion||0);

  let serverProxy=null;
  let proxySource='';
  const cachedUsable=
    local.lastSavedProxySubadminUid===subId &&
    usableProxyDoc(local.lastSavedProxyConfig)
      ? local.lastSavedProxyConfig : null;
  const cachedVersion=Number(cachedUsable?.version||0);
  const cachedProxyAge=Date.now()-Number(local.lastSavedProxyConfigAt||0);
  const cachedProxyFresh=Number.isFinite(cachedProxyAge) && cachedProxyAge>=0 && cachedProxyAge<60000;

  // If our local canonical proxy is at least as new as the control version,
  // use it for a short period to avoid redundant reads. After that, re-check
  // the canonical document even if control/state has not advanced, which keeps
  // the client robust when a proxy write succeeds but its advisory version
  // update lags or fails.
  if(cachedUsable && cachedVersion>=stateProxyVersion && cachedProxyFresh){
    serverProxy=cachedUsable;
    proxySource='cache';
  }else{
    const nested=await CS.Firebase.getDoc(['users',subId,'proxy','config'],me.session.idToken).catch(()=>({exists:false,data:null}));
    if(nested.exists){
      if(usableProxyDoc(nested.data)){serverProxy=nested.data;proxySource='canonical';}
    }else{
      const legacy=await CS.Firebase.getDoc(['subadminProxyConfigs',subId],me.session.idToken).catch(()=>({exists:false,data:null}));
      if(usableProxyDoc(legacy.data)){serverProxy=legacy.data;proxySource='legacy';}
    }
  }

  if(serverProxy){
    const normalized={...serverProxy,mode:'fixed_servers'};
    const result={
      state:{...controlState,proxyVersion:Math.max(stateProxyVersion,Number(normalized.version||0)),resetVersion:Math.max(stateResetVersion,Number(normalized.resetVersion||0),Number(me.profile.deviceResetVersion||0))},
      proxy:normalized,
      proxySource
    };
    await CS.Store.set({
      lastSavedProxyConfig:normalized,
      lastSavedProxyConfigAt:Date.now(),
      lastSavedProxySubadminUid:subId,
      clientControlCache:result,
      clientControlCacheAt:Date.now(),
      clientControlCacheSubadminUid:subId
    }).catch(()=>{});
    return result;
  }

  const cachedFallback=local.lastSavedProxySubadminUid===subId&&local.lastSavedProxyConfig?local.lastSavedProxyConfig:null;
  const fallback={
    state:{...controlState,proxyVersion:Math.max(stateProxyVersion,Number(cachedFallback?.version||0)),resetVersion:Math.max(stateResetVersion,Number(me.profile.deviceResetVersion||0),Number(cachedFallback?.resetVersion||0))},
    proxy:cachedFallback ? {...cachedFallback,mode:'unconfigured',healthy:false,ip:'',lastError:'Saved proxy data is unavailable or incomplete.'} : {mode:'unconfigured',healthy:false,ip:'',lastError:'Proxy is not configured.'},
    proxySource:''
  };
  await CS.Store.set({clientControlCache:fallback,clientControlCacheAt:Date.now(),clientControlCacheSubadminUid:subId}).catch(()=>{});
  return fallback;
}
async function getSyncKey(me){
  return CS.Sync.getGroupKey(me.profile.subadminUid,me.session.idToken);
}
async function applyLatestSnapshots(me,sites,key,device,controlState,{fresh=false,syncOnly=false}={}){
  let next={...device}, applied=0, newest=Number(device.lastSyncVersion||0), newestReset=Number(device.lastResetVersion||0), cookieFailures=0;
  const appliedSiteIds=[];
  const diagnostics=[];
  const proxyVersion=Number(controlState?.proxyVersion||0);
  const resetVersion=Number(controlState?.resetVersion||0);

  for(const site of sites){
    const r=await CS.Firebase.getDoc(['sites',site.id,'sync','latest'],me.session.idToken);
    if(!r.exists||!r.data?.envelope){
      diagnostics.push({siteId:site.id,hostname:site.hostname,status:'missing'});
      continue;
    }

    const reason=String(r.data.reason||'');
    if(reason==='admin-refresh-users'){
      diagnostics.push({siteId:site.id,hostname:site.hostname,status:'admin-refresh-signal'});
      continue;
    }
    const ver=Number(r.data.version||0);
    if(!fresh && ver<=Number(device.lastSyncVersionBySite?.[site.id]||0)){
      diagnostics.push({siteId:site.id,hostname:site.hostname,status:'already-applied',version:ver});
      continue;
    }

    // Normal client lifecycle keeps the existing proxy/reset safety gates.
    // The dedicated cookie-sync path intentionally does not: the snapshot is
    // already authorized by the client's site assignment + shared sync key,
    // and cookie restoration must not depend on a proxy health check.
    if(!syncOnly && Number(r.data.requiredProxyVersion||0)!==proxyVersion){
      diagnostics.push({
        siteId:site.id,hostname:site.hostname,status:'proxy-version-mismatch',
        snapshotProxyVersion:Number(r.data.requiredProxyVersion||0),clientProxyVersion:proxyVersion
      });
      continue;
    }

    const snapshotResetVersion=Number(r.data.requiredResetVersion||0);
    if(!syncOnly && snapshotResetVersion<resetVersion){
      diagnostics.push({
        siteId:site.id,hostname:site.hostname,status:'stale-reset-snapshot',
        snapshotResetVersion,clientResetVersion:resetVersion
      });
      continue;
    }

    // A malformed/legacy snapshot must never prevent the client from logging
    // in or syncing its other assigned sites. The Supabase compatibility layer
    // normalizes invalid TEXT envelopes to null; skip those snapshots safely.
    if(!r.data.envelope || typeof r.data.envelope!=='object'){
      diagnostics.push({siteId:site.id,hostname:site.hostname,status:'invalid-snapshot'});
      continue;
    }

    let payload=null;
    try{
      payload=await CS.Crypto.decryptWithKey(r.data.envelope,key);
    }catch(e){
      diagnostics.push({siteId:site.id,hostname:site.hostname,status:'invalid-snapshot',error:e?.message||String(e)});
      continue;
    }
    if(payload.siteId!==site.id){
      diagnostics.push({siteId:site.id,hostname:site.hostname,status:'site-id-mismatch'});
      continue;
    }

    const result=await CS.Cookies.reconcile(site,payload.cookies||[]);
    cookieFailures+=Number(result.failed||0);

    // A page that was already open before the snapshot arrived may have
    // started its request with the old cookies. Only mark the site for a
    // reload when at least one cookie was actually written.
    if(Number(result.set||0)>0) appliedSiteIds.push(String(site.id));

    next.lastSyncVersionBySite={...(next.lastSyncVersionBySite||{}),[site.id]:ver};
    newest=Math.max(newest,ver);
    applied++;
    newestReset=Math.max(newestReset,snapshotResetVersion);

    diagnostics.push({
      siteId:site.id,
      hostname:site.hostname,
      status:'applied',
      version:ver,
      cookies:Number(payload.cookies?.length||0),
      cookiesSet:Number(result.set||0),
      cookiesFailed:Number(result.failed||0)
    });
  }

  if(applied) next.lastSyncAt=CS.Util.now();
  next.lastSyncVersion=newest;
  if(!syncOnly) next.lastResetVersion=Math.max(newestReset,resetVersion);
  else next.lastResetVersion=Math.max(newestReset,Number(device.lastResetVersion||0));

  return{device:next,applied,cookieFailures,syncDiagnostics:diagnostics,appliedSiteIds:[...new Set(appliedSiteIds)]};
}

async function reloadManagedTabsAfterSync(sites, appliedSiteIds){
  const wanted=new Set((appliedSiteIds||[]).map(String));
  if(!wanted.size)return 0;
  let reloaded=0;
  try{
    const tabs=await chrome.tabs.query({});
    for(const tab of tabs){
      if(tab?.id==null || !/^https?:\/\//i.test(String(tab.url||'')))continue;
      const match=(sites||[]).find(site=>wanted.has(String(site.id)) && managedUrlForSites(tab.url,[site]));
      if(!match)continue;
      clearLoadingWatch(tab.id);
      try{
        await chrome.tabs.reload(tab.id,{bypassCache:false});
        reloaded++;
      }catch{}
    }
  }catch{}
  return reloaded;
}

function stableDeviceSignature(d){
  const bySite={};
  for(const k of Object.keys(d?.lastSyncVersionBySite||{}).sort())bySite[k]=Number(d.lastSyncVersionBySite[k]||0);
  return JSON.stringify({
    uid:String(d?.uid||''),
    subadminUid:String(d?.subadminUid||''),
    deviceId:String(d?.deviceId||''),
    status:String(d?.status||''),
    extensionVersion:String(d?.extensionVersion||''),
    lastProxyVersion:Number(d?.lastProxyVersion||0),
    lastResetVersion:Number(d?.lastResetVersion||0),
    lastSyncVersion:Number(d?.lastSyncVersion||0),
    lastSyncVersionBySite:bySite,
    lastSyncAt:String(d?.lastSyncAt||''),
    publicKey:String(d?.publicKey||'')
  });
}
async function persistDeviceIfMeaningful(me,previous,next){
  if(stableDeviceSignature(previous)===stableDeviceSignature(next))return false;
  await CS.Firebase.setDoc(['devices',me.session.uid],next,me.session.idToken);
  return true;
}

async function syncLatestCookies({fresh=false,reloadTabs=true}={}){
  let me=await CS.Auth.currentProfile(true);
  if(!me)return{ok:false,loggedIn:false};
  if(me.profile.role!=='client')throw new Error('This account is not a client account.');
  if(me.profile.active===false)return{ok:true,loggedIn:true,suspended:true};

  const sites=await loadSites(me,{force:true});
  if(!sites.length)return{ok:true,loggedIn:true,profile:me.profile,sites,applied:0};

  const scan=await CS.Security.scan(sites);
  if(scan.locked)return{ok:false,loggedIn:true,profile:me.profile,sites,locked:true,error:'Unauthorized Chrome extension detected.'};

  const key=await getSyncKey(me);
  if(!key)return{ok:true,loggedIn:true,profile:me.profile,sites,applied:0,received:0,error:'No synchronization key is available yet.'};

  // Fresh Sync is an explicit user action, but it must still honor the
  // durable one-device claim. The snapshot path used to trust only the
  // devices/{uid} document, which could let a second Chrome installation
  // continue with cookies if its UI reached Fresh Sync through a stale state.
  const deviceResult=await ensureDevice(me);
  const device={...deviceResult.device};
  const r=await applyLatestSnapshots(
    me,sites,key,device,{},
    {fresh,syncOnly:true}
  );

  // Never reload an already-open page as part of Login/Fresh Sync. Cookie
  // injection completes in the background and the customer decides when to
  // refresh the website. This keeps both the client and managed site exactly
  // where the user left them. The proxy-rotation cleanup path remains separate.
  const reloadedTabs=0;

  const nextDevice={
    ...r.device,
    status:'active'
  };

  // Fresh Sync only writes the durable device record when the snapshot actually
  // advanced. Re-syncing an already-applied snapshot therefore causes zero
  // device writes.
  if(Number(r.applied||0)>0){
    await persistDeviceIfMeaningful(me,device,nextDevice).catch(()=>{});
  }

  await CS.Store.set({
    clientLastState:{
      ip:nextDevice.lastIp||'',
      lastSyncAt:nextDevice.lastSyncAt||'',
      proxyHealthy:nextDevice.proxyHealthy===true,
      applied:r.applied,
      cookieFailures:r.cookieFailures,
      syncDiagnostics:r.syncDiagnostics
    }
  }).catch(()=>{});

  return{
    ok:true,
    loggedIn:true,
    profile:me.profile,
    sites,
    device:nextDevice,
    applied:r.applied,
    cookieFailures:r.cookieFailures,
    syncDiagnostics:r.syncDiagnostics,
    reloadedTabs
  };
}

async function installAndTestProxy(me,sites,control,{force=false,resetRequired=false}={}){
  const proxy=CS.Proxy.normalize(control.proxy);
  if(proxy.mode==='unconfigured') return {ok:false,ip:null,reason:'Proxy is not configured.'};
  await CS.Proxy.setActiveCredentials(proxy);await CS.Proxy.apply(proxy);
  // For a one-time check, temporarily allow the health endpoint as a top-level request.
  await CS.Rules.applyNavigationPolicy(sites,{locked:false,testEnabled:true});
  if(!force&&!resetRequired) return {ok:control.proxy.healthy===true,ip:control.proxy.ip||null,reason:control.proxy.healthy===true?'Last saved proxy check is healthy.':(control.proxy.lastError||'Proxy is not working.')};
  return CS.Proxy.test(proxy);
}
function stateSafeBoolean(v){return v===true;}
async function runClientStep({forceProxyTest=false,freshSync=false,deferProxyTest=false,allowDeviceReset=false,recoveryAttempt=false,syncCookies=true,forceSites=false,suppressFirstWelcome=false}={}){
  let me=null;
  try{
    try{me=await CS.Auth.currentProfile(false);if(!me)me=await CS.Auth.currentProfile(true);}
    catch(e){
      if(e.code==='ACCOUNT_SUSPENDED'){
        const cached=(await CS.Store.get('clientSitesCache')).clientSitesCache||[];
        await clearAllManaged(cached,'Account suspended.');
        return{ok:true,loggedIn:true,suspended:true,error:'Account suspended.'};
      }
      throw e;
    }

    if(!me)return{ok:false,loggedIn:false};
    if(me.profile.role!=='client')throw new Error('This account is not a client account.');
    if(me.profile.active===false){
      const cached=(await CS.Store.get('clientSitesCache')).clientSitesCache||[];
      await clearAllManaged(cached,'Account suspended.');
      return{ok:true,loggedIn:true,suspended:true,error:'Account suspended.'};
    }

    const subStatus=await getSubStatus(me,{force:forceSites});
    if(subStatus.active===false){
      const sites=await loadSites(me);
      await clearAllManaged(sites,'Account suspended.');
      return{ok:true,loggedIn:true,suspended:true,error:'Account suspended.'};
    }

    const previousSites=(await CS.Store.get('clientSitesCache')).clientSitesCache||[];
    const sites=await loadSites(me,{force:forceSites});
    const activeIds=new Set(sites.map(s=>s.id));
    for(const oldSite of previousSites){
      if(!activeIds.has(oldSite.id))await CS.Cookies.clearOrigin(oldSite).catch(()=>{});
    }
    await CS.Store.set({clientSitesCache:sites});

    const scan=await CS.Security.scan(sites);
    if(scan.locked){
      await CS.Rules.applyNavigationPolicy(sites,{locked:true,testEnabled:false}).catch(()=>{});
      return{ok:false,loggedIn:true,profile:me.profile,sites,locked:true,error:'Unauthorized Chrome extension detected.'};
    }

    const origins=[...new Set(sites.flatMap(s=>{
      try{
        const u=new URL(s.origin);
        const scope=syncScopeHostname(u.hostname);
        return[
          `${u.origin}/*`,
          `https://${scope}/*`, `https://*.${scope}/*`,
          `http://${scope}/*`, `http://*.${scope}/*`
        ];
      }catch{return[]}
    }))];
    if(origins.length && !(await chrome.permissions.contains({origins}))){
      await CS.Rules.applyNavigationPolicy(sites,{locked:true,testEnabled:false}).catch(()=>{});
      return{ok:true,loggedIn:true,profile:me.profile,sites,needsPermission:true};
    }

    if(!sites.length){
      await CS.Rules.applyNavigationPolicy([],{locked:true,testEnabled:false});
      return{ok:true,loggedIn:true,profile:me.profile,sites,waitingForSite:true,locked:true,error:'No managed website is assigned yet.'};
    }

    // Read the published reset state BEFORE attempting to create/recreate a device claim.
    // This prevents a previously authorized browser from silently reclaiming the account
    // in the background immediately after an Admin presses Reset Device.
    // Capture the locally known/currently installed proxy BEFORE getControl().
    // getControl() refreshes lastSavedProxyConfig with the remote proxy, so this
    // snapshot must happen first in order to tell whether the incoming proxy is
    // actually different from the proxy currently in Chrome.
    const preControlLocal=await CS.Store.get(['lastSavedProxyConfig','lastSavedProxySubadminUid']).catch(()=>({}));
    const previousSavedProxy=
      String(preControlLocal.lastSavedProxySubadminUid||'')===String(me.profile.subadminUid||'') &&
      usableProxyDoc(preControlLocal.lastSavedProxyConfig)
        ? preControlLocal.lastSavedProxyConfig : null;
    let installedProxyBefore=null;
    try{installedProxyBefore=effectiveProxyDoc(await CS.Proxy.effective());}catch{}

    const control=await getControl(me);
    const controlReset=Math.max(
      Number(control.state.resetVersion||0),
      Number(me.profile.deviceResetVersion||0)
    );
    const controlProxy=Number(control.state.proxyVersion||0);
    const binding=await getDeviceBinding();
    const cachedDeviceState=await CS.Store.get(['clientDeviceCache','clientDeviceCacheUid']).catch(()=>({}));
    const cachedDevice=cachedDeviceState.clientDeviceCache;
    const sameCachedDevice=
      String(cachedDeviceState.clientDeviceCacheUid||'')===String(me.session.uid) &&
      cachedDevice &&
      String(cachedDevice.deviceId||'')===String(binding.deviceId||'');
    // A newer resetVersion matters only to a device that was actually bound
    // before that reset. Keep this distinction separate from proxyVersion:
    // Admin proxy rotation advances both counters, but it must NOT turn a
    // normal proxy rotation into a device re-authorization prompt.
    const resetPendingForKnownDevice=
      String(binding.uid||'')===String(me.session.uid) &&
      !!String(binding.deviceId||'') &&
      controlReset > Number(binding.resetVersion||0);
    // A proxy rotation intentionally advances BOTH proxyVersion and
    // resetVersion. That reset is session-safety for the old proxy, not a
    // request to make the user click Sync Again. Allow the same already-bound
    // device to process that specific proxy rotation automatically. A reset
    // with no newer proxyVersion still requires explicit re-authorization.
    const proxyRotationPending =
      resetPendingForKnownDevice &&
      sameCachedDevice &&
      controlProxy > Number(cachedDevice?.lastProxyVersion||0);

    if(resetPendingForKnownDevice && !allowDeviceReset && !proxyRotationPending){
      await clearAllManaged(sites,'This device was reset by an Admin. Open Cookie Sync to re-authorize this device.').catch(()=>{});
      return{
        ok:true,loggedIn:true,profile:me.profile,sites,
        waitingForDevice:true,deviceResetRequired:true,locked:false,
        proxy:control.proxy,
        proxyFailed:false,
        error:'This device was reset by an Admin. Open Cookie Sync to re-authorize this device.',
        applied:0
      };
    }

    const deviceResult=await ensureDevice(me,{fast:recoveryAttempt});
    await ensureFirstRegistrationSetup(deviceResult,{openWelcome:suppressFirstWelcome!==true});
    let device={...deviceResult.device};

    // A first-time device registration must NEVER be treated as a proxy
    // rotation.  Keep a short-lived local marker across any concurrent
    // startup/login/background clientStep calls so the initial application of
    // the currently published proxy cannot trigger the destructive rotation
    // cleanup or the DAT-setup welcome page.  Only a later Admin proxy change
    // should clear the browser session.
    const firstProxySetupKey=`clientFirstProxySetup:${String(me.session.uid||'')}`;
    const firstProxySetupState=(await CS.Store.get(firstProxySetupKey).catch(()=>({})))[firstProxySetupKey]||null;
    if(deviceResult.newlyRegistered){
      // Drop any stale rotation retry state before initializing a brand-new
      // device.  This prevents an old pending cleanup from appearing as a
      // false "new DAT setup" immediately after first registration.
      await CS.Store.remove([
        'proxyRotationCleanupPending',
        `proxyRotationTabsClosed:${String(me.profile.subadminUid||'')}`,
        `proxyRotationDataCleared:${String(me.profile.subadminUid||'')}`
      ]).catch(()=>{});
      await CS.Store.set({[firstProxySetupKey]:{
        proxyVersion:Number(controlProxy||0),
        startedAt:Date.now()
      }}).catch(()=>{});
    }
    const initialProxySetupPending = !!(
      firstProxySetupState &&
      Number(firstProxySetupState.proxyVersion||0)===Number(controlProxy||0)
    ) || deviceResult.newlyRegistered;

    // Keep a browser-local record of the proxy version that this exact
    // extension instance has successfully installed.  This is a safety
    // fallback for cases where a device telemetry write is delayed/denied;
    // otherwise the stale server lastProxyVersion can make the same proxy
    // look like a brand-new rotation every time the popup opens.
    const localProxyMarker=await CS.Store.get([
      'clientAppliedProxyVersion','clientAppliedProxySubadminUid','clientAppliedProxyIdentity'
    ]).catch(()=>({}));
    const localProxyVersion=
      String(localProxyMarker.clientAppliedProxySubadminUid||'')===String(me.profile.subadminUid||'')
        ? Number(localProxyMarker.clientAppliedProxyVersion||0) : 0;
    const localProxyIdentity=
      String(localProxyMarker.clientAppliedProxySubadminUid||'')===String(me.profile.subadminUid||'')
        ? String(localProxyMarker.clientAppliedProxyIdentity||'') : '';

    const previousProxyVersion=Math.max(
      Number(device.lastProxyVersion||0),
      localProxyVersion
    );
    const needReset=Number(device.lastResetVersion||0)<controlReset;
    const needProxy=previousProxyVersion<controlProxy;
    const hadPriorProxySession=previousProxyVersion>0 || !!String(device.lastIp||'').trim() || !!device.lastProxyCheckAt || !!previousSavedProxy || !!localProxyIdentity;

    // A rotation is based on the proxy that is actually installed, not on
    // whether the endpoint has ever appeared before. Returning to an older
    // proxy still counts as a rotation when the currently installed proxy is
    // different. Reusing the CURRENT proxy is the only no-cleanup case.
    const targetProxyIdentity=clientProxyIdentity(control.proxy);
    const installedProxyIdentity=installedProxyBefore ? clientProxyIdentity(installedProxyBefore) : '';
    const previousSavedProxyIdentity=previousSavedProxy ? clientProxyIdentity(previousSavedProxy) : '';
    const proxyDiffersFromInstalled=!!targetProxyIdentity && !!installedProxyIdentity && targetProxyIdentity!==installedProxyIdentity;
    const proxyDiffersFromSaved=!!targetProxyIdentity && !!previousSavedProxyIdentity && targetProxyIdentity!==previousSavedProxyIdentity;
    const proxyWasActuallyRotated=!initialProxySetupPending && !deviceResult.newlyRegistered && hadPriorProxySession && (proxyDiffersFromInstalled || (!installedProxyIdentity && proxyDiffersFromSaved));

    if(needReset||needProxy){
      device={...device,status:'resetting',proxyHealthy:false,lastIp:'',lastSyncAt:''};
      if(needReset && !needProxy) await clearAllManaged(sites,'Preparing your browser for the latest session reset.');
    }

    if(!control.proxy || control.proxy.mode==='unconfigured'){
      const proxy={
        mode:'unconfigured',
        healthy:false,
        ip:'',
        lastError:'Proxy is not configured.'
      };
      await clearAllManaged(
        sites,
        'Proxy is not configured. Contact your Admin Extension.'
      ).catch(()=>{});
      return{
        ok:true,
        loggedIn:true,
        profile:me.profile,
        sites,
        proxy,
        proxyFailed:true,
        locked:false,
        health:{ok:false,ip:null,reason:'Proxy is not configured.'},
        applied:0,
        newlyRegistered:!!deviceResult.newlyRegistered
      };
    }

    const proxy=CS.Proxy.normalize(control.proxy);
    await CS.Proxy.setActiveCredentials(proxy);
    await CS.Proxy.apply(proxy);

    if(proxy.mode==='fixed_servers'){
      // Fail closed while checking, but explicitly allow the one health-check
      // endpoint. Without testEnabled=true, the network-wide DNR block also
      // blocks api.ipify.org and Chrome reports net::ERR_BLOCKED_BY_CLIENT.
      await CS.Rules.applyNavigationPolicy(sites,{locked:false,testEnabled:true});
    }

    if(deferProxyTest && proxy.mode==='fixed_servers'){
      // Explicit startup/re-authorization calls may authorize a device before
      // the separate proxy health check runs. Persist the local binding now so
      // that the follow-up `check-proxy` call is not mistaken for an old,
      // pre-reset device. This is local-only and does not write telemetry.
      if(allowDeviceReset || needReset){
        await rememberDeviceBinding(me.session.uid,device.deviceId,controlReset).catch(()=>{});
      }
      const health={ok:false,pending:true,ip:null,reason:'Checking proxy…'};
      await CS.Store.set({
        clientProxyHealth:{ok:stateSafeBoolean(device.proxyHealthy),pending:true,ip:device.lastIp||null,reason:'Checking proxy…',checkedAt:Date.now()},
        clientLastState:{ip:device.lastIp||'',lastSyncAt:device.lastSyncAt||'',proxyHealthy:device.proxyHealthy===true}
      });
      return{ok:true,loggedIn:true,profile:me.profile,sites,proxy,device,health,proxyChecking:true,applied:0,newlyRegistered:!!deviceResult.newlyRegistered};
    }

    const health=await CS.Proxy.test(proxy);

    if(!health.ok){
      // Proxy failure is temporary/local runtime state. Do not persist it to
      // Firebase as device telemetry.
      device={...device,status:'proxy_error',proxyHealthy:false,lastSeenAt:CS.Util.now(),lastProxyCheckAt:CS.Util.now(),lastIp:health.ip||''};
      await lockForProxyFailure(health.reason||'Proxy is not working.');
      await CS.Store.set({
        clientLastState:{ip:health.ip||'',lastSyncAt:device.lastSyncAt||'',proxyHealthy:false},
        clientProxyHealth:{...health,pending:true,reason:health.reason||'Reconnecting to proxy…'}
      }).catch(()=>{});
      return{ok:true,loggedIn:true,profile:me.profile,sites,health:{...health,pending:true},proxyFailed:true,proxyChecking:true,device,applied:0,newlyRegistered:!!deviceResult.newlyRegistered};
    }

    // A profile-data wipe is for an actual proxy rotation, not first-time setup.
    // IMPORTANT: tab-closing and data-clearing are tracked separately. The old
    // implementation bundled them together, so if any later storage/device
    // update failed the next background health cycle could see the same proxy
    // version and repeat the browser cleanup. Rotation cleanup is idempotent: the
    // old tabs are replaced once per proxy version, while web data can be retried
    // without closing the browser or repeating tab cleanup.
    if(proxyWasActuallyRotated){
      const cleanup=await cleanupAfterProxyRotation(String(me.profile.subadminUid||''),controlProxy);
      if(!cleanup.ok){
        const cleanupReason=`New proxy connected, but browser cleanup is still pending: ${cleanup.reason||'Please wait while LogIn clears the previous browser session.'}`;
        await CS.Store.set({
          clientProxyHealth:{...health,pending:true,ip:health.ip||null,reason:cleanupReason,checkedAt:Date.now()},
          proxyRotationCleanupPending:{subadminUid:String(me.profile.subadminUid||''),version:controlProxy,phase:cleanup.phase||'browser-data',lastError:cleanup.reason||'',updatedAt:Date.now()}
        }).catch(()=>{});
        // Do not release managed navigation or apply fresh cookies until the
        // previous browser session has been fully cleared. The cleanup alarm
        // retries locally and will re-enter clientStep once successful.
        await CS.Rules.applyNavigationPolicy(sites,{locked:true,testEnabled:false}).catch(()=>{});
        return{
          ok:true,loggedIn:true,profile:me.profile,sites,proxy,health:{...health,pending:true,reason:cleanupReason},
          proxyFailed:false,proxyChecking:true,proxyCleanupPending:true,device,applied:0,error:cleanupReason
        };
      }
    }

    await CS.Rules.applyNavigationPolicy(sites,{locked:false,testEnabled:false});

    const key=syncCookies ? await getSyncKey(me) : '';
    let applied=0, cookieFailures=0, syncDiagnostics=[];
    if(syncCookies && key){
      const r=await applyLatestSnapshots(me,sites,key,device,control.state,{fresh:freshSync});
      device=r.device;
      applied=r.applied;
      cookieFailures=Number(r.cookieFailures||0);
      syncDiagnostics=r.syncDiagnostics||[];
    }

    const persistedBefore={...device};
    device={
      ...device,status:'active',proxyHealthy:true,
      lastProxyVersion:controlProxy,lastResetVersion:controlReset,
      lastSeenAt:CS.Util.now(),lastProxyCheckAt:CS.Util.now(),
      lastIp:health.ip||device.lastIp||''
    };
    // Only durable device changes hit Firestore. Runtime health/IP/heartbeat
    // values remain local, so a 30-second health cycle does not write.
    await persistDeviceIfMeaningful(me,persistedBefore,device).catch(()=>{});
    await rememberDeviceBinding(me.session.uid,device.deviceId,controlReset);
    await CS.Store.set({
      clientLastState:{
        ip:device.lastIp||'',
        lastSyncAt:device.lastSyncAt||'',
        proxyHealthy:true,
        applied,
        cookieFailures,
        syncDiagnostics
      },
      clientProxyHealth:{...health,pending:false}
    });
    await CS.Store.remove(['clientLockReason']).catch(()=>{});
    await CS.Store.set({proxyRecoveryState:{active:false,confirmedFailed:false,startedAt:Date.now(),attempts:0,lastError:''}}).catch(()=>{});
    // Mark the exact proxy version/identity that this browser has actually
    // installed.  This survives service-worker restarts and prevents a stale
    // server-side device telemetry row from repeating the DAT cleanup dialog.
    await CS.Store.set({
      lastSavedProxyConfig:proxy,
      lastSavedProxyConfigAt:Date.now(),
      lastSavedProxySubadminUid:String(me.profile.subadminUid||''),
      clientAppliedProxyVersion:controlProxy,
      clientAppliedProxySubadminUid:String(me.profile.subadminUid||''),
      clientAppliedProxyIdentity:clientProxyIdentity(proxy)
    }).catch(()=>{});
    // Initial device setup is complete only after the first proxy has passed
    // its health check and the normal client state has been persisted.
    if(initialProxySetupPending){
      await CS.Store.remove([firstProxySetupKey]).catch(()=>{});
    }

    return{ok:true,loggedIn:true,profile:me.profile,sites,proxy,health,device,applied,cookieFailures,syncDiagnostics,newlyRegistered:!!deviceResult.newlyRegistered};
  }catch(e){
    const message=String(e?.message||e||'Unexpected error');
    const cached=(await CS.Store.get('clientSitesCache')).clientSitesCache||[];
    const deviceError=['DEVICE_ALREADY_CLAIMED','DEVICE_ASSIGNMENT_MISMATCH','DEVICE_REVOKED','DEVICE_CLAIM_FAILED'].includes(String(e?.code||''));
    if(deviceError){
      // An account claim/device mismatch is a security event. Perform the same
      // full browser cleanup used for proxy rotation, once for this concrete
      // device identity, then keep the existing device-block/logout behavior.
      let deviceKey=`device:${String(me?.session?.uid||'unknown')}`;
      try{
        const ident=await CS.Crypto.getStoredDeviceIdentity();
        if(ident?.deviceId)deviceKey+=`:${String(ident.deviceId)}`;
      }catch{}
      await CS.Security.securityWipe({key:deviceKey,reason:message,warningKind:'device'}).catch(()=>{});
      await clearAllManaged(cached,message).catch(()=>{});
      await CS.Auth.logout().catch(()=>{});
      return{ok:false,loggedIn:false,profile:null,deviceBlocked:true,error:message};
    }
    const isSecurityLock=/unauthorized chrome extension|profile locked/i.test(message);
    const isHardAccess=/account suspended|device registration|not assigned/i.test(message);
    if(isSecurityLock||isHardAccess)await clearAllManaged(cached,message).catch(()=>{});
    else if(/proxy/i.test(message)){
      await lockForProxyFailure(message).catch(()=>{});
    }
    return{
      ok:false,loggedIn:!!me,profile:me?.profile||null,
      proxyFailed:/proxy/i.test(message),
      locked:isSecurityLock,
      error:message
    };
  }
}

async function clientStep(options={}) {
  if (runningPromise) return runningPromise;
  runningPromise = runClientStep(options);
  try { return await runningPromise; } finally { runningPromise = null; }
}

CS.Proxy.installProxyErrorListener(async details=>{
  try{
    if(!details?.isProxy)return;
    const reason=`Proxy error: ${details.error||details.details||'Chrome reported a proxy error.'}`;
    await lockForProxyFailure(reason);
    // Replace a currently failing/connecting managed tab with a same-tab wait
    // screen. No new tabs are created.
    if(Number.isInteger(Number(details?.tabId)) && Number(details.tabId)>=0){
      const sites=(await CS.Store.get('clientSitesCache')).clientSitesCache||[];
      const tab=await chrome.tabs.get(Number(details.tabId)).catch(()=>null);
      if(tab && managedUrlForSites(tab.url,sites)) await holdLoadingTab(tab.id,tab.url);
    }
  }catch{}
});

chrome.webNavigation?.onErrorOccurred?.addListener(async details=>{
  clearLoadingWatch(details.tabId);
  try{
    if(details.frameId!==0 || !details.url || !/^https?:\/\//i.test(details.url))return;
    const code=String(details.error||'').toUpperCase();
    const proxyish=/(ERR_(TUNNEL_CONNECTION_FAILED|PROXY_CONNECTION_FAILED|PROXY_AUTH_UNSUPPORTED|PROXY_AUTHENTICATION_FAILED|CONNECTION_TIMED_OUT|TIMED_OUT|CONNECTION_REFUSED)|PROXY|TUNNEL)/.test(code);
    if(!proxyish)return;
    const sites=(await CS.Store.get('clientSitesCache')).clientSitesCache||[];
    if(!managedUrlForSites(details.url,sites))return;
    const reason=`Browser reported ${details.error||'a proxy connection error.'}`;
    await beginProxyRecovery(reason);
    await holdLoadingTab(details.tabId,details.url);
  }catch{}
},{url:[{schemes:['http','https']}]});

chrome.webNavigation?.onBeforeNavigate?.addListener(async details=>{
  try{
    if(details.frameId!==0 || !details.url || details.url.startsWith(chrome.runtime.getURL('')))return;
    await applyCachedProxyImmediately();
  }catch{}

  try{
    if(details.frameId!==0 || !details.url || details.url.startsWith(chrome.runtime.getURL('')))return;
    const sites=await cachedManagedSites();
    if(!managedUrlForSites(details.url,sites))return;
    watchManagedLoadingTab(details.tabId,details.url);
    const r=await CS.Store.get('proxyRecoveryState');
    if(!r.proxyRecoveryState?.active)return;
    await holdLoadingTab(details.tabId,details.url);
  }catch{}
},{url:[{schemes:['http','https']}]});

chrome.webNavigation?.onCompleted?.addListener(details=>{
  if(details.frameId===0)clearLoadingWatch(details.tabId);
},{url:[{schemes:['http','https']}]});

async function applyCachedProxyImmediately(){
  try{
    const raw=await CS.Store.get(['lastSavedProxyConfig','activeProxyCredentials','clientProxyConfig']);
    const cached=raw.lastSavedProxyConfig||raw.clientProxyConfig||null;
    if(!cached || cached.mode==='unconfigured' || cached.enabled===false)return false;
    const proxy=CS.Proxy.normalize(cached);
    if(!proxy.host || !Number(proxy.port))return false;
    await CS.Proxy.setActiveCredentials(proxy);
    await CS.Proxy.apply(proxy);
    return true;
  }catch(e){
    await CS.Store.set({clientProxyHealth:{
      ok:false,pending:true,ip:null,reason:String(e?.message||e||'Proxy could not be applied.'),checkedAt:Date.now()
    }}).catch(()=>{});
    return false;
  }
}

async function startup(){
  // Apply the last known proxy locally first. The proxy must not depend on
  // opening the popup or on a successful Firebase round-trip.
  try{await chrome.alarms?.clear?.('cookie-sync-latest-snapshot');}catch{}
  await applyCachedProxyImmediately();
  await ensureProxyHealthAlarm();
  await ensureManualShareOpenAlarm();

  const scan=await CS.Security.scan((await CS.Store.get('clientSitesCache')).clientSitesCache||[]).catch(()=>({locked:false}));
  if(scan.locked)return;

  const rec=(await CS.Store.get('proxyRecoveryState').catch(()=>({}))).proxyRecoveryState;
  if(rec?.active && !proxyRecoveryPromise)setTimeout(()=>recoverProxyInBackground().catch(()=>{}),0);

  // Firebase/auth reconciliation remains separate from the local proxy apply.
  const existingSession=await CS.Auth.raw().catch(()=>null);
  if(existingSession?.uid){
    const marker=await CS.Store.get('clientLoginSessionStartedAt').catch(()=>({}));
    if(!Number(marker.clientLoginSessionStartedAt||0)){
      await CS.Store.set({clientLoginSessionStartedAt:Date.now()}).catch(()=>{});
    }
  }
  await clientStep({forceProxyTest:false,freshSync:false,syncCookies:false}).catch(()=>{});
}
chrome.runtime.onStartup.addListener(startup);
chrome.runtime.onInstalled.addListener(startup);
chrome.alarms?.onAlarm?.addListener(async alarm=>{
  if(alarm?.name===MANUAL_SHARE_OPEN_ALARM){await checkManualShareOpen().catch(()=>{});return;}
  if(alarm?.name!==PROXY_HEALTH_ALARM && alarm?.name!==PROXY_ROTATION_CLEANUP_ALARM)return;

  if(alarm?.name===PROXY_ROTATION_CLEANUP_ALARM){
    const pending=(await CS.Store.get('proxyRotationCleanupPending').catch(()=>({}))).proxyRotationCleanupPending;
    if(!(pending?.subadminUid && Number(pending.version)>0)){
      await chrome.alarms?.clear?.(PROXY_ROTATION_CLEANUP_ALARM).catch(()=>{});
      return;
    }
    const cleanup=await cleanupAfterProxyRotation(pending.subadminUid,Number(pending.version)).catch(e=>({ok:false,reason:e?.message||String(e)}));
    if(cleanup?.ok){
      await CS.Store.remove(['proxyRotationCleanupPending']).catch(()=>{});
      await chrome.alarms?.clear?.(PROXY_ROTATION_CLEANUP_ALARM).catch(()=>{});
      await CS.Store.set({clientProxyHealth:{ok:true,pending:false,ip:null,reason:'Browser session cleanup completed.',checkedAt:Date.now()}}).catch(()=>{});
      await clientStep({forceProxyTest:true,freshSync:false,deferProxyTest:false,syncCookies:false}).catch(()=>{});
    }else{
      await ensureProxyRotationCleanupAlarm();
    }
    return;
  }

  const r=await CS.Store.get('proxyRecoveryState').catch(()=>({}));
  if(r.proxyRecoveryState?.active===true || r.proxyRecoveryState?.confirmedFailed===true){
    if(r.proxyRecoveryState?.confirmedFailed===true && r.proxyRecoveryState?.active!==true) await beginProxyRecovery(r.proxyRecoveryState.lastError||'Retrying proxy connection…').catch(()=>{});
    await recoverProxyInBackground().catch(()=>{});
  }
});
chrome.management.onInstalled.addListener(async()=>{const bad=await CS.Security.unauthorizedExtensions().catch(()=>[]);if(bad.length){const s=(await CS.Store.get('clientSitesCache')).clientSitesCache||[];await CS.Security.lockdown(s,'Unauthorized Chrome extension detected').catch(()=>{});}});
chrome.management.onEnabled.addListener(async()=>{const bad=await CS.Security.unauthorizedExtensions().catch(()=>[]);if(bad.length){const s=(await CS.Store.get('clientSitesCache')).clientSitesCache||[];await CS.Security.lockdown(s,'Unauthorized Chrome extension detected').catch(()=>{});}});

async function refreshChromeForClient(options={}){
  // Intentionally clear browser site data, but never extension storage,
  // passwords, bookmarks, or the LogIn device/account state.
  await chrome.browsingData.remove({}, {
    cache: true,
    cacheStorage: true,
    cookies: true,
    fileSystems: true,
    formData: true,
    history: true,
    indexedDB: true,
    localStorage: true,
    serviceWorkers: true,
    webSQL: true
  });

  // Refreshes clean browser data first, then restore the current shared login
  // snapshot to the clean browser before showing the completion/welcome page.
  let sync=null;
  if(options.remoteAdmin || options.afterLogin){
    for(let attempt=0;attempt<2;attempt++){
      sync=await syncLatestCookies({fresh:true,reloadTabs:false}).catch(()=>null);
      if(sync?.ok)break;
      if(attempt===0)await CS.Util.sleep(350);
    }
  }

  const targetPage = options.afterLogin
    ? 'welcome.html'
    : `chrome-refreshed.html${options.remoteAdmin?('?remote=1'+(options.profileRefresh?'&profile=1':'')):''}`;
  const resetUrl = chrome.runtime.getURL(targetPage);
  const freshTab = await chrome.tabs.create({url: resetUrl, active: true});
  const tabs = await chrome.tabs.query({});
  const oldTabIds = tabs
    .filter(tab => tab.id !== freshTab.id)
    .map(tab => tab.id)
    .filter(id => Number.isInteger(id));

  if(oldTabIds.length){
    await chrome.tabs.remove(oldTabIds).catch(()=>{});
  }

  await chrome.tabs.update(freshTab.id,{active:true}).catch(()=>{});
  return {ok:true,sync};
}

chrome.runtime.onMessage.addListener((msg,sender,sendResponse)=>{(async()=>{
  if(msg.type==='fix-chrome')return await refreshChromeForClient();
  if(msg.type==='bootstrap')return{ok:true,...await cachedState()};
  if(msg.type==='proxy-wait-status'){
    const r=await CS.Store.get(['proxyRecoveryState','clientProxyHealth']);
    const rec=r.proxyRecoveryState||{active:false,confirmedFailed:false};
    if(rec.active)return{ok:true,status:'recovering',health:r.clientProxyHealth||null};
    if(rec.confirmedFailed)return{ok:true,status:'failed',health:r.clientProxyHealth||null};
    const me=await CS.Auth.currentProfile(false).catch(()=>null);
    return{ok:true,status:me?'connected':'signed_out',health:r.clientProxyHealth||null};
  }
  if(msg.type==='proxy-retry-now'){
    await beginProxyRecovery('Retrying proxy connection…');
    return{ok:true};
  }
  if(msg.type==='resume') return await clientStep({forceProxyTest:false,freshSync:false,deferProxyTest:true,allowDeviceReset:msg.allowDeviceReset===true,forceSites:true});
  if(msg.type==='device-gate') return await clientStep({forceProxyTest:false,freshSync:false,deferProxyTest:true,allowDeviceReset:msg.allowDeviceReset===true,forceSites:true});
  if(msg.type==='reauthorize-device') return await clientStep({forceProxyTest:true,freshSync:false,deferProxyTest:false,allowDeviceReset:true});
  if(msg.type==='check-proxy') return await clientStep({forceProxyTest:true,freshSync:false,deferProxyTest:false,allowDeviceReset:true,syncCookies:false});
  if(msg.type==='login'){
    try{
      const r=await CS.Auth.login(msg.email,msg.password,['client']);
      await CS.Store.set({clientLoginSessionStartedAt:Date.now()}).catch(()=>{});
      // During explicit login, suppress the one-time registration welcome inside
      // clientStep. If this is genuinely a NEW Chrome device, the full browser
      // cleanup runs exactly once below and the existing welcome page is shown.
      // Existing authorized devices do NOT get cleaned/refreshed on every login.
      const state=await clientStep({forceProxyTest:false,freshSync:false,deferProxyTest:true,forceSites:true,suppressFirstWelcome:true});
      if(state.suspended||state.deviceBlocked||state.locked||state.waitingForSite) return state;

      if(state?.newlyRegistered===true){
        const refreshed=await refreshChromeForClient({afterLogin:true}).catch(()=>({ok:false,sync:null}));
        if(!refreshed?.ok) throw new Error('Chrome could not be refreshed. Please try signing in again.');
        return{
          ok:true,
          profile:r.profile,
          ...state,
          ...(refreshed.sync||{}),
          proxy:state.proxy,
          health:state.health,
          proxyChecking:state.proxyChecking,
          loggedIn:true,
          loginBrowserRefreshed:true,
          newlyRegistered:true
        };
      }

      return{
        ok:true,
        profile:r.profile,
        ...state,
        loggedIn:true,
        loginBrowserRefreshed:false,
        newlyRegistered:false
      };
    }catch(e){
      await CS.Auth.logout().catch(()=>{});
      throw e;
    }
  }
  if(msg.type==='logout'){
  const sites=(await CS.Store.get('clientSitesCache')).clientSitesCache||[];
  const me=await CS.Auth.cached().catch(()=>null);
  await CS.Proxy.clear().catch(()=>{});
  await CS.Rules.applyNavigationPolicy(sites,{locked:true});
  await CS.Auth.logout();
  const keys=['clientSitesCache','clientSitesCacheAt','clientSitesCacheSubadminUid','clientSubStatusCache','clientSubStatusCacheAt','clientSubStatusCacheSubadminUid','clientControlCache','clientControlCacheAt','clientControlCacheSubadminUid','clientLastState','clientProxyHealth','clientLockReason','clientSuspendedReason','lastSavedProxyConfig','lastSavedProxyConfigAt','lastSavedProxySubadminUid','clientDeviceCache','clientDeviceCacheAt','clientDeviceCacheUid','proxyRecoveryState','clientLoginSessionStartedAt'];
  if(me?.subadminUid)keys.push(`syncGroupKey:${me.subadminUid}`);
  await CS.Store.remove(keys);
  return{ok:true};
}
  if(msg.type==='refresh')return clientStep({forceProxyTest:false,freshSync:false,forceSites:true});
  if(msg.type==='fresh-sync')return syncLatestCookies({fresh:true});
  if(msg.type==='warning-check')return CS.Security.recheck((await CS.Store.get('clientSitesCache')).clientSitesCache||[]);
  throw new Error('Unknown command.');
})().then(r=>sendResponse(r)).catch(e=>sendResponse({ok:false,error:e?.message||String(e)}));return true;});
