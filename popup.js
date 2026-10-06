const $ = (id) => document.getElementById(id);
let toastTimer = null;
let startupHealthTimer = null;
let popupState = { session: null, profile: null, sites: [], device: null, proxy: null, health: null };

function busy(button, on, label) {
  if (!button) return;
  if (on) {
    button.disabled = true;
    button.dataset.oldLabel = button.textContent;
    button.innerHTML = `<span class="spinner"></span>${escapeHtml(label)}`;
  } else {
    button.disabled = false;
    button.textContent = button.dataset.oldLabel || label;
    delete button.dataset.oldLabel;
  }
}

function show(id) {
  for (const name of ['startup', 'login', 'suspended', 'deviceBlocked', 'locked', 'app']) {
    $(name).classList.toggle('hidden', name !== id);
  }
}

function showError(message) {
  const box = $('loginError');
  box.textContent = String(message || 'Something went wrong.');
  box.classList.remove('hidden');
}

function clearError() {
  $('loginError').classList.add('hidden');
  $('loginError').textContent = '';
}

function showStartup(text = 'Restoring secure session…') {
  $('startupText').textContent = text;
  show('startup');
}

function showLocked(reason = 'Profile locked.') {
  $('lockedText').textContent = reason;
  show('locked');
}

function showSuspended() {
  show('suspended');
}

function showDeviceBlocked(reason = 'This account is already registered on another Chrome device.') {
  const box = $('deviceBlockedReason');
  if (box) box.textContent = reason;
  show('deviceBlocked');
}

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, (c) => ({
    '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#039;'
  }[c]));
}

function send(type, payload = {}, timeoutMs = 12000) {
  return new Promise((resolve) => {
    let finished = false;
    const finish = (value) => {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      resolve(value || { ok:false, error: chrome.runtime.lastError?.message || 'No response from extension.' });
    };
    const timer = setTimeout(() => finish({
      ok:false,
      error:'The background service did not respond. The interface is still available; please retry.'
    }), timeoutMs);
    try {
      chrome.runtime.sendMessage({ type, ...payload }, (response) => {
        if (chrome.runtime.lastError) finish({ ok:false, error:chrome.runtime.lastError.message });
        else finish(response);
      });
    } catch (error) {
      finish({ ok:false, error:error?.message || String(error) });
    }
  });
}

async function restoreAuth() {
  const session=await CS.Auth.session(false);
  if(!session)return null;
  try{
    return await CS.Auth.currentProfile(true);
  }catch(error){
    if(error?.code==='ACCOUNT_SUSPENDED'){
      return{suspended:true,profile:error.profile||null,session};
    }
    const cached=await CS.Auth.cached();
    if(cached)return{session,profile:cached,stale:true};
    throw error;
  }
}

async function loadAssignedState(authState) {
  const { session, profile } = authState;
  if (!profile || profile.role !== 'client') throw new Error('This account is not a client account.');
  if (profile.active === false) return { suspended:true };

  const subId = String(profile.subadminUid || '').trim();
  if (!subId) throw new Error('This client account has no assigned Admin Extension.');

  const [statusDoc, accessDoc, proxyDoc, legacyProxyDoc, clientDevice] = await Promise.all([
    CS.Firebase.getDoc(['users', subId, 'control', 'status'], session.idToken),
    CS.Firebase.getDoc(['clientAccess', session.uid], session.idToken).catch(() => ({exists:false, data:null})),
    CS.Firebase.getDoc(['users', subId, 'proxy', 'config'], session.idToken).catch(() => ({ exists:false, data:null })),
    CS.Firebase.getDoc(['subadminProxyConfigs', subId], session.idToken).catch(() => ({ exists:false, data:null })),
    CS.Firebase.getDoc(['devices', session.uid], session.idToken).catch(() => ({ exists:false, data:null }))
  ]);

  if (statusDoc.exists && statusDoc.data?.active === false) return { suspended:true };

  let sites = [];

  // Hidden Main Admin-created clients inherit the Admin Extension's current
  // active website set. Resolve it live so adding/removing a managed website
  // is reflected immediately after login or Fresh Sync, without a stale
  // copied siteIds/clientAccess list.
  if (profile.visibleToSubadmin === false) {
    const docs = await CS.Firebase.queryDocsByField(
      ['sites'],
      'subadminUid',
      'EQUAL',
      subId,
      session.idToken
    );
    sites = docs
      .filter((d) => d.data?.active !== false && d.data?.enabled !== false)
      .map((d) => ({id:d.id, ...d.data}))
      .sort((a,b) => String(a.name || a.hostname).localeCompare(String(b.name || b.hostname)));
  } else {
    let siteIds = Array.isArray(accessDoc.data?.siteIds) ? accessDoc.data.siteIds.map(String) : [];
    if (!siteIds.length && Array.isArray(profile.siteIds)) siteIds = profile.siteIds.map(String);
    if (!siteIds.length && profile.siteId) siteIds = [String(profile.siteId)];

    sites = (await Promise.all(siteIds.map(async (siteId) => {
      const site = await CS.Firebase.getDoc(['sites', siteId], session.idToken).catch(() => ({exists:false}));
      if (!site.exists || site.data?.active === false || site.data?.enabled === false) return null;
      if (String(site.data?.subadminUid || '') !== subId) return null;
      return {id:siteId, ...site.data};
    }))).filter(Boolean);
  }

  return {
    ok:true,
    loggedIn:true,
    session,
    profile,
    sites,
    proxy:(proxyDoc.exists && proxyDoc.data?.host && proxyDoc.data?.port ? proxyDoc.data : (legacyProxyDoc.exists && legacyProxyDoc.data?.host && legacyProxyDoc.data?.port ? legacyProxyDoc.data : { mode:'unconfigured', healthy:false, ip:'', lastError:'Proxy is not configured.' })),
    device:clientDevice.exists ? clientDevice.data : null,
    localOnly:true
  };
}

async function verifyCurrentProxy(authState, state) {
  const proxy = CS.Proxy.normalize(state.proxy || {mode:'unconfigured'});
  if (proxy.mode === 'unconfigured') {
    return { ok:false, ip:null, reason:'Proxy is not configured.' };
  }

  await CS.Proxy.setActiveCredentials(proxy);
  await CS.Proxy.apply(proxy);
  await CS.Rules.applyNavigationPolicy(state.sites || [], { locked:false, testEnabled:true });

  try {
    const fresh = { ...proxy, expectedIp: String(proxy.expectedIp || '').trim() };
    const result = await CS.Proxy.test(fresh);
    return result;
  } finally {
    // Keep the normal navigation policy active after the one-time test.
    await CS.Rules.applyNavigationPolicy(state.sites || [], { locked:false, testEnabled:false }).catch(() => {});
  }
}

async function updateDeviceIp(authState, state, health) {
  if (!state?.device || !health?.ok) return;
  // Public IP / proxy-health telemetry is local runtime state; do not write it
  // to Firebase merely because the popup performed a health check.
  popupState.device = {
    ...state.device,
    lastIp:health.ip || state.device.lastIp || '',
    proxyHealthy:true,
    status:'active',
    lastProxyCheckAt:CS.Util.now()
  };
}

function render(state) {
  const previousState=popupState||{};
  popupState = state;
  if (state?.suspended || state?.suspendedReason) return showSuspended();
  if (!state?.locked && state?.deviceResetRequired) {
    $('username').textContent = state.profile?.displayName || state.profile?.email || 'User';
    $('accountEmail').textContent = state.profile?.email || '';
    $('website').textContent = 'Device reset pending';
    $('ip').textContent = '—';
    $('proxy').textContent = '—';
    $('lastSync').textContent = 'Not synced';
    $('proxyBadge').className = 'badge warn';
    $('proxyBadge').innerHTML = '<span class="dot"></span>Re-authorizing';
    $('proxyInfo').className = 'alert info';
    $('proxyInfo').textContent = 'This device was reset. Re-open the extension to authorize it again.';
    $('syncInfo').textContent = '';
    $('sitesList').innerHTML = '';
    show('app');
    return;
  }
  if (state?.locked && (state?.waitingForSite || state?.waitingForDevice)) {
    $('username').textContent = state.profile?.displayName || state.profile?.email || 'User';
    $('accountEmail').textContent = state.profile?.email || '';
    $('website').textContent = state.waitingForDevice ? 'Device reset pending' : 'Waiting for assignment';
    $('ip').textContent = '—';
    $('proxy').textContent = '—';
    $('lastSync').textContent = 'Not synced';
    $('proxyBadge').className = 'badge warn';
    $('proxyBadge').innerHTML = '<span class="dot"></span>Waiting';
    $('proxyInfo').className = 'alert info';
    $('proxyInfo').textContent = state.waitingForDevice
      ? 'This device was reset. Waiting for the new device registration to become active.'
      : 'Your Admin Extension has not assigned a managed website yet.';
    show('app');
    return;
  }
  if (state?.locked || state?.lockReason) return showLocked(state.error || state.lockReason);
  if (!state?.profile) return show('login');

  $('username').textContent = state.profile.displayName || state.profile.email || 'User';
  $('accountEmail').textContent = state.profile.email || '';
  $('website').textContent = state.sites?.length === 1
    ? (state.sites[0].name || state.sites[0].hostname)
    : `${state.sites?.length || 0} managed websites`;
  const proxyState=state.proxy || previousState.proxy || {};
  const healthState=state.health || state.proxyHealth || previousState.health || previousState.proxyHealth || {};
  const deviceState=state.device || previousState.device || {};
  const lastState=state.lastState || previousState.lastState || {};

  $('ip').textContent = healthState?.ip || deviceState?.lastIp || lastState?.ip || (state.proxyChecking?'Checking…':'—');
  $('proxy').textContent = proxyState?.mode === 'fixed_servers'
    ? `${proxyState.scheme || 'http'}://${proxyState.host}:${proxyState.port}`
    : 'Not configured';
  $('lastSync').textContent = deviceState?.lastSyncAt
    ? new Date(deviceState.lastSyncAt).toLocaleString()
    : (lastState?.lastSyncAt ? new Date(lastState.lastSyncAt).toLocaleString() : 'Not synced');

  const h = healthState;
  const configured = proxyState?.mode === 'fixed_servers';
  const checking = configured && (state.proxyChecking === true || h.pending === true);
  // Preserve the last-known-good/optimistic connected state while verification
  // is in progress. Only an explicit confirmed failure should turn it red.
  const confirmedFailure = configured && h.pending !== true && h.ok === false && state.proxyFailed === true;
  const working = configured && !confirmedFailure && (
    h.ok === true ||
    deviceState?.proxyHealthy === true ||
    checking ||
    (!h.ok && h.pending !== false && !state.proxyFailed)
  );
  $('proxyBadge').className = `badge ${working ? 'good' : 'bad'}`;
  $('proxyBadge').innerHTML = `<span class="dot"></span>${working ? 'Connected' : 'Not Working'}`;
  $('proxyInfo').className = `alert ${working ? 'info' : 'bad'}`;
  $('proxyInfo').textContent = working
    ? (checking ? 'Verifying the proxy in the background…' : 'Proxy is active for this device.')
    : (h.reason || state.proxy?.lastError || state.error || 'Proxy is not configured or not working.');
  // syncInfo remains as a hidden compatibility hook; keep the dashboard visually quiet.
  $('syncInfo').textContent = '';
  $('sitesList').innerHTML = (state.sites || []).map((site) =>
    `<div class="site-pill"><span>${escapeHtml(site.name || site.hostname)}</span><span>${escapeHtml(site.hostname || '')}</span></div>`
  ).join('') || '<div class="small">No managed websites are currently assigned.</div>';
  show('app');
}

async function performBackgroundSync(forceProxyTest = false, freshSync = false) {
  const r = await send(freshSync ? 'fresh-sync' : 'refresh', {}, 18000);
  if (!r.ok && !r.loggedIn && !r.suspended) return r;
  render(r);
  return r;
}

function watchProxyRecovery(baseState){
  clearInterval(startupHealthTimer);
  startupHealthTimer=setInterval(async()=>{
    try{
      const r=await send('proxy-wait-status',{},4000);
      if(r?.status==='recovering'){
        render({...baseState,health:r.health||{ok:false,pending:true,reason:'Reconnecting to proxy…'},proxyChecking:true,proxyFailed:false});
        return;
      }
      if(r?.status==='failed'){
        clearInterval(startupHealthTimer);
        render({...baseState,health:r.health||{ok:false,pending:false,reason:'Proxy could not be restored.'},proxyChecking:false,proxyFailed:true});
        return;
      }
      clearInterval(startupHealthTimer);
    }catch{}
  },1500);
}

async function startup() {
  clearError();
  showStartup('Restoring secure session…');
  const watchdog=setTimeout(()=>{
    if(!$('startup').classList.contains('hidden')){
      show('login');
      showError('Startup is taking too long. Please reload the extension.');
    }
  },15000);

  try{
    const local=await restoreAuth();
    if(!local){clearTimeout(watchdog);show('login');return;}
    if(local.suspended){clearTimeout(watchdog);showSuspended();return;}

    showStartup('Checking your authorized device…');
    const state=await send('resume',{allowDeviceReset:true},20000);
    clearTimeout(watchdog);

    if(state?.deviceBlocked)return showDeviceBlocked(state.error);
    if(state?.suspended)return showSuspended();
    if(state?.locked)return render(state);
    if(!(state?.profile&&state?.loggedIn))throw new Error(state?.error||'This device could not be authorized.');

    render(state);

    if(state?.proxy?.mode==='fixed_servers'||state?.proxyChecking){
      const health=await send('check-proxy',{},20000);
      if(health?.deviceBlocked)return showDeviceBlocked(health.error);
      if(health?.suspended)return showSuspended();
      if(health?.profile&&health?.loggedIn)render(health);
      else render({...state,...health,proxyFailed:health?.proxyFailed===true,health:health?.health||{ok:false,reason:health?.error||'Proxy is not working.'}});
      if(health?.proxyChecking===true || health?.health?.pending===true)watchProxyRecovery({...state,...health,proxy:health.proxy||state.proxy,profile:health.profile||state.profile,sites:health.sites||state.sites,device:health.device||state.device});
    }
  }catch(error){
    clearTimeout(watchdog);
    show('login');
    showError(error?.message||String(error));
  }
}

function setProxyChecking(){
  const badge=$('proxyBadge'),info=$('proxyInfo');
  if(badge){badge.className='badge warn';badge.innerHTML='<span class="dot"></span>Checking';}
  if(info){info.className='alert info';info.textContent='Checking the current proxy and public IP…';}
}


$('fixChrome').onclick = async () => {
  const b = $('fixChrome');
  busy(b, true, 'Refreshing…');
  try {
    const r = await send('fix-chrome', {}, 30000);
    if (!r?.ok) {
      toast(r?.error || 'Chrome could not be refreshed.');
      busy(b, false, 'Fix Chrome');
    }
  } catch (error) {
    toast(error?.message || 'Chrome could not be refreshed.');
    busy(b, false, 'Fix Chrome');
  }
};

$('loginBtn').onclick=async()=>{
  clearError();
  const email=$('email').value.trim(),password=$('password').value;
  if(!email||!password){showError('Enter email and password.');return;}
  const b=$('loginBtn');busy(b,true,'Signing in…');
  try{
    const result=await send('login',{email,password},20000);
    if(result?.deviceBlocked)return showDeviceBlocked(result.error);
    if(result?.suspended)return showSuspended();
    if(result?.profile&&result?.loggedIn){
      render(result);
      if(result?.proxy?.mode==='fixed_servers'||result?.proxyChecking){
        const health=await send('check-proxy',{},20000);
        if(health?.deviceBlocked)return showDeviceBlocked(health.error);
        if(health?.suspended)return showSuspended();
        if(health?.profile&&health?.loggedIn)render(health);
        else render({...result,...health,proxyFailed:health?.proxyFailed===true,health:health?.health||{ok:false,reason:health?.error||'Proxy is not working.'}});
        if(health?.proxyChecking===true || health?.health?.pending===true)watchProxyRecovery({...result,...health,proxy:health.proxy||result.proxy,profile:health.profile||result.profile,sites:health.sites||result.sites,device:health.device||result.device});
      }
      if(Number(result?.applied||0)>0){
        toast(`Login completed • ${result.applied} site${Number(result.applied)===1?'':'s'} synced.`);
      }else{
        const d=(result?.syncDiagnostics||[]).find(x=>x?.status && x.status!=='missing');
        if(d?.status==='invalid-snapshot') toast('Login succeeded, but the latest cookie snapshot could not be restored.');
        else if(d?.status==='site-id-mismatch') toast('Login succeeded, but the cookie snapshot did not match the assigned site.');
      }
      return;
    }
    show('login');showError(result?.error||'Sign in failed.');
  }catch(error){
    show('login');showError(error?.message||String(error));
  }finally{busy(b,false,'Sign in');}
};

$('freshSync').onclick = async () => {
  const b = $('freshSync');
  let completed = false;
  busy(b, true, 'Logging In…');
  try {
    const r = await send('fresh-sync', {}, 20000);
    render(r);
    if (r?.ok) {
      completed = true;
      b.disabled = true;
      b.classList.add('login-success');
      b.textContent = 'Logged In';

      if(r.applied){
        const failed=Number(r.cookieFailures||0);
        toast(failed
          ? `Login completed • ${failed} cookie${failed===1?'':'s'} failed.`
          : (Number(r.reloadedTabs||0)>0
            ? `Login completed • ${r.reloadedTabs} managed tab${r.reloadedTabs===1?' was':'s were'} refreshed.`
            : `Login completed for ${r.applied} site${r.applied===1?'':'s'}.`));
      }else{
        const d=(r.syncDiagnostics||[])[0];
        toast(d?.status==='already-applied' ? 'Login completed • latest session already applied.' : (r.error||'Login completed.'));
      }
      return;
    }
    toast(r?.error || 'Login failed.');
  } finally {
    if (!completed) busy(b, false, 'LogIn Website');
  }
};

$('logout').onclick = async () => {
  const b = $('logout');
  busy(b, true, 'Signing out…');
  await send('logout', {}, 10000);
  await CS.Auth.logout().catch(() => {});
  show('login');
  busy(b, false, '↪');
};

$('retrySuspended').onclick = () => startup();
$('retryLocked').onclick = async () => {
  const r = await send('warning-check');
  if (r?.ok) startup(); else showLocked(r?.error || 'Remove unauthorized extensions first.');
};
$('grantAccess').onclick = async () => {
  const local = await restoreAuth();
  if (!local) return show('login');
  try {
    const state = await loadAssignedState(local);
    const origins = [...new Set((state.sites || []).flatMap((site) => {
      try { return [`${new URL(site.origin).origin}/*`]; } catch { return []; }
    }))];
    if (!origins.length || await chrome.permissions.request({origins})) {
      await performBackgroundSync(false, false);
      toast('Website access granted.');
    } else toast('Permission was not granted.');
  } catch (error) {
    toast(error?.message || String(error));
  }
};

function toast(message) {
  const el = $('toast');
  el.textContent = String(message || '');
  el.classList.remove('hidden');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.add('hidden'), 2400);
}

// Always show a usable login screen if JavaScript starts successfully but Firebase
// or the background worker is unavailable. This avoids a blank white popup.
show('login');
startup();

$('deviceBlockedBack').onclick=()=>show('login');

window.addEventListener('unload',()=>clearInterval(startupHealthTimer));
