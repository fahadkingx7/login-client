globalThis.CS = globalThis.CS || {};
CS.Auth = (() => {
  const SESSION='authSession', PROFILE='profileCache';
  async function save(s){await CS.Store.set({[SESSION]:s});}
  async function raw(){const r=await CS.Store.get(SESSION);return r[SESSION]||null;}
  async function cached(){const r=await CS.Store.get(PROFILE);return r[PROFILE]||null;}
  async function clear(){await CS.Store.remove([SESSION,PROFILE]);}
  async function refreshIfNeeded(s){
    if(!s)return null;if(Number(s.expiresAt||0)-Date.now()>5*60*1000)return s;if(!s.refreshToken)return null;
    try{const n=await CS.Firebase.refresh(s.refreshToken);const next={uid:n.user_id||s.uid,email:s.email,idToken:n.id_token,refreshToken:n.refresh_token||s.refreshToken,expiresAt:Date.now()+Number(n.expires_in||3600)*1000};await save(next);return next;}
    catch(e){if(['INVALID_GRANT','INVALID_REFRESH_TOKEN','USER_DISABLED'].includes(String(e.code||''))){await clear();return null;}return s;}
  }
  async function session(fresh=true){const s=await raw();return fresh?refreshIfNeeded(s):s;}
  async function fetchProfile(s){
    const r=await CS.Firebase.getDoc(['users',s.uid],s.idToken);if(!r.exists){const e=new Error('Account profile is missing.');e.code='PROFILE_MISSING';throw e;}
    await CS.Store.set({[PROFILE]:r.data});
    if(r.data.active===false){const e=new Error('Account suspended.');e.code='ACCOUNT_SUSPENDED';e.profile=r.data;throw e;}
    return r.data;
  }
  async function login(email,password,roles){
    const a=await CS.Firebase.signIn(CS.Util.normalizeEmail(email),password);
    const s={uid:a.localId,email:a.email,idToken:a.idToken,refreshToken:a.refreshToken,expiresAt:Date.now()+Number(a.expiresIn||3600)*1000};await save(s);
    try{const p=await fetchProfile(s);if(!roles.includes(p.role))throw new Error('This account cannot use this extension.');return{session:s,profile:p};}
    catch(e){if(e.code==='ACCOUNT_SUSPENDED')return{session:s,profile:e.profile,suspended:true};await clear();throw e;}
  }
  async function currentProfile(fresh=true){
    const s=await session(fresh);if(!s)return null;const p=await cached();
    if(!fresh&&p)return{session:s,profile:p,suspended:p.active===false};
    try{return{session:s,profile:await fetchProfile(s)}}catch(e){if(e.code==='ACCOUNT_SUSPENDED')return{session:s,profile:e.profile||p,suspended:true};if(e.code==='PROFILE_MISSING')await clear();throw e;}
  }
  async function createUser(email,password){const a=await CS.Firebase.signUp(CS.Util.normalizeEmail(email),password);return{uid:a.localId,email:a.email,idToken:a.idToken};}
  async function deleteCreatedUser(idToken){try{await CS.Firebase.deleteAuthAccount(idToken)}catch{}}
  async function logout(){await clear();}
  return {save,raw,cached,session,currentProfile,login,logout,createUser,deleteCreatedUser};
})();
