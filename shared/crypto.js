globalThis.CS = globalThis.CS || {};
CS.Crypto = (() => {
  const enc = new TextEncoder(), dec = new TextDecoder();
  const b64 = bytes => btoa(String.fromCharCode(...new Uint8Array(bytes)));
  const unb64 = s => Uint8Array.from(atob(String(s)), c => c.charCodeAt(0));

  const KEY='deviceIdentity';

  async function generateKeyMaterial(){
    const kp=await crypto.subtle.generateKey(
      {name:'ECDH',namedCurve:'P-256'},
      true,
      ['deriveBits']
    );
    return {
      privateJwk:await crypto.subtle.exportKey('jwk',kp.privateKey),
      publicJwk:await crypto.subtle.exportKey('jwk',kp.publicKey)
    };
  }

  async function readIdentity(){
    const r=await CS.Store.get(KEY);
    return r[KEY]||null;
  }

  async function ensureDeviceIdentity(){
    const existing=await readIdentity();

    // Never generate a new deviceId merely because the popup reopened,
    // service worker restarted, or the user signed out/in.
    if(existing?.deviceId) return existing;

    const identity={
      deviceId:CS.Util.uuid(),
      ...await generateKeyMaterial(),
      createdAt:CS.Util.now()
    };
    await CS.Store.set({[KEY]:identity});
    return identity;
  }

  async function getStoredDeviceIdentityCandidates(){
    const identity=await readIdentity();
    return identity?.deviceId?[identity]:[];
  }

  async function getStoredDeviceIdentity(){
    const list=await getStoredDeviceIdentityCandidates();
    return list[0]||null;
  }

  async function persistDeviceIdentity(identity){
    if(!identity?.deviceId) throw new Error('Invalid device identity.');
    await CS.Store.set({[KEY]:identity});
    return identity;
  }

  async function importPrivate(jwk){
    return crypto.subtle.importKey(
      'jwk',jwk,
      {name:'ECDH',namedCurve:'P-256'},
      false,
      ['deriveBits']
    );
  }

  async function importPublic(jwk){
    return crypto.subtle.importKey(
      'jwk',jwk,
      {name:'ECDH',namedCurve:'P-256'},
      false,
      []
    );
  }

  async function deriveAes(privateKey,publicKey,salt,info){
    const bits=await crypto.subtle.deriveBits(
      {name:'ECDH',public:publicKey},
      privateKey,
      256
    );
    const material=await crypto.subtle.importKey(
      'raw',bits,{name:'HKDF'},false,['deriveKey']
    );
    return crypto.subtle.deriveKey(
      {
        name:'HKDF',
        hash:'SHA-256',
        salt,
        info:new TextEncoder().encode(info)
      },
      material,
      {name:'AES-GCM',length:256},
      false,
      ['encrypt','decrypt']
    );
  }

  async function encryptForPublic(value,recipientPublicJwk,aadValue=''){
    const eph=await crypto.subtle.generateKey(
      {name:'ECDH',namedCurve:'P-256'},
      true,
      ['deriveBits']
    );
    const ephPublicJwk=await crypto.subtle.exportKey('jwk',eph.publicKey);
    const salt=crypto.getRandomValues(new Uint8Array(16));
    const iv=crypto.getRandomValues(new Uint8Array(12));
    const key=await deriveAes(
      eph.privateKey,
      await importPublic(recipientPublicJwk),
      salt,
      'cookie-sync-v2'
    );
    const plaintext=new TextEncoder().encode(JSON.stringify(value));
    const aad=new TextEncoder().encode(String(aadValue||''));
    const ciphertext=await crypto.subtle.encrypt(
      {name:'AES-GCM',iv,additionalData:aad},
      key,
      plaintext
    );
    const b64=b=>btoa(String.fromCharCode(...new Uint8Array(b)));
    return {
      v:2,
      ephemeralPublicJwk:ephPublicJwk,
      salt:b64(salt),
      iv:b64(iv),
      ciphertext:b64(ciphertext),
      aad:String(aadValue||'')
    };
  }

  async function decryptEnvelope(envelope,privateJwk){
    if(!envelope||envelope.v!==2) throw new Error('Unsupported encrypted payload.');
    const ub=s=>Uint8Array.from(atob(String(s)),c=>c.charCodeAt(0));
    const priv=await importPrivate(privateJwk);
    const peer=await importPublic(envelope.ephemeralPublicJwk);
    const key=await deriveAes(
      priv,
      peer,
      ub(envelope.salt),
      'cookie-sync-v2'
    );
    const plaintext=await crypto.subtle.decrypt(
      {
        name:'AES-GCM',
        iv:ub(envelope.iv),
        additionalData:new TextEncoder().encode(String(envelope.aad||''))
      },
      key,
      ub(envelope.ciphertext)
    );
    return JSON.parse(new TextDecoder().decode(plaintext));
  }

  async function newKeyBase64(){
    const bytes=crypto.getRandomValues(new Uint8Array(32));
    return btoa(String.fromCharCode(...bytes));
  }

  async function importRawKey(base64){
    const bytes=Uint8Array.from(atob(String(base64)),c=>c.charCodeAt(0));
    if(bytes.byteLength!==32) throw new Error('Invalid synchronization key.');
    return crypto.subtle.importKey(
      'raw',bytes,{name:'AES-GCM'},false,['encrypt','decrypt']
    );
  }

  async function encryptWithKey(value,base64,aad=''){
    const key=await importRawKey(base64);
    const iv=crypto.getRandomValues(new Uint8Array(12));
    const ciphertext=await crypto.subtle.encrypt(
      {name:'AES-GCM',iv,additionalData:new TextEncoder().encode(String(aad||''))},
      key,
      new TextEncoder().encode(JSON.stringify(value))
    );
    const b64=b=>btoa(String.fromCharCode(...new Uint8Array(b)));
    return {
      v:1,
      iv:b64(iv),
      ciphertext:b64(ciphertext),
      aad:String(aad||'')
    };
  }

  async function decryptWithKey(envelope,base64){
    if(envelope?.v===2){
      const identity=await ensureDeviceIdentity();
      return decryptEnvelope(envelope,identity.privateJwk);
    }
    if(!envelope||envelope.v!==1) throw new Error('Unsupported synchronization payload.');
    const key=await importRawKey(base64);
    const ub=s=>Uint8Array.from(atob(String(s)),c=>c.charCodeAt(0));
    const plaintext=await crypto.subtle.decrypt(
      {
        name:'AES-GCM',
        iv:ub(envelope.iv),
        additionalData:new TextEncoder().encode(String(envelope.aad||''))
      },
      key,
      ub(envelope.ciphertext)
    );
    return JSON.parse(new TextDecoder().decode(plaintext));
  }

  return {
    ensureDeviceIdentity,
    getStoredDeviceIdentityCandidates,
    getStoredDeviceIdentity,
    persistDeviceIdentity,
    encryptForPublic,
    decryptEnvelope,
    newKeyBase64,
    encryptWithKey,
    decryptWithKey
  };
})();
