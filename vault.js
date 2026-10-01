/* GTwin vault: enkripsi sisi-klien dengan WebCrypto (dipakai index.html dan admin.html) */
const VT=new TextEncoder(),VITER=600000,CHUNK=20*1024*1024;
const b64=u=>{let s='';for(let i=0;i<u.length;i+=32768)s+=String.fromCharCode.apply(null,u.subarray(i,i+32768));return btoa(s)};
const ub64=s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0));
const hex=n=>[...crypto.getRandomValues(new Uint8Array(n))].map(b=>b.toString(16).padStart(2,'0')).join('');
async function pwKey(pw,salt,iter){const k=await crypto.subtle.importKey('raw',VT.encode(pw),'PBKDF2',false,['deriveKey']);
return crypto.subtle.deriveKey({name:'PBKDF2',salt,iterations:iter,hash:'SHA-256'},k,{name:'AES-GCM',length:256},false,['encrypt','decrypt'])}
async function aesEnc(key,data){const iv=crypto.getRandomValues(new Uint8Array(12)),ct=new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM',iv},key,data)),o=new Uint8Array(12+ct.length);o.set(iv);o.set(ct,12);return o}
async function aesDec(key,buf){buf=new Uint8Array(buf);return crypto.subtle.decrypt({name:'AES-GCM',iv:buf.subarray(0,12)},key,buf.subarray(12))}
const newMaster=()=>crypto.subtle.generateKey({name:'AES-GCM',length:256},true,['encrypt','decrypt']);
const RSA={name:'RSA-OAEP',hash:'SHA-256'};
async function makeUser(username,password,master){
const kp=await crypto.subtle.generateKey({...RSA,modulusLength:2048,publicExponent:new Uint8Array([1,0,1])},true,['wrapKey','unwrapKey']),
salt=crypto.getRandomValues(new Uint8Array(16)),pk=await pwKey(password,salt,VITER),
priv=new Uint8Array(await crypto.subtle.exportKey('pkcs8',kp.privateKey)),pub=new Uint8Array(await crypto.subtle.exportKey('spki',kp.publicKey)),
wk=new Uint8Array(await crypto.subtle.wrapKey('raw',master,kp.publicKey,{name:'RSA-OAEP'}));
return{u:username,iter:VITER,salt:b64(salt),priv:b64(await aesEnc(pk,priv)),pub:b64(pub),wk:b64(wk)}}
async function rewrap(user,master){const pub=await crypto.subtle.importKey('spki',ub64(user.pub),RSA,false,['wrapKey']);
return{...user,wk:b64(new Uint8Array(await crypto.subtle.wrapKey('raw',master,pub,{name:'RSA-OAEP'})))}}
async function vaultLogin(users,username,password,extractable){
const u=users.find(x=>x.u.toLowerCase()===String(username).trim().toLowerCase());
if(!u){await pwKey(password,new Uint8Array(16),VITER);throw new Error('login')}
const pk=await pwKey(password,ub64(u.salt),u.iter);let priv;
try{priv=await aesDec(pk,ub64(u.priv))}catch(x){throw new Error('login')}
const pr=await crypto.subtle.importKey('pkcs8',priv,RSA,false,['unwrapKey']);
return crypto.subtle.unwrapKey('raw',ub64(u.wk),pr,{name:'RSA-OAEP'},{name:'AES-GCM',length:256},!!extractable,['encrypt','decrypt'])}
async function encModel(key,file,onChunk){const id=hex(4),files=[];let n=0;
for(let o=0;o<file.size;o+=CHUNK){files.push({path:`m_${id}.${n}.bin`,blob:new Blob([await aesEnc(key,await file.slice(o,o+CHUNK).arrayBuffer())])});n++;if(onChunk)onChunk(n)}
return{id,chunks:n,files}}
const encJSON=async(key,obj)=>new Blob([await aesEnc(key,VT.encode(JSON.stringify(obj)))]);
const decJSON=async(key,buf)=>JSON.parse(new TextDecoder().decode(await aesDec(key,buf)));
/* ZIP sederhana (tanpa kompresi) */
const CRCT=(()=>{const t=new Uint32Array(256);for(let n=0;n<256;n++){let c=n;for(let k=0;k<8;k++)c=c&1?0xEDB88320^(c>>>1):c>>>1;t[n]=c>>>0}return t})();
function crc32(u){let c=0xFFFFFFFF;for(let i=0;i<u.length;i++)c=CRCT[(c^u[i])&255]^(c>>>8);return(c^0xFFFFFFFF)>>>0}
async function zipBlob(files){const parts=[],cd=[],te=new TextEncoder(),d=new Date(),
dt=((d.getFullYear()-1980)<<9)|((d.getMonth()+1)<<5)|d.getDate(),tm=(d.getHours()<<11)|(d.getMinutes()<<5)|(d.getSeconds()>>1);let off=0;
for(const[p,b]of files){const nm=te.encode(p),crc=crc32(new Uint8Array(await b.arrayBuffer())),sz=b.size,h=new DataView(new ArrayBuffer(30));
h.setUint32(0,0x04034b50,true);h.setUint16(4,20,true);h.setUint16(6,0x0800,true);h.setUint16(8,0,true);h.setUint16(10,tm,true);h.setUint16(12,dt,true);h.setUint32(14,crc,true);h.setUint32(18,sz,true);h.setUint32(22,sz,true);h.setUint16(26,nm.length,true);h.setUint16(28,0,true);
parts.push(h.buffer,nm,b);
const c=new DataView(new ArrayBuffer(46));c.setUint32(0,0x02014b50,true);c.setUint16(4,20,true);c.setUint16(6,20,true);c.setUint16(8,0x0800,true);c.setUint16(10,0,true);c.setUint16(12,tm,true);c.setUint16(14,dt,true);c.setUint32(16,crc,true);c.setUint32(20,sz,true);c.setUint32(24,sz,true);c.setUint16(28,nm.length,true);c.setUint32(42,off,true);
cd.push(c.buffer,nm);off+=30+nm.length+sz}
let cs=0;cd.forEach(x=>cs+=x.byteLength||x.length);
const e=new DataView(new ArrayBuffer(22));e.setUint32(0,0x06054b50,true);e.setUint16(8,files.length,true);e.setUint16(10,files.length,true);e.setUint32(12,cs,true);e.setUint32(16,off,true);
return new Blob([...parts,...cd,e.buffer],{type:'application/zip'})}
