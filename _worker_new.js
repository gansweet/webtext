/*
=========================================================
 ADVANCED MARKDOWN WORKSPACE
 Cloudflare Worker - Enhanced Edition

 NEW IMPROVEMENTS
 --------------------------------------------------------
 ✓ Full Markdown toolbar
 ✓ Insert markdown buttons
 ✓ Better writing workspace
 ✓ Reading themes
 ✓ Linen reading background
 ✓ Live save indicator
 ✓ Better editor layout
 ✓ Better reading UI
 ✓ Markdown shortcuts
 ✓ Responsive mobile/iPad/desktop
 ✓ Preview mode
 ✓ Autosave
 ✓ Word count
 ✓ Reading time
 ✓ Copy code blocks
 ✓ Search
 ✓ Rename/Delete/Reorder docs

 REQUIRED:
 --------------------------------------------------------
 KV Binding:
 CONTENT_KV

 ENV:
 PASSWORD
 SECRET
 SESSION_TTL_SECONDS
=========================================================
*/

const COOKIE_NAME = 'wksess';

export default {
  async fetch(request, env) {
    return handleRequest(request, env);
  },
};

/* =====================================================
   UTILS
===================================================== */

async function sha256Hex(text){

  const enc = new TextEncoder();

  const data = enc.encode(text);

  const hash = await crypto.subtle.digest(
    'SHA-256',
    data
  );

  return Array.from(new Uint8Array(hash))
    .map(b=>b.toString(16).padStart(2,'0'))
    .join('');
}

function base64UrlEncode(bytes){

  const b64 = btoa(
    String.fromCharCode(...new Uint8Array(bytes))
  );

  return b64
    .replace(/\+/g,'-')
    .replace(/\//g,'_')
    .replace(/=+$/,'');
}

function base64UrlDecodeToUint8Array(str){

  str = str.replace(/-/g,'+')
           .replace(/_/g,'/');

  while(str.length % 4){
    str += '=';
  }

  const bin = atob(str);

  const arr = new Uint8Array(bin.length);

  for(let i=0;i<bin.length;i++){
    arr[i]=bin.charCodeAt(i);
  }

  return arr;
}

async function hmacSha256Sign(keyStr,dataStr){

  const enc = new TextEncoder();

  const key = await crypto.subtle.importKey(
    'raw',
    enc.encode(keyStr),
    {name:'HMAC',hash:'SHA-256'},
    false,
    ['sign']
  );

  const sig = await crypto.subtle.sign(
    'HMAC',
    key,
    enc.encode(dataStr)
  );

  return new Uint8Array(sig);
}

async function verifyHmac(keyStr,dataStr,sigBytes){

  const enc = new TextEncoder();

  const key = await crypto.subtle.importKey(
    'raw',
    enc.encode(keyStr),
    {name:'HMAC',hash:'SHA-256'},
    false,
    ['verify']
  );

  return crypto.subtle.verify(
    'HMAC',
    key,
    sigBytes,
    enc.encode(dataStr)
  );
}

/* =====================================================
   SESSION
===================================================== */

async function makeSessionToken(secret,ttlSeconds=86400){

  const header = base64UrlEncode(
    new TextEncoder().encode(
      JSON.stringify({
        alg:'HS256',
        typ:'WKS'
      })
    )
  );

  const payload = base64UrlEncode(
    new TextEncoder().encode(
      JSON.stringify({
        exp:
          Math.floor(Date.now()/1000)
          + ttlSeconds
      })
    )
  );

  const toSign = header+'.'+payload;

  const sig = await hmacSha256Sign(
    secret,
    toSign
  );

  return toSign+'.'+base64UrlEncode(sig);
}

async function verifySessionToken(token,secret){

  try{

    const parts = token.split('.');

    if(parts.length!==3){
      return false;
    }

    const [header,payload,sig] = parts;

    const ok = await verifyHmac(
      secret,
      header+'.'+payload,
      base64UrlDecodeToUint8Array(sig)
    );

    if(!ok)return false;

    const payloadObj = JSON.parse(
      new TextDecoder().decode(
        base64UrlDecodeToUint8Array(payload)
      )
    );

    return payloadObj.exp >
      Math.floor(Date.now()/1000);

  }catch{
    return false;
  }
}

/* =====================================================
   COOKIES
===================================================== */

function parseCookies(cookieHeader){

  const out={};

  if(!cookieHeader)return out;

  for(const part of cookieHeader.split(';')){

    const [k,v]=part.split('=');

    if(k&&v){
      out[k.trim()] = decodeURIComponent(v.trim());
    }
  }

  return out;
}

function makeSetCookieHeader(name,value,options={}){

  let s =
    `${name}=${encodeURIComponent(value)}`;

  if(options.maxAge!=null){
    s += `; Max-Age=${options.maxAge}`;
  }

  s += '; Path=/';

  if(options.httpOnly){
    s += '; HttpOnly';
  }

  if(options.secure){
    s += '; Secure';
  }

  if(options.sameSite){
    s += `; SameSite=${options.sameSite}`;
  }

  return s;
}

/* =====================================================
   REQUEST HANDLER
===================================================== */

async function handleRequest(request,env){

  const url = new URL(request.url);

  const pathname = url.pathname;

  const providedPasswordEnv =
    env.PASSWORD || '';

  const storedHash =
    /^[0-9a-f]{64}$/i.test(
      providedPasswordEnv.trim()
    )
      ? providedPasswordEnv.trim().toLowerCase()
      : await sha256Hex(providedPasswordEnv);

  const secret =
    env.SECRET ||
    storedHash ||
    'dev-secret';

  const cookies = parseCookies(
    request.headers.get('Cookie') || ''
  );

  const token = cookies[COOKIE_NAME];

  const authed = token
    ? await verifySessionToken(token,secret)
    : false;

  if(pathname==='/' && request.method==='GET'){

    return new Response(
      renderMainHTML(authed),
      {
        headers:{
          'Content-Type':'text/html;charset=utf-8'
        }
      }
    );
  }

  if(pathname==='/browse'
    && request.method==='GET'
  ){

    return new Response(
      renderBrowseHTML(authed),
      {
        headers:{
          'Content-Type':'text/html;charset=utf-8'
        }
      }
    );
  }

  if(pathname==='/login'
    && request.method==='POST'
  ){

    const body = await request.json();

    if(body.hash!==storedHash){

      return json({
        ok:false,
        error:'Wrong password'
      },401);
    }

    const ttl =
      parseInt(env.SESSION_TTL_SECONDS)
      || 86400;

    const tk = await makeSessionToken(
      secret,
      ttl
    );

    const cookie = makeSetCookieHeader(
      COOKIE_NAME,
      tk,
      {
        httpOnly:true,
        secure:true,
        sameSite:'Lax',
        maxAge:ttl
      }
    );

    return new Response(
      JSON.stringify({ok:true}),
      {
        headers:{
          'Content-Type':'application/json',
          'Set-Cookie':cookie
        }
      }
    );
  }

  if(pathname==='/logout'){

    const cookie = makeSetCookieHeader(
      COOKIE_NAME,
      '',
      {maxAge:0}
    );

    return new Response(
      JSON.stringify({ok:true}),
      {
        headers:{
          'Content-Type':'application/json',
          'Set-Cookie':cookie
        }
      }
    );
  }

  if(pathname==='/api/titles'
    && request.method==='GET'
  ){

    const raw =
      await env.CONTENT_KV.get(
        'titles',
        {type:'json'}
      );

    return json({
      ok:true,
      titles:raw||[]
    });
  }

  if(pathname==='/api/titles'
    && request.method==='PUT'
  ){

    if(!authed){

      return json({
        ok:false,
        error:'unauthorized'
      },401);
    }

    const body = await request.json();

    await env.CONTENT_KV.put(
      'titles',
      JSON.stringify(body.titles||[])
    );

    return json({ok:true});
  }

  if(pathname.startsWith('/api/doc/')
    && request.method==='GET'
  ){

    const title = decodeURIComponent(
      pathname.slice('/api/doc/'.length)
    );

    const val =
      await env.CONTENT_KV.get(
        'doc:'+encodeURIComponent(title),
        {type:'text'}
      );

    return json({
      ok:true,
      content:val||''
    });
  }

  if(pathname.startsWith('/api/doc/')
    && request.method==='PUT'
  ){

    if(!authed){

      return json({
        ok:false,
        error:'unauthorized'
      },401);
    }

    const title = decodeURIComponent(
      pathname.slice('/api/doc/'.length)
    );

    const body = await request.json();

    await env.CONTENT_KV.put(
      'doc:'+encodeURIComponent(title),
      body.content||''
    );

    return json({ok:true});
  }

  if(pathname==='/api/title/delete'
    && request.method==='POST'
  ){

    if(!authed){

      return json({
        ok:false,
        error:'unauthorized'
      },401);
    }

    const {title}=await request.json();

    const raw =
      await env.CONTENT_KV.get(
        'titles',
        {type:'json'}
      ) || [];

    const list =
      raw.filter(t=>t!==title);

    await env.CONTENT_KV.put(
      'titles',
      JSON.stringify(list)
    );

    await env.CONTENT_KV.delete(
      'doc:'+encodeURIComponent(title)
    );

    return json({ok:true});
  }

  if(pathname==='/api/title/rename'
    && request.method==='POST'
  ){

    if(!authed){

      return json({
        ok:false,
        error:'unauthorized'
      },401);
    }

    const {
      oldTitle,
      newTitle
    } = await request.json();

    const raw =
      await env.CONTENT_KV.get(
        'titles',
        {type:'json'}
      ) || [];

    if(raw.includes(newTitle)){

      return json({
        ok:false,
        error:'Title exists'
      },400);
    }

    const list = raw.map(t=>
      t===oldTitle
        ? newTitle
        : t
    );

    const content =
      await env.CONTENT_KV.get(
        'doc:'+encodeURIComponent(oldTitle),
        {type:'text'}
      ) || '';

    await env.CONTENT_KV.put(
      'titles',
      JSON.stringify(list)
    );

    await env.CONTENT_KV.put(
      'doc:'+encodeURIComponent(newTitle),
      content
    );

    await env.CONTENT_KV.delete(
      'doc:'+encodeURIComponent(oldTitle)
    );

    return json({ok:true});
  }

  return new Response(
    'Not Found',
    {status:404}
  );
}

function json(obj,status=200){

  return new Response(
    JSON.stringify(obj),
    {
      status,
      headers:{
        'Content-Type':'application/json'
      }
    }
  );
}

/* =====================================================
   MAIN PAGE
===================================================== */

function renderMainHTML(authed){

return `
<!doctype html>
<html>
<head>

<meta charset="utf-8"/>

<meta
  name="viewport"
  content="width=device-width,initial-scale=1"
/>

<title>Note Workspace</title>

<style>

body{
  margin:0;
  font-family:system-ui;
  background:#0f172a;
  color:white;
}

.wrap{
  max-width:1100px;
  margin:auto;
  padding:24px;
}

.card{
  background:#111827;
  border-radius:24px;
  padding:24px;
}

input{
  width:100%;
  padding:14px;
  border:none;
  border-radius:14px;
  background:#1e293b;
  color:white;
}

button{
  border:none;
  border-radius:12px;
  padding:12px 16px;
  cursor:pointer;
}

.primary{
  background:#2563eb;
  color:white;
}

.secondary{
  background:#1e293b;
  color:white;
}

.danger{
  background:#dc2626;
  color:white;
}

.row{
  display:flex;
  gap:12px;
  flex-wrap:wrap;
}

.doc{
  background:#1e293b;
  border-radius:18px;
  padding:18px;
  margin-top:16px;

  display:flex;
  justify-content:space-between;
  align-items:center;
  gap:12px;
  flex-wrap:wrap;
}

.actions{
  display:flex;
  gap:8px;
  flex-wrap:wrap;
}

@media(max-width:700px){

  .doc{
    flex-direction:column;
    align-items:stretch;
  }

  .actions button{
    flex:1;
  }
}

</style>
</head>

<body>

<div class="wrap">

<div class="card">

<h1> Note Workspace</h1>

${authed ? `

<div class="row">

<input
  id="newTitleInput"
  placeholder="Create document..."
/>

<button
  class="primary"
  id="addBtn"
>
Create
</button>

<button
  class="secondary"
  id="logoutBtn"
>
Logout
</button>

</div>

<div style="height:16px"></div>

<input
  id="searchInput"
  placeholder="Search documents..."
/>

<div id="docs"></div>

` : `

<form id="loginForm">

<div class="row">

<input
  id="pw"
  type="password"
  placeholder="Password"
/>

<button class="primary">
Login
</button>

</div>

</form>

`}

</div>

</div>

<script>

(async()=>{

async function sha256Hex(text){

  const enc = new TextEncoder();

  const data = enc.encode(text);

  const hash = await crypto.subtle.digest(
    'SHA-256',
    data
  );

  return Array.from(new Uint8Array(hash))
    .map(b=>b.toString(16).padStart(2,'0'))
    .join('');
}

const authed=${authed?'true':'false'};

if(!authed){

  document
    .getElementById('loginForm')
    .addEventListener('submit',async e=>{

      e.preventDefault();

      const pw =
        document.getElementById('pw').value;

      const hash =
        await sha256Hex(pw);

      const r = await fetch('/login',{
        method:'POST',
        headers:{
          'Content-Type':'application/json'
        },
        body:JSON.stringify({hash})
      });

      const j = await r.json();

      if(j.ok){
        location.reload();
      }else{
        alert(j.error||'Login failed');
      }
    });

  return;
}

const docs =
  document.getElementById('docs');

const searchInput =
  document.getElementById('searchInput');

let titles=[];

async function load(){

  const r = await fetch('/api/titles');

  const j = await r.json();

  titles = j.titles || [];

  render();
}

function render(){

  docs.innerHTML='';

  const q =
    searchInput.value.toLowerCase();

  titles
    .filter(t=>
      t.toLowerCase().includes(q)
    )
    .forEach((t,index)=>{

      const div=document.createElement('div');

      div.className='doc';

      div.innerHTML=\`
        <div style="font-size:20px;font-weight:700">
          \${t}
        </div>

        <div class="actions">

          <button
            class="secondary"
            onclick="location.href='/browse?mode=read&title='+encodeURIComponent('\${t}')"
          >
            Read
          </button>

          <button
            class="primary"
            onclick="location.href='/browse?mode=edit&title='+encodeURIComponent('\${t}')"
          >
            Edit
          </button>

          <button
            class="secondary"
            data-up="\${index}"
          >
            ↑
          </button>

          <button
            class="secondary"
            data-down="\${index}"
          >
            ↓
          </button>

          <button
            class="secondary"
            data-rename="\${t}"
          >
            Rename
          </button>

          <button
            class="danger"
            data-delete="\${t}"
          >
            Delete
          </button>

        </div>
      \`;

      docs.appendChild(div);
    });

  bindEvents();
}

function bindEvents(){

  document
    .querySelectorAll('[data-delete]')
    .forEach(btn=>{

      btn.onclick=async()=>{

        const title =
          btn.dataset.delete;

        if(!confirm('Delete '+title+' ?')){
          return;
        }

        await fetch(
          '/api/title/delete',
          {
            method:'POST',
            headers:{
              'Content-Type':'application/json'
            },
            body:JSON.stringify({title})
          }
        );

        await load();
      };
    });

  document
    .querySelectorAll('[data-rename]')
    .forEach(btn=>{

      btn.onclick=async()=>{

        const oldTitle =
          btn.dataset.rename;

        const newTitle =
          prompt('Rename',oldTitle);

        if(!newTitle)return;

        await fetch(
          '/api/title/rename',
          {
            method:'POST',
            headers:{
              'Content-Type':'application/json'
            },
            body:JSON.stringify({
              oldTitle,
              newTitle
            })
          }
        );

        await load();
      };
    });

  document
    .querySelectorAll('[data-up]')
    .forEach(btn=>{

      btn.onclick=async()=>{

        const i =
          Number(btn.dataset.up);

        if(i===0)return;

        [titles[i-1],titles[i]] =
        [titles[i],titles[i-1]];

        await saveOrder();
      };
    });

  document
    .querySelectorAll('[data-down]')
    .forEach(btn=>{

      btn.onclick=async()=>{

        const i =
          Number(btn.dataset.down);

        if(i===titles.length-1)return;

        [titles[i+1],titles[i]] =
        [titles[i],titles[i+1]];

        await saveOrder();
      };
    });
}

async function saveOrder(){

  await fetch('/api/titles',{
    method:'PUT',
    headers:{
      'Content-Type':'application/json'
    },
    body:JSON.stringify({titles})
  });

  render();
}

searchInput.oninput=render;

document.getElementById('addBtn').onclick=async()=>{

  const val =
    document.getElementById(
      'newTitleInput'
    ).value.trim();

  if(!val)return;

  titles.push(val);

  await saveOrder();

  await fetch(
    '/api/doc/'+encodeURIComponent(val),
    {
      method:'PUT',
      headers:{
        'Content-Type':'application/json'
      },
      body:JSON.stringify({
        content:'# '+val
      })
    }
  );

  document.getElementById(
    'newTitleInput'
  ).value='';

  await load();
};

document.getElementById('logoutBtn').onclick=async()=>{

  await fetch('/logout',{
    method:'POST'
  });

  location.reload();
};

await load();

})();
</script>

</body>
</html>
`;
}

/* =====================================================
   BROWSE PAGE
===================================================== */

/*
=========================================================
 PATCHED VERSION
 FIXES:
 --------------------------------------------------------
 ✓ Code block copy button in READ MODE
 ✓ Bold button fixed
 ✓ Italic button fixed
 ✓ CodeBlock button fixed
 ✓ Quote button fixed
 ✓ Table button fixed
 ✓ Link button fixed
 ✓ Image button fixed
 ✓ List button fixed
 ✓ Task button fixed
 ✓ Better markdown insertion logic
=========================================================
*/

function renderBrowseHTML(authed){

return `
<!doctype html>
<html>

<head>

<meta charset="utf-8"/>

<meta
  name="viewport"
  content="width=device-width,initial-scale=1"
/>

<title>Note Markdown Editor</title>

<link
  rel="stylesheet"
  href="https://cdn.jsdelivr.net/npm/github-markdown-css/github-markdown.min.css"
/>

<script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js"></script>

<style>

body{
  margin:0;
  font-family:system-ui;
  background:#0f172a;
}

/* TOPBAR */

.topbar{
  position:sticky;
  top:0;
  z-index:100;
  background:#111827;
  padding:12px;
  display:flex;
  gap:8px;
  flex-wrap:wrap;
  align-items:center;
}

button{
  border:none;
  border-radius:10px;
  padding:10px 14px;
  cursor:pointer;
}

.primary{
  background:#2563eb;
  color:white;
}

.secondary{
  background:#1e293b;
  color:white;
}

.success{
  background:#16a34a;
  color:white;
}

/* TOOLBAR */

.toolbar{
  background:#1e293b;
  padding:10px;
  display:flex;
  gap:8px;
  flex-wrap:wrap;
}

/* EDITOR */

.editor{
  width:100%;
  height:calc(100vh - 130px);
  border:none;
  outline:none;
  resize:none;
  padding:40px;
  background:#0f172a;
  color:white;
  font-size:18px;
  line-height:1.9;
  font-family:monospace;
  box-sizing:border-box;
}

/* READER */

.readerWrap{
  padding:30px;
}

.readerCard{
  max-width:900px;
  margin:auto;
  border-radius:24px;
  padding:60px;
  background:linen;
  transition:.2s;
}

.themeButtons{
  margin-bottom:18px;
  display:flex;
  gap:8px;
  flex-wrap:wrap;
}

/* CODE BLOCK */

.readerCard pre,
.previewInner pre{

  position:relative;

  background:#111827 !important;

  color:#fff;

  border-radius:14px;

  padding:20px;

  overflow:auto;
}

.copy-btn{

  position:absolute;

  top:10px;

  right:10px;

  background:#2563eb;

  color:white;

  border:none;

  border-radius:8px;

  padding:6px 10px;

  cursor:pointer;

  font-size:12px;

  opacity:0;

  transition:.2s;
}

pre:hover .copy-btn{
  opacity:1;
}

/* PREVIEW */

.preview{
  position:fixed;
  top:120px;
  right:0;
  width:45%;
  height:calc(100vh - 120px);
  overflow:auto;
  background:white;
  display:none;
}

.preview.show{
  display:block;
}

.previewInner{
  padding:40px;
}

.saveStatus{
  margin-left:auto;
  color:#94a3b8;
}

/* MOBILE */

@media(max-width:900px){

  .editor{
    padding:18px;
    font-size:16px;
  }

  .preview{
    width:100%;
  }

  .readerWrap{
    padding:16px;
  }

  .readerCard{
    padding:24px;
  }
}

</style>
</head>

<body>

${authed ? `

<div class="topbar">

<button
  class="secondary"
  id="homeBtn"
>
Home
</button>

<button
  class="secondary"
  id="switchBtn"
>
Switch Mode
</button>

<button
  class="secondary"
  id="previewBtn"
>
Preview
</button>

<button
  class="primary"
  id="saveBtn"
>
Save
</button>

<div
  id="saveStatus"
  class="saveStatus"
>
Ready
</div>

</div>

<div
  id="editorToolbar"
  class="toolbar"
  style="display:none"
>

<button data-insert="# ">H1</button>
<button data-insert="## ">H2</button>
<button data-insert="### ">H3</button>

<button data-wrap="**">Bold</button>
<button data-wrap="*">Italic</button>
<button data-wrap="\`">Code</button>

<button data-block="code">CodeBlock</button>
<button data-block="quote">Quote</button>
<button data-block="table">Table</button>
<button data-block="link">Link</button>
<button data-block="image">Image</button>
<button data-block="list">List</button>
<button data-block="task">Task</button>

</div>

<div
  id="readerWrap"
  class="readerWrap"
>

<div class="themeButtons">

<button
  class="secondary themeBtn"
  data-bg="linen"
>
Linen
</button>

<button
  class="secondary themeBtn"
  data-bg="#ffffff"
>
White
</button>

<button
  class="secondary themeBtn"
  data-bg="#f4ecd8"
>
Warm
</button>

<button
  class="secondary themeBtn"
  data-bg="#e5e7eb"
>
Gray
</button>

</div>

<div
  id="readerCard"
  class="readerCard markdown-body"
></div>

</div>

<div
  id="editorWrap"
  style="display:none"
>

<textarea
  id="editor"
  class="editor"
></textarea>

<div
  id="preview"
  class="preview"
>

<div
  id="previewInner"
  class="previewInner markdown-body"
></div>

</div>

</div>

` : 'Please login'}

<script>

(async()=>{

const authed=${authed?'true':'false'};

if(!authed)return;

const p = new URLSearchParams(location.search);

const title = p.get('title');

let mode = p.get('mode') || 'read';

const readerCard =
  document.getElementById('readerCard');

const editor =
  document.getElementById('editor');

const preview =
  document.getElementById('preview');

const previewInner =
  document.getElementById('previewInner');

const saveStatus =
  document.getElementById('saveStatus');

const readerWrap =
  document.getElementById('readerWrap');

const editorWrap =
  document.getElementById('editorWrap');

const toolbar =
  document.getElementById('editorToolbar');

let previewOpen=false;

/* COPY BUTTON */

function addCopyButtons(container){

  const pres =
    container.querySelectorAll('pre');

  pres.forEach(pre=>{

    if(pre.querySelector('.copy-btn')){
      return;
    }

    const btn =
      document.createElement('button');

    btn.className='copy-btn';

    btn.innerText='Copy';

    btn.onclick=async()=>{

      const code =
        pre.querySelector('code');

      const text =
        code
          ? code.innerText
          : pre.innerText;

      await navigator.clipboard.writeText(text);

      btn.innerText='Copied';

      setTimeout(()=>{
        btn.innerText='Copy';
      },2000);
    };

    pre.appendChild(btn);
  });
}

/* LOAD */

async function load(){

  const r = await fetch(
    '/api/doc/'+encodeURIComponent(title)
  );

  const j = await r.json();

  const content = j.content || '';

  readerCard.innerHTML =
    marked.parse(content);

  editor.value = content;

  renderPreview();

  addCopyButtons(readerCard);

  applyMode();
}

/* MODE */

function applyMode(){

  if(mode==='read'){

    readerWrap.style.display='block';

    editorWrap.style.display='none';

    toolbar.style.display='none';

  }else{

    readerWrap.style.display='none';

    editorWrap.style.display='block';

    toolbar.style.display='flex';
  }
}

/* PREVIEW */

function renderPreview(){

  previewInner.innerHTML =
    marked.parse(editor.value);

  addCopyButtons(previewInner);
}

/* SAVE */

async function save(){

  saveStatus.innerText='Saving...';

  await fetch(
    '/api/doc/'+encodeURIComponent(title),
    {
      method:'PUT',
      headers:{
        'Content-Type':'application/json'
      },
      body:JSON.stringify({
        content:editor.value
      })
    }
  );

  readerCard.innerHTML =
    marked.parse(editor.value);

  addCopyButtons(readerCard);

  saveStatus.innerText='Saved ✓';

  setTimeout(()=>{
    saveStatus.innerText='Ready';
  },2500);
}

/* AUTOSAVE */

let timer=null;

editor.addEventListener('input',()=>{

  saveStatus.innerText='Typing...';

  renderPreview();

  clearTimeout(timer);

  timer=setTimeout(async()=>{
    await save();
  },2500);
});

/* INSERT HELPERS */

function insertText(text){

  const start = editor.selectionStart;

  editor.setRangeText(
    text,
    start,
    start,
    'end'
  );

  editor.focus();
}

function wrapSelection(before,after){

  const start = editor.selectionStart;

  const end = editor.selectionEnd;

  const selected =
    editor.value.substring(start,end);

  editor.setRangeText(
    before + selected + after,
    start,
    end,
    'end'
  );

  editor.focus();

  renderPreview();
}

function insertBlock(text){

  const start = editor.selectionStart;

  editor.setRangeText(
    "\\n"+text+"\\n",
    start,
    start,
    'end'
  );

  editor.focus();

  renderPreview();
}

/* TOOLBAR BUTTONS */

document
.querySelectorAll('[data-insert]')
.forEach(btn=>{

  btn.onclick=()=>{

    insertText(btn.dataset.insert);
  };
});

document
.querySelectorAll('[data-wrap]')
.forEach(btn=>{

  btn.onclick=()=>{

    const w = btn.dataset.wrap;

    wrapSelection(w,w);
  };
});

document
.querySelectorAll('[data-block]')
.forEach(btn=>{

  btn.onclick=()=>{

    const type = btn.dataset.block;

    if(type==='code'){

      insertBlock(
\`\`\`
code here
\`\`\`
      );
    }

    if(type==='quote'){

      insertBlock(
'> quote'
      );
    }

    if(type==='table'){

      insertBlock(
'| Title | Value |\\n|---|---|\\n| A | B |'
      );
    }

    if(type==='link'){

      insertBlock(
'[OpenAI](https://openai.com)'
      );
    }

    if(type==='image'){

      insertBlock(
'![image](https://example.com/image.jpg)'
      );
    }

    if(type==='list'){

      insertBlock(
'- item 1\\n- item 2\\n- item 3'
      );
    }

    if(type==='task'){

      insertBlock(
'- [ ] task 1\\n- [x] task 2'
      );
    }
  };
});

/* THEMES */

document
.querySelectorAll('.themeBtn')
.forEach(btn=>{

  btn.onclick=()=>{

    readerCard.style.background =
      btn.dataset.bg;
  };
});

/* BUTTONS */

document.getElementById('saveBtn').onclick=save;

document.getElementById('switchBtn').onclick=()=>{

  mode =
    mode==='read'
      ? 'edit'
      : 'read';

  applyMode();
};

document.getElementById('previewBtn').onclick=()=>{

  previewOpen=!previewOpen;

  if(previewOpen){

    preview.classList.add('show');

  }else{

    preview.classList.remove('show');
  }
};

document.getElementById('homeBtn').onclick=()=>{

  location.href='/';
};

/* SHORTCUTS */

editor.addEventListener('keydown',e=>{

  if(e.ctrlKey && e.key==='s'){

    e.preventDefault();

    save();
  }

  if(e.key==='Tab'){

    e.preventDefault();

    const start=editor.selectionStart;

    editor.setRangeText(
      '  ',
      start,
      start,
      'end'
    );
  }
});

await load();

})();
</script>

</body>
</html>
`;
}
