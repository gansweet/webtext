// Cloudflare Worker (module)
// 升级版：
// 1. 前端 HASH 登录，防止明文密码传输
// 2. 引入 marked.js，实现 Markdown 预览和编辑
//
// KV 名称: CONTENT_KV
// 环境变量: PASSWORD, SESSION_TTL_SECONDS, SECRET

const COOKIE_NAME = 'wksess';

export default {
  async fetch(request, env) {
    return handleRequest(request, env);
  },
};

/* ======== 工具函数 (服务器端) ======== */
async function sha256Hex(text) {
  const enc = new TextEncoder();
  const data = enc.encode(text);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2,'0')).join('');
}
function base64UrlEncode(bytes) {
  const b64 = btoa(String.fromCharCode(...new Uint8Array(bytes)));
  return b64.replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
}
function base64UrlDecodeToUint8Array(str) {
  str = str.replace(/-/g,'+').replace(/_/g,'/');
  while (str.length % 4) str += '=';
  const bin = atob(str);
  const arr = new Uint8Array(bin.length);
  for (let i=0;i<bin.length;i++) arr[i]=bin.charCodeAt(i);
  return arr;
}
async function hmacSha256Sign(keyStr, dataStr) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', enc.encode(keyStr), {name:'HMAC', hash:'SHA-256'}, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(dataStr));
  return new Uint8Array(sig);
}
async function verifyHmac(keyStr, dataStr, sigBytes) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', enc.encode(keyStr), {name:'HMAC', hash:'SHA-256'}, false, ['verify']);
  return crypto.subtle.verify('HMAC', key, sigBytes, enc.encode(dataStr));
}

/* ======== Session ======== */
async function makeSessionToken(secret, ttlSeconds = 86400) {
  const header = base64UrlEncode(new TextEncoder().encode(JSON.stringify({alg:'HS256',typ:'WKS'})));
  const payloadObj = { exp: Math.floor(Date.now()/1000) + ttlSeconds };
  const payload = base64UrlEncode(new TextEncoder().encode(JSON.stringify(payloadObj)));
  const toSign = header + '.' + payload;
  const sig = await hmacSha256Sign(secret, toSign);
  const sigEnc = base64UrlEncode(sig);
  return `${toSign}.${sigEnc}`;
}
async function verifySessionToken(token, secret) {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return false;
    const [headerB64, payloadB64, sigB64] = parts;
    const toVerify = headerB64 + '.' + payloadB64;
    const sigBytes = base64UrlDecodeToUint8Array(sigB64);
    const ok = await verifyHmac(secret, toVerify, sigBytes);
    if (!ok) return false;
    const payloadJson = new TextDecoder().decode(base64UrlDecodeToUint8Array(payloadB64));
    const payload = JSON.parse(payloadJson);
    return payload.exp && payload.exp > Math.floor(Date.now()/1000);
  } catch { return false; }
}

/* ======== Cookie ======== */
function parseCookies(cookieHeader) {
  const out = {};
  if (!cookieHeader) return out;
  for (const part of cookieHeader.split(';')) {
    const [k,v] = part.split('=');
    if (k && v) out[k.trim()] = decodeURIComponent(v.trim());
  }
  return out;
}
function makeSetCookieHeader(name, value, options={}) {
  let s = `${name}=${encodeURIComponent(value)}`;
  if (options.maxAge != null) s += `; Max-Age=${options.maxAge}`;
  if (options.path) s += `; Path=${options.path}`; else s += `; Path=/`;
  if (options.httpOnly) s += '; HttpOnly';
  if (options.secure) s += '; Secure';
  if (options.sameSite) s += `; SameSite=${options.sameSite}`;
  return s;
}

/* ======== 主处理 ======== */
async function handleRequest(request, env) {
  const url = new URL(request.url);
  const pathname = url.pathname;
  const providedPasswordEnv = env.PASSWORD || '';
  // 优先使用已有的 64 位 HASH，否则计算明文的 HASH
  const storedHash = /^[0-9a-f]{64}$/i.test(providedPasswordEnv.trim())
    ? providedPasswordEnv.trim().toLowerCase()
    : await sha256Hex(providedPasswordEnv);
  const secret = env.SECRET || storedHash || 'dev-secret';
  const cookies = parseCookies(request.headers.get('Cookie') || '');
  const token = cookies[COOKIE_NAME];
  const authed = token ? await verifySessionToken(token, secret) : false;

  if (pathname === '/' && request.method === 'GET') {
    return new Response(renderMainHTML(authed), {headers:{'Content-Type':'text/html; charset=utf-8'}});
  }

  if (pathname === '/browse' && request.method === 'GET') {
    return new Response(renderBrowseHTML(authed), {headers:{'Content-Type':'text/html; charset=utf-8'}});
  }

  if (pathname === '/login' && request.method === 'POST') {
    const body = await request.json();
    // ✅ **[升级点 1]**：期望接收 'hash' 而不是 'password'
    const incomingHash = String(body.hash || '');
    if (!storedHash) return json({ok:false,error:'PASSWORD未配置'},500);
    
    // ✅ 直接对比 HASH 值
    if (incomingHash !== storedHash) return json({ok:false,error:'密码错误'},401);

    // 登录成功，创建 session
    const ttl = parseInt(env.SESSION_TTL_SECONDS) || 86400;
    const tk = await makeSessionToken(secret, ttl);
    const cookie = makeSetCookieHeader(COOKIE_NAME, tk, {httpOnly:true,secure:true,sameSite:'Lax',maxAge:ttl});
    return new Response(JSON.stringify({ok:true}), {status:200,headers:{'Content-Type':'application/json','Set-Cookie':cookie}});
  }

  if (pathname === '/logout' && request.method === 'POST') {
    const cookie = makeSetCookieHeader(COOKIE_NAME, '', {maxAge:0});
    return new Response(JSON.stringify({ok:true}), {status:200,headers:{'Content-Type':'application/json','Set-Cookie':cookie}});
  }

  // --- [API 路由，保持不变] ---

  // 多标签 API
  if (pathname === '/api/titles' && request.method === 'GET') {
    const raw = await env.CONTENT_KV.get('titles', {type:'json'});
    return json({ok:true,titles:raw||[]});
  }
  if (pathname === '/api/titles' && request.method === 'PUT') {
    if (!authed) return json({ok:false,error:'unauthorized'},401);
    const body = await request.json();
    const list = Array.from(new Set((body.titles||[]).map(t=>String(t).trim()).filter(Boolean)));
    await env.CONTENT_KV.put('titles', JSON.stringify(list));
    return json({ok:true});
  }

  if (pathname.startsWith('/api/doc/') && request.method === 'GET') {
    const title = decodeURIComponent(pathname.slice('/api/doc/'.length));
    const val = await env.CONTENT_KV.get(`doc:${encodeURIComponent(title)}`, {type:'text'});
    return json({ok:true,content:val||''});
  }
  if (pathname.startsWith('/api/doc/') && request.method === 'PUT') {
    if (!authed) return json({ok:false,error:'unauthorized'},401);
    const title = decodeURIComponent(pathname.slice('/api/doc/'.length));
    const body = await request.json();
    await env.CONTENT_KV.put(`doc:${encodeURIComponent(title)}`, body.content||'');
    return json({ok:true});
  }

  // 新增删除标题接口
  if (pathname.startsWith('/api/title/delete') && request.method === 'POST') {
    if (!authed) return json({ok:false,error:'unauthorized'},401);
    const {title} = await request.json();
    if (!title) return json({ok:false,error:'missing title'},400);
    const raw = await env.CONTENT_KV.get('titles', {type:'json'}) || [];
    const list = raw.filter(t=>t!==title);
    await env.CONTENT_KV.put('titles', JSON.stringify(list));
    await env.CONTENT_KV.delete(`doc:${encodeURIComponent(title)}`);
    return json({ok:true});
  }

  if (pathname.startsWith('/api/title/rename') && request.method === 'POST') {
    if (!authed) return json({ok:false,error:'unauthorized'},401);
    const {oldTitle,newTitle} = await request.json();
    if (!oldTitle || !newTitle) return json({ok:false,error:'missing title'},400);
    const raw = await env.CONTENT_KV.get('titles', {type:'json'}) || [];
    if (raw.includes(newTitle)) return json({ok:false,error:'new title exists'},400);
    const list = raw.map(t=>t===oldTitle?newTitle:t);
    const content = await env.CONTENT_KV.get(`doc:${encodeURIComponent(oldTitle)}`, {type:'text'}) || '';
    await env.CONTENT_KV.put('titles', JSON.stringify(list));
    await env.CONTENT_KV.put(`doc:${encodeURIComponent(newTitle)}`, content);
    await env.CONTENT_KV.delete(`doc:${encodeURIComponent(oldTitle)}`);
    return json({ok:true});
  }

  return new Response('Not found', {status:404});
}

function json(obj, status=200) {
  return new Response(JSON.stringify(obj), {status,headers:{'Content-Type':'application/json'}});
}

/* ======== 页面模板：主界面 ======== */
function renderMainHTML(authed) {
  return `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"/>
<title>多标签信息管理</title>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<style>
body{font-family:system-ui;margin:0;padding:24px;background:#f7f8fa;}
.container{max-width:900px;margin:auto;background:#fff;padding:24px;border-radius:12px;box-shadow:0 6px 18px rgba(0,0,0,0.06);}
h1{font-size:22px;margin-bottom:12px;}
button{padding:8px 14px;border-radius:8px;border:1px solid #ddd;background:#fff;cursor:pointer;}
button.primary{background:#0b61ff;color:#fff;border:none;}
.tag{display:flex;align-items:center;gap:8px;background:#eef;padding:6px 10px;border-radius:8px;margin:4px;}
.small{font-size:13px;color:#666;}
.tag span{flex:1;}
</style></head><body>
<div class="container">
<h1>信息查看</h1>
${authed?`
<div style="display:flex;gap:8px;align-items:center">
  <input id="newTitleInput" type="text" placeholder="新标题..." style="flex:1;padding:8px;border-radius:8px;border:1px solid #ccc"/>
  <button id="addBtn" class="primary">创建</button>
  <button id="logoutBtn">退出登录</button>
</div>
<div id="tags" style="margin-top:12px;"></div>
`:`<form id="loginForm"><input id="pw" type="password" placeholder="输入密码" style="padding:8px;border-radius:8px;border:1px solid #ccc;width:60%"/>
<button class="primary">登录</button></form>`}
</div>
<script>
(async()=>{

  // ✅ **[升级点 2]**：在客户端定义 sha256Hex 函数，用于登录时哈希密码
  async function sha256Hex(text) {
    const enc = new TextEncoder();
    const data = enc.encode(text);
    const hash = await crypto.subtle.digest('SHA-256', data);
    return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2,'0')).join('');
  }

  const authed=${authed?'true':'false'};
  if(!authed){
    document.getElementById('loginForm').addEventListener('submit',async e=>{
      e.preventDefault();
      const pw = document.getElementById('pw').value;
      if (!pw) return;

      // ✅ **[升级点 3]**：在前端哈希密码后再发送
      const hash = await sha256Hex(pw);

      try {
        const r = await fetch('/login',{
          method:'POST',
          headers:{'Content-Type':'application/json'},
          body:JSON.stringify({ hash: hash }) // 发送 HASH
        });
        const j = await r.json();
        if(j.ok) location.reload();
        else alert(j.error || '登录错误');
      } catch(err) {
        alert('登录请求失败: ' + err.message);
      }
    });
    return;
  }

  // --- [已登录的逻辑，保持不变] ---

  const tags=document.getElementById('tags');

  async function loadTitles(){
    const r=await fetch('/api/titles');const j=await r.json();
    tags.innerHTML='';
    (j.titles||[]).forEach(t=>{
      const div=document.createElement('div');div.className='tag';
      div.innerHTML='<span>'+t+'</span> \
      <button class="viewBtn">查看</button> \
      <button class="renameBtn">修改</button> \
      <button class="delBtn">删除</button>';
      div.querySelector('.viewBtn').onclick=()=>location.href='/browse?title='+encodeURIComponent(t);
      div.querySelector('.delBtn').onclick=async()=>{
        if(confirm('确认删除标题：'+t+'?')){
          await fetch('/api/title/delete',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({title:t})});
          await loadTitles();
        }
      };
      div.querySelector('.renameBtn').onclick=async()=>{
        const newT=prompt('输入新标题名称',t);
        if(!newT || newT===t)return;
        const res=await fetch('/api/title/rename',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({oldTitle:t,newTitle:newT})});
        const data=await res.json();
        if(data.ok) await loadTitles(); else alert(data.error||'修改失败');
      };
      tags.appendChild(div);
    });
  }

  document.getElementById('addBtn').onclick=async()=>{
    const val=document.getElementById('newTitleInput').value.trim();
    if(!val)return;
    const r=await fetch('/api/titles');const j=await r.json();const arr=j.titles||[];
    if(arr.includes(val)){alert('标题已存在');return;}
    arr.push(val);
    await fetch('/api/titles',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({titles:arr})});
    await fetch('/api/doc/'+encodeURIComponent(val),{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({content:''})});
    await loadTitles();
  };

  document.getElementById('logoutBtn').onclick=async()=>{await fetch('/logout',{method:'POST'});location.reload();};
  await loadTitles();
})();
</script>
</body></html>`;
}

/* ======== 页面模板：浏览编辑界面 (Markdown 升级) ======== */
function renderBrowseHTML(authed) {
  return `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"/>
<title>内容浏览</title>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js"></script>
<style>
body{font-family:system-ui;margin:0;padding:24px;background:#f7f8fa;}
.container{max-width:880px;margin:auto;background:#fff;padding:24px;border-radius:12px;box-shadow:0 6px 18px rgba(0,0,0,0.06);}
button{padding:8px 14px;border-radius:8px;border:1px solid #ddd;background:#fff;cursor:pointer;}
button.primary{background:#0b61ff;color:#fff;border:none;}
/* 移除旧的 textarea 样式，它将在 JS 中动态创建 */

/* ✅ **[升级点 5]**：为 Markdown 查看区域 #viewArea 添加样式 */
#viewArea {
  line-height: 1.6;
  min-height: 240px;
  padding: 12px;
  border: 1px solid #eee;
  border-radius: 8px;
  background: #fcfdff;
}
/* Markdown 基础排版 (prose) 样式 */
#viewArea > :first-child { margin-top: 0; }
#viewArea > :last-child { margin-bottom: 0; }
#viewArea h1, #viewArea h2, #viewArea h3, #viewArea h4 { margin-bottom: 0.5em; margin-top: 1.2em; }
#viewArea p { margin: 1em 0; }
#viewArea ul, #viewArea ol { padding-left: 2em; }
#viewArea blockquote { border-left: 4px solid #ddd; padding-left: 1em; margin-left: 0; color: #555; }
#viewArea pre { background: #f4f4f4; padding: 1em; border-radius: 4px; overflow-x: auto; }
#viewArea code { font-family: monospace; background: #eee; padding: 2px 4px; border-radius: 3px; font-size: 0.95em; }
#viewArea pre code { background: none; padding: 0; }
#viewArea table { border-collapse: collapse; width: 100%; margin: 1em 0; }
#viewArea th, #viewArea td { border: 1px solid #ccc; padding: 8px; }
</style></head><body>
<div class="container">
<h1 id="titleBox">加载中...</h1>
${authed?`
<div id="viewArea">加载中…</div>
<div style="margin-top:12px;display:flex;gap:8px;">
  <button id="editBtn">编辑</button>
  <button id="saveBtn" class="primary" disabled>保存</button>
  <button id="backBtn" style="margin-left:auto">返回主页</button>
  <button id="logoutBtn">退出登录</button>
</div>`:`<p>未登录，请返回主页。</p>`}
</div>
<script>
(async()=>{
  const authed=${authed?'true':'false'};
  if(!authed){document.getElementById('titleBox').innerText='请登录';return;}
  const p=new URLSearchParams(location.search);
  const title=p.get('title');
  document.getElementById('titleBox').innerText=title||'';
  
  let view=document.getElementById('viewArea');
  const editBtn=document.getElementById('editBtn');
  const saveBtn=document.getElementById('saveBtn');
  const backBtn=document.getElementById('backBtn');
  const logoutBtn=document.getElementById('logoutBtn');

  let mode='view';
  let textarea=null;
  let autosaveTimer=null;
  let dirty=false;
  let saving=false;
  
  // ✅ **[升级点 6]**：存储原始 Markdown 文本
  let rawContent = '';

  async function load(){
    try{
      const r=await fetch('/api/doc/'+encodeURIComponent(title));
      const j=await r.json();
      
      // ✅ **[升级点 7]**：保存原始文本，并使用 marked 解析为 HTML
      rawContent = j.content || '';
      view.innerHTML = marked.parse(rawContent || '（空内容）');
    }catch(e){
      view.textContent='加载失败';
    }
  }

  async function put(v){
    saving=true;
    try{
      await fetch('/api/doc/'+encodeURIComponent(title),{
        method:'PUT',
        headers:{'Content-Type':'application/json'},
        body:JSON.stringify({content:v})
      });
      dirty=false;
    }catch(e){
      console.error('保存失败',e);
      alert('保存失败：'+(e.message||e));
    }finally{
      saving=false;
    }
  }

  function enterEdit(){
    if(mode==='edit')return;
    mode='edit';
    
    textarea=document.createElement('textarea');
    // ✅ **[升级点 8]**：使用原始 Markdown 文本填充 textarea
    textarea.value = rawContent;
    
    // 设置 textarea 样式 (与旧版保持一致)
    textarea.style.width='100%';
    textarea.style.boxSizing='border-box'; // 确保 padding 不会撑开宽度
    textarea.style.minHeight='240px';
    textarea.style.padding='12px';
    textarea.style.border='1px solid #ccc';
    textarea.style.borderRadius='8px';
    textarea.style.fontFamily='inherit';
    textarea.style.fontSize='14px';
    textarea.style.lineHeight='1.6'; // 改善编辑体验
    
    view.replaceWith(textarea); // 用 textarea 替换 #viewArea 容器

    saveBtn.disabled=false;
    editBtn.disabled=true;
    textarea.focus();

    // 启动 3 分钟自动保存 (逻辑不变)
    if(autosaveTimer) clearInterval(autosaveTimer);
    autosaveTimer=setInterval(async()=>{
      if(!dirty||saving)return;
      console.log('自动保存中...');
      await put(textarea.value);
    },180000);

    textarea.addEventListener('input',()=>dirty=true);
  }

  async function exitEdit(){
    if(mode!=='edit')return;
    clearInterval(autosaveTimer);

    const v = textarea.value;
    await put(v);

    // ✅ **[升级点 9]**：更新
    rawContent = v; // 保存最新的 Markdown 原文

    // 创建新的查看模式 div
    const newView = document.createElement('div');
    newView.id = 'viewArea'; // 确保 CSS 样式能应用上
    
    // ✅ **[升级点 10]**：解析 Markdown 并显示
    newView.innerHTML = marked.parse(rawContent || '（空内容）');
    
    // (旧的动态样式已移除，因为 CSS 会自动处理 #viewArea)

    textarea.replaceWith(newView); // 用新 #viewArea 替换 textarea

    // 更新全局引用，确保再次点击“编辑”可用
    textarea=null;
    view=newView;
    window.view=newView; 

    mode='view';
    saveBtn.disabled=true;
    editBtn.disabled=false;
    alert('保存成功');
  }

  editBtn.onclick=enterEdit;
  saveBtn.onclick=exitEdit;

  backBtn.onclick=()=>location.href='/';
  logoutBtn.onclick=async()=>{await fetch('/logout',{method:'POST'});location.href='/';};

  await load();
})();
</script></body></html>`;
}
