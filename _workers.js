// Cloudflare Worker (module)
const COOKIE_NAME = (typeof SESSION_COOKIE_NAME !== 'undefined') ? SESSION_COOKIE_NAME : 'wksess';
// env bindings: CONTENT_KV, PASSWORD (string)
// optional env: SESSION_TTL_SECONDS
export default {
  async fetch(request, env) {
    return handleRequest(request, env)
  }
}

/* -----------------------
   工具函数：SHA-256 / HMAC / base64 等
   使用 Web Crypto (crypto.subtle)
   -----------------------*/
async function sha256Hex(text) {
  const enc = new TextEncoder();
  const data = enc.encode(text);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return bufferToHex(hash);
}
function bufferToHex(buffer) {
  const bytes = new Uint8Array(buffer);
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}
function hexToArrayBuffer(hex) {
  if (hex.length % 2) throw new Error('Invalid hex');
  const arr = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) arr[i/2] = parseInt(hex.substr(i,2), 16);
  return arr.buffer;
}
function base64UrlEncode(bytes) {
  const b64 = btoa(String.fromCharCode(...new Uint8Array(bytes)));
  return b64.replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/, '');
}
function base64UrlDecodeToUint8Array(str) {
  // pad
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

/* -----------------------
   Session token: 简单的 HMAC-signed payload
   token = base64url(header).base64url(payload).base64url(signature)
   header 固定: {"alg":"HS256","typ":"WKS"}
   payload: {"exp": unix_ts}
   -----------------------*/
async function makeSessionToken(secret, ttlSeconds=86400) {
  const header = base64UrlEncode(new TextEncoder().encode(JSON.stringify({alg:'HS256',typ:'WKS'})));
  const payloadObj = {exp: Math.floor(Date.now()/1000) + ttlSeconds};
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
    const now = Math.floor(Date.now()/1000);
    return payload.exp && payload.exp > now;
  } catch (e) {
    return false;
  }
}

/* -----------------------
   Helpers: cookie parse / set
   -----------------------*/
function parseCookies(cookieHeader) {
  const out = {};
  if (!cookieHeader) return out;
  const parts = cookieHeader.split(';');
  for (const p of parts) {
    const idx = p.indexOf('=');
    if (idx > -1) {
      const key = p.slice(0, idx).trim();
      const val = p.slice(idx+1).trim();
      out[key] = decodeURIComponent(val);
    }
  }
  return out;
}
function makeSetCookieHeader(name, value, options={}) {
  let s = `${name}=${encodeURIComponent(value)}`;
  if (options.maxAge != null) s += `; Max-Age=${options.maxAge}`;
  if (options.domain) s += `; Domain=${options.domain}`;
  if (options.path) s += `; Path=${options.path}`;
  else s += `; Path=/`;
  if (options.httpOnly) s += `; HttpOnly`;
  if (options.secure) s += `; Secure`;
  if (options.sameSite) s += `; SameSite=${options.sameSite}`;
  return s;
}

/* -----------------------
   Main request handler
   -----------------------*/
async function handleRequest(request, env) {
  const url = new URL(request.url);
  const pathname = url.pathname;

  // prepare hashed password from env.PASSWORD
  const providedPasswordEnv = env.PASSWORD || '';
  const storedHash = await (async () => {
    if (!providedPasswordEnv) return null;
    const maybeHex = String(providedPasswordEnv).trim();
    const isHex64 = /^[0-9a-f]{64}$/i.test(maybeHex);
    if (isHex64) return maybeHex.toLowerCase();
    // treat as plaintext -> sha256 hex
    return await sha256Hex(maybeHex);
  })();

  // secret for session signing - if user configured SECRET env use it, else use storedHash (safe enough)
  const secret = env.SECRET || storedHash || 'dev-secret';

  // Routes:
  // GET /  -> serve app page (login or content depending on session)
  // POST /login -> authenticate password, set cookie
  // GET /api/content -> return content JSON
  // PUT /api/content -> save content (requires valid session)
  // POST /logout -> clear cookie
  if (pathname === '/' && request.method === 'GET') {
    // if has valid session cookie -> serve app html (still page includes auth check)
    const cookies = parseCookies(request.headers.get('Cookie') || '');
    const token = cookies[COOKIE_NAME];
    const authed = token ? await verifySessionToken(token, secret) : false;
    return new Response(renderHTML(authed), {
      headers: {'Content-Type': 'text/html; charset=utf-8'}
    });
  }

  if (pathname === '/login' && request.method === 'POST') {
    // Expect JSON body {password: "..."}
    try {
      const body = await request.json();
      const pw = body && body.password ? String(body.password) : '';
      if (!storedHash) return jsonResponse({ok:false, error:'PASSWORD not configured on worker env'}, 500);
      const incomingHash = await sha256Hex(pw);
      if (incomingHash === storedHash) {
        // make token
        const ttl = parseInt(env.SESSION_TTL_SECONDS) || 86400;
        const token = await makeSessionToken(secret, ttl);
        const cookie = makeSetCookieHeader(COOKIE_NAME, token, {
          httpOnly: true,
          secure: true,
          sameSite: 'Lax',
          maxAge: ttl,
          path: '/'
        });
        return new Response(JSON.stringify({ok:true}), {status:200, headers: {'Content-Type':'application/json', 'Set-Cookie': cookie}});
      } else {
        return jsonResponse({ok:false, error:'密码错误'}, 401);
      }
    } catch (e) {
      return jsonResponse({ok:false, error:'bad request'}, 400);
    }
  }

  if (pathname === '/logout' && request.method === 'POST') {
    const cookie = makeSetCookieHeader(COOKIE_NAME, '', {maxAge:0, path:'/'});
    return new Response(JSON.stringify({ok:true}), {status:200, headers: {'Content-Type':'application/json', 'Set-Cookie': cookie}});
  }

  if (pathname === '/api/content' && request.method === 'GET') {
    // read from KV
    try {
      const value = await env.CONTENT_KV.get('document', {type:'text'});
      return jsonResponse({ok:true, content: value || ''});
    } catch (e) {
      return jsonResponse({ok:false, error:'kv read error'}, 500);
    }
  }

  if (pathname === '/api/content' && request.method === 'PUT') {
    // require session
    const cookies = parseCookies(request.headers.get('Cookie') || '');
    const token = cookies[COOKIE_NAME];
    const authed = token ? await verifySessionToken(token, secret) : false;
    if (!authed) return jsonResponse({ok:false, error:'unauthorized'}, 401);
    try {
      const body = await request.json();
      const content = body && typeof body.content === 'string' ? body.content : '';
      // store to KV
      await env.CONTENT_KV.put('document', content);
      return jsonResponse({ok:true});
    } catch (e) {
      return jsonResponse({ok:false, error:'bad request'}, 400);
    }
  }

  // static asset fallback (if any)
  return new Response('Not found', {status:404});
}

function jsonResponse(obj, status=200) {
  return new Response(JSON.stringify(obj), {status, headers: {'Content-Type':'application/json'}});
}

/* -----------------------
   前端 HTML/JS/CSS
   - 页面标题 "信息查看"
   - 登录界面 -> 登录通过后刷新页面（cookie 已设置）
   - 编辑按钮进入编辑模式（textarea），自动保存（debounce）
   - 保存按钮保存并返回浏览模式
   - 内容存储在 KV key 'document'
   -----------------------*/
function renderHTML(authed) {
  return `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<title>信息查看</title>
<style>
  :root{font-family:system-ui,-apple-system,Segoe UI,Roboto,"Helvetica Neue",Arial;}
  body{margin:0; padding:24px; background:#f7f8fa; color:#111;}
  .container{max-width:880px;margin:40px auto;background:#fff;border-radius:12px;padding:20px;box-shadow:0 6px 18px rgba(0,0,0,0.06);}
  h1{margin:0 0 16px; font-size:20px;}
  #viewArea{white-space:pre-wrap; line-height:1.6; padding:12px; border:1px solid #eee; border-radius:8px; min-height:240px; background:#fcfdff;}
  .controls{margin-top:12px; display:flex; gap:8px;}
  button{padding:8px 14px;border-radius:8px;border:1px solid #ddd;background:#fff;cursor:pointer;}
  button.primary{background:#0b61ff;color:#fff;border-color:transparent;}
  button:disabled{opacity:0.6;cursor:default;}
  textarea{width:100%; min-height:240px; padding:12px; font-family:inherit; font-size:14px; border-radius:8px; border:1px solid #e6e6e6; box-sizing:border-box;}
  .small{font-size:13px;color:#666;margin-top:8px;}
  .loginBox{max-width:420px;margin:24px auto 0;}
  input[type=password]{width:100%; padding:10px;border-radius:8px;border:1px solid #ddd;}
</style>
</head>
<body>
  <div class="container" id="app">
    <h1>信息查看</h1>

    <div id="authArea">
      ${authed ? '' : renderLoginHtml()}
    </div>

    <div id="mainArea" style="display:${authed ? 'block' : 'none'}">
      <div id="viewArea">加载中……</div>
      <div class="controls">
        <button id="editBtn">编辑</button>
        <button id="saveBtn" class="primary" disabled>保存</button>
        <button id="logoutBtn" style="margin-left:auto">退出登录</button>
      </div>
      <div class="small">编辑时会3min自动保存。点击“保存”结束编辑并保存为浏览模式。</div>
    </div>
  </div>

<script>
(async function(){
  const authArea = document.getElementById('authArea');
  const mainArea = document.getElementById('mainArea');
  const viewArea = document.getElementById('viewArea');
  const editBtn = document.getElementById('editBtn');
  const saveBtn = document.getElementById('saveBtn');
  const logoutBtn = document.getElementById('logoutBtn');

  // MODE: 'view' | 'edit'
  let mode = 'view';
  let textareaEl = null;
  let autoSaveTimer = null;
  let dirty = false;
  let saving = false;

  async function fetchContent() {
    const r = await fetch('/api/content');
    const j = await r.json();
    if (j.ok) return j.content || '';
    return '';
  }
  async function putContent(content) {
    saving = true;
    saveBtn.disabled = true;
    try {
      const r = await fetch('/api/content', {
        method:'PUT',
        headers:{'Content-Type':'application/json'},
        body: JSON.stringify({content})
      });
      const j = await r.json();
      if (!j.ok) throw new Error(j.error || 'save failed');
      dirty = false;
    } catch (e) {
      console.error('save error', e);
      alert('保存失败：' + (e.message || e));
    } finally {
      saving = false;
      saveBtn.disabled = false;
    }
  }

  async function loadAndShow() {
    const content = await fetchContent();
    viewArea.textContent = content || '（当前没有内容）';
  }

   /*
   function enterEdit() {
    if (mode === 'edit') return;
    mode = 'edit';
    // replace viewArea with textarea
    const cur = viewArea.textContent;
    textareaEl = document.createElement('textarea');
    textareaEl.value = cur === '（当前没有内容）' ? '' : cur;
    viewArea.replaceWith(textareaEl);
    saveBtn.disabled = false;
    editBtn.disabled = true;
    textareaEl.focus();
    // autosave on input (debounce)
    if (autoSaveTimer) clearTimeout(autoSaveTimer);
    textareaEl.addEventListener('input', () => {
      dirty = true;
      if (autoSaveTimer) clearTimeout(autoSaveTimer);
      autoSaveTimer = setTimeout(async () => {
        const v = textareaEl.value;
        await putContent(v);
      }, 1500); // 1.5s debounce auto-save
    });
  } 
  */
  function enterEdit() {
    if (mode === 'edit') return;
    mode = 'edit';
  
    // ✅ 每次都重新获取当前 viewArea（防止旧引用）
    const currentView = document.getElementById('viewArea');
    const cur = currentView ? currentView.textContent : '';
    
    textareaEl = document.createElement('textarea');
    textareaEl.value = cur === '（当前没有内容）' ? '' : cur;
    currentView.replaceWith(textareaEl);
  
    saveBtn.disabled = false;
    editBtn.disabled = true;
    textareaEl.focus();
  
    // 启动自动保存（3 分钟一次）
    if (autoSaveTimer) clearInterval(autoSaveTimer);
    autoSaveTimer = setInterval(async () => {
      if (!dirty || saving) return;
      const v = textareaEl.value;
      await putContent(v);
    }, 180000);
  
    textareaEl.addEventListener('input', () => {
      dirty = true;
    });
  }
  
  
  async function exitEdit(save = true) {
    if (mode !== 'edit') return;
    if (autoSaveTimer) clearInterval(autoSaveTimer);
  
    const content = textareaEl.value;
    if (save) {
      await putContent(content);
    }
  
    const newView = document.createElement('div');
    newView.id = 'viewArea';
    newView.style.whiteSpace = 'pre-wrap';
    newView.style.lineHeight = '1.6';
    newView.textContent = content || '（当前没有内容）';
  
    textareaEl.replaceWith(newView);
    textareaEl = null;
    mode = 'view';
    saveBtn.disabled = true;
    editBtn.disabled = false;
  }
  

  // wire buttons
  editBtn.addEventListener('click', enterEdit);
  saveBtn.addEventListener('click', async () => {
    if (mode !== 'edit') return;
    await exitEdit(true);
  });
  logoutBtn.addEventListener('click', async () => {
    await fetch('/logout', {method:'POST'});
    // refresh to show login screen
    location.reload();
  });

  // initial load if authed
  if (${authed ? 'true' : 'false'}) {
    await loadAndShow();
  }

  // login handling
  const loginForm = document.getElementById('loginForm');
  if (loginForm) {
    loginForm.addEventListener('submit', async (ev) => {
      ev.preventDefault();
      const pwInput = document.getElementById('passwordInput');
      const pw = pwInput.value;
      try {
        const r = await fetch('/login', {
          method:'POST',
          headers:{'Content-Type':'application/json'},
          body: JSON.stringify({password: pw})
        });
        const j = await r.json();
        if (j.ok) {
          // reload to show page with cookie
          location.reload();
        } else {
          alert('登录失败: ' + (j.error || '密码错误'));
        }
      } catch (e) {
        alert('登录请求失败');
      }
    });
  }

})();
</script>
</body>
</html>`;
}

function renderLoginHtml(){
  return `
  <div class="loginBox">
    <form id="loginForm">
      <div style="margin-bottom:8px">请输入密码以查看内容</div>
      <input id="passwordInput" type="password" placeholder="密码" required />
      <div style="margin-top:8px">
        <button type="submit" class="primary" style="margin-top:8px">登录</button>
      </div>
    </form>
  </div>`;
}
