/**
 * @file Cloudflare Worker - 基于时间的一次性密码 (TOTP) 身份验证器
 * @version D1.0
 * @description
 * 这是一个部署在 Cloudflare Workers 上的全功能 TOTP 应用。
 * 它使用 Cloudflare D1 数据库作为后端存储，以保证数据的强一致性和即时更新。
 * 用户可以通过密码访问，管理（添加、删除）TOTP 密钥，并查看实时生成的6位验证码。
 *
 * 主要技术栈:
 * - 运行时: Cloudflare Workers
 * - 数据库: Cloudflare D1 (SQLite)
 * - 前端: 服务器端渲染的 Vanilla JavaScript, HTML, CSS
 */

export default {
  /**
   * Worker 的主入口点。
   * @param {Request} request - 收到的 HTTP 请求对象。
   * @param {object} env - 包含环境变量和绑定的服务（如 D1 数据库）。
   * @returns {Promise<Response>} - 返回给客户端的 HTTP 响应。
   */
  async fetch(request, env) {
    return handleRequest(request, env);
  },
};

/**
 * 核心请求处理函数，根据请求的 URL 和方法进行路由。
 * @param {Request} request
 * @param {object} env
 * @returns {Promise<Response>}
 */
async function handleRequest(request, env) {
  const url = new URL(request.url);
  const ACCESS_PASSWORD = env.ACCESS_PASSWORD;
  // 从环境中获取 D1 数据库的绑定
  const DB = env.DB; 

  // 为所有动态 HTML 响应定义标准的、禁止缓存的 HTTP 头
  const noCacheHeaders = {
    'Content-Type': 'text/html; charset=utf-8',
    'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0',
    'Pragma': 'no-cache', // 兼容 HTTP/1.0
    'Expires': '0'      // 兼容代理服务器
  };

  // --- 处理 POST 请求 (用于执行添加、删除、认证等操作) ---
  if (request.method === 'POST') {
    const formData = await request.formData();
    const password = formData.get('password');
    const action = formData.get('action');

    // 对所有写操作进行密码验证
    if (password !== ACCESS_PASSWORD) {
      return new Response('Unauthorized: Invalid password', { status: 401 });
    }

    // 根据 'action' 参数执行不同的数据库操作
    switch (action) {
      case 'add': {
        const name = formData.get('name');
        const secret = formData.get('secret');
        if (name && secret) {
          try {
            new TOTP(secret); // 在写入前，先在服务器端校验密钥格式的合法性
            
            // 将新的密钥数据插入 D1 数据库
            await DB.prepare("INSERT INTO totp_keys (name, secret) VALUES (?, ?)")
                    .bind(name, secret)
                    .run();
            return new Response('Key added successfully!', { status: 200 });
          } catch(e) {
            // 如果密钥格式错误，或名称重复（主键冲突），D1 会抛出错误
            return new Response(`添加失败: ${e.message}`, { status: 400 });
          }
        }
        return new Response('Missing name or secret', { status: 400 });
      }
      case 'delete': {
        const keyToDelete = formData.get('key');
        if (keyToDelete) {
          // 从 D1 数据库中删除指定的密钥
          await DB.prepare("DELETE FROM totp_keys WHERE name = ?")
                  .bind(keyToDelete)
                  .run();
          return new Response('Key deleted successfully!', { status: 200 });
        }
        return new Response('Missing key to delete', { status: 400 });
      }
      case 'auth':
        // 'auth' 操作仅用于验证密码，成功后返回200 OK，由前端进行跳转
        return new Response(null, { status: 200 });
      default:
        return new Response('Invalid action', { status: 400 });
    }
  }

  // --- 处理 GET 请求 (用于渲染页面) ---
  const isAuthenticated = url.searchParams.get('auth') === 'true';

  // 如果用户未通过身份验证，则显示密码登录页面
  if (!isAuthenticated) {
    return new Response(passwordFormHtml(), { headers: noCacheHeaders });
  }

  // 从D1数据库查询所有密钥以渲染主页面
  const { results } = await DB.prepare("SELECT name, secret FROM totp_keys ORDER BY name ASC").all();
  const totpKeys = {};
  if (results) {
    for (const row of results) {
      totpKeys[row.name] = row.secret;
    }
  }

  // 渲染并返回包含所有密钥的主应用页面
  return new Response(await appHtml(totpKeys, ACCESS_PASSWORD), { headers: noCacheHeaders });
}

/**
 * 生成密码登录页面的 HTML。
 * @returns {string} 登录页的完整 HTML 字符串。
 */
function passwordFormHtml() {
  return `
<!DOCTYPE html>
<html lang="zh-CN"><head>
<meta charset="UTF-8"><title>身份验证</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
:root {
  --bg-color: #f8f9fa; --text-color: #212529; --card-bg: #ffffff;
  --accent-color: #0d6efd; --accent-hover: #0b5ed7; --border-color: #dee2e6;
  --shadow-color: rgba(0, 0, 0, 0.05);
}
body { 
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  background-color: var(--bg-color); color: var(--text-color);
  display: flex; align-items: center; justify-content: center;
  height: 100vh; margin: 0;
}
.container { 
  background-color: var(--card-bg);
  padding: 2.5rem; border-radius: 12px;
  box-shadow: 0 4px 20px var(--shadow-color);
  text-align: center; max-width: 320px; width: 100%;
}
h2 { margin-top: 0; margin-bottom: 1.5rem; font-weight: 600; }
input { 
  font-size: 1rem; padding: 0.75rem; width: 100%; box-sizing: border-box;
  margin-bottom: 1.5rem; border-radius: 8px; border: 1px solid var(--border-color);
  background-color: var(--bg-color); color: var(--text-color);
  transition: border-color 0.2s, box-shadow 0.2s;
}
input:focus { border-color: var(--accent-color); box-shadow: 0 0 0 3px color-mix(in srgb, var(--accent-color) 25%, transparent); outline: none; }
button { 
  font-size: 1rem; font-weight: 500; padding: 0.75rem; width: 100%;
  background-color: var(--accent-color); color: white; border: none;
  border-radius: 8px; cursor: pointer; transition: background-color 0.2s;
}
button:hover { background-color: var(--accent-hover); }
</style>
</head>
<body>
  <div class="container">
    <h2>请输入访问密码</h2>
    <form id="form">
      <input type="password" id="password" placeholder="密码" required>
      <button type="submit">进 入</button>
    </form>
  </div>
  <script>
    document.getElementById('form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const password = document.getElementById('password').value;
      const res = await fetch('/', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: 'password=' + encodeURIComponent(password) + '&action=auth'
      });
      if (res.ok) {
        window.location.href = '/?auth=true';
      } else {
        alert('密码错误');
        document.getElementById('password').value = '';
      }
    });
  </script>
</body></html>`;
}

/**
 * 生成主应用界面的 HTML，包含所有 TOTP 密钥的实时验证码。
 * @param {object} totpKeys - 包含所有密钥的对象，格式为 { name: secret }。
 * @param {string} ACCESS_PASSWORD - 访问密码，需要注入到客户端脚本中用于后续操作的认证。
 * @returns {Promise<string>} 主应用页面的完整 HTML 字符串。
 */
async function appHtml(totpKeys, ACCESS_PASSWORD) {
  const ICONS = {
    copy: `<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>`,
    trash: `<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path></svg>`,
    sun: `<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="5"></circle><line x1="12" y1="1" x2="12" y2="3"></line><line x1="12" y1="21" x2="12" y2="23"></line><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"></line><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"></line><line x1="1" y1="12" x2="3" y2="12"></line><line x1="21" y1="12" x2="23" y2="12"></line><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"></line><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"></line></svg>`,
    moon: `<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path></svg>`,
    plus: `<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="12" y1="5" x2="12" y2="19"></line><line x1="5" y1="12" x2="19" y2="12"></line></svg>`
  };

  let cardsHtml = '';
  for (const name in totpKeys) {
    const secret = totpKeys[name];
    try {
      const token = await new TOTP(secret).generate();
      cardsHtml += `
      <div class="totp-card" data-name="${name}">
        <div class="card-header">
          <span class="name">${name}</span>
          <div class="actions">
            <button class="icon-btn" onclick="copy('${token}')" title="复制">${ICONS.copy}</button>
            <button class="icon-btn danger" onclick="remove('${name}')" title="删除">${ICONS.trash}</button>
          </div>
        </div>
        <div class="token">${token.slice(0, 3)} ${token.slice(3)}</div>
        <div class="progress-bar-container"><div class="progress-bar"></div></div>
      </div>`;
    } catch (e) {
      cardsHtml += `
      <div class="totp-card error-card" data-name="${name}">
        <div class="card-header">
          <span class="name">${name}</span>
          <div class="actions">
            <button class="icon-btn danger" onclick="remove('${name}')" title="删除">${ICONS.trash}</button>
          </div>
        </div>
        <div class="token-error">密钥格式错误</div>
        <div class="token-error-detail">${e.message}</div>
      </div>`;
    }
  }

  return `
<!DOCTYPE html>
<html lang="zh-CN"><head>
<meta charset="UTF-8"><title>我的验证码</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
/* 具体的CSS样式，定义了页面的外观和响应式布局 */
:root {
  --bg-color: #f8f9fa; --text-color: #212529; --card-bg: #ffffff;
  --accent-color: #0d6efd; --accent-hover: #0b5ed7; --border-color: #dee2e6;
  --shadow-color: rgba(0, 0, 0, 0.05); --danger-color: #dc3545;
  --code-font: "Menlo", "Monaco", "Consolas", "Courier New", monospace;
}
body.dark {
  --bg-color: #121212; --text-color: #e9ecef; --card-bg: #1e1e1e;
  --accent-color: #2586fd; --accent-hover: #1c7ed6; --border-color: #343a40;
  --shadow-color: rgba(0, 0, 0, 0.2); --danger-color: #e03142;
}
body { 
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  background-color: var(--bg-color); color: var(--text-color); margin: 0;
  padding: 2rem 1rem; transition: background-color 0.3s, color 0.3s;
}
.main-container { max-width: 600px; margin: 0 auto; display: grid; gap: 2rem; }
.top-bar { display: flex; justify-content: space-between; align-items: center; }
.top-bar h2 { margin: 0; font-size: 1.75rem; font-weight: 700; }
.top-bar .controls { display: flex; align-items: center; gap: 0.5rem; }
.cards-grid { display: grid; gap: 1rem; }
.totp-card {
  background-color: var(--card-bg); border-radius: 12px; padding: 1.25rem;
  box-shadow: 0 4px 20px var(--shadow-color);
  transition: transform 0.2s, box-shadow 0.2s;
  overflow: hidden;
}
.totp-card:hover { transform: translateY(-3px); }
.card-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.75rem; }
.name { font-size: 1.1rem; font-weight: 600; }
.token {
  font-family: var(--code-font); font-size: 2.5rem; letter-spacing: 2px;
  font-weight: 500; text-align: center; color: var(--accent-color); margin-bottom: 1rem;
}
.progress-bar-container { background-color: var(--border-color); height: 4px; border-radius: 2px; overflow: hidden; }
.progress-bar { background-color: var(--accent-color); height: 100%; width: 100%; transition: width 1s linear; }
.error-card { border-left: 4px solid var(--danger-color); }
.token-error { font-weight: 500; text-align: center; color: var(--danger-color); font-size: 1.2rem; }
.token-error-detail { font-size: 0.8rem; text-align: center; color: var(--danger-color); opacity: 0.7; margin-top: 4px;}
.add-section { background-color: var(--card-bg); border-radius: 12px; padding: 1.5rem; box-shadow: 0 4px 20px var(--shadow-color); }
.form-group { display: grid; grid-template-columns: 1fr 1fr; gap: 0.75rem; margin-bottom: 0.75rem; }
input { 
  font-size: 0.95rem; padding: 0.6rem; box-sizing: border-box; width: 100%;
  border-radius: 8px; border: 1px solid var(--border-color); background-color: var(--bg-color); color: var(--text-color);
  transition: border-color 0.2s, box-shadow 0.2s;
}
input:focus { border-color: var(--accent-color); box-shadow: 0 0 0 3px color-mix(in srgb, var(--accent-color) 25%, transparent); outline: none; }
button { 
  font-size: 0.95rem; font-weight: 500; padding: 0.6rem 1rem; background-color: var(--accent-color); 
  color: white; border: none; border-radius: 8px; cursor: pointer;
  display: inline-flex; align-items: center; justify-content: center; gap: 0.5rem;
  transition: background-color 0.2s, transform 0.1s;
}
button:hover { background-color: var(--accent-hover); }
button:active { transform: scale(0.98); }
.icon-btn { padding: 0.5rem; background: transparent; color: var(--text-color); }
.icon-btn:hover { background-color: color-mix(in srgb, var(--text-color) 10%, transparent); }
.icon-btn.danger:hover { color: var(--danger-color); background-color: color-mix(in srgb, var(--danger-color) 10%, transparent); }
#toast-container { position: fixed; bottom: 20px; right: 20px; z-index: 1000; display: grid; gap: 10px; }
.toast {
  background-color: #333; color: white; padding: 12px 20px; border-radius: 8px;
  box-shadow: 0 4px 15px rgba(0,0,0,0.2); font-size: 0.9rem;
  opacity: 0; transform: translateY(20px); animation: toast-in 0.5s forwards;
}
@keyframes toast-in { to { opacity: 1; transform: translateY(0); } }
</style>
</head>
<body>
  <div id="toast-container"></div>
  <div class="main-container">
    <div class="top-bar">
      <h2>验证码</h2>
      <div class="controls">
        <button onclick="exportKeys()">导出密钥</button>
        <button id="theme-toggle" class="icon-btn" title="切换主题"></button>
      </div>
    </div>
    <div class="cards-grid" id="cards-grid">${cardsHtml}</div>
    <div class="add-section">
      <h3>添加新密钥</h3>
      <div class="form-group">
        <input id="name-input" placeholder="名称 (例如: Google)">
        <input id="secret-input" placeholder="Base32 密钥或 otpauth:// URL">
      </div>
      <button onclick="add()">${ICONS.plus} 添加</button>
    </div>
  </div>

<script>
  // 从服务器端注入密码到客户端，用于后续的API请求认证。
  const PWD = '${ACCESS_PASSWORD}';
  const ICONS = { copy: \`${ICONS.copy}\`, trash: \`${ICONS.trash}\`, sun: \`${ICONS.sun}\`, moon: \`${ICONS.moon}\`};

  /* --- UI 交互函数 --- */

  // 主题切换逻辑
  const themeToggle = document.getElementById('theme-toggle');
  function applyTheme(theme) { if (theme === 'dark') { document.body.classList.add('dark'); themeToggle.innerHTML = ICONS.sun; } else { document.body.classList.remove('dark'); themeToggle.innerHTML = ICONS.moon; } }
  themeToggle.addEventListener('click', () => { const newTheme = document.body.classList.contains('dark') ? 'light' : 'dark'; localStorage.setItem('theme', newTheme); applyTheme(newTheme); });
  applyTheme(localStorage.getItem('theme') || 'light');
  
  // 显示一个短暂的通知消息 (Toast)
  function showToast(message, duration = 3000) { const container = document.getElementById('toast-container'); const toast = document.createElement('div'); toast.className = 'toast'; toast.textContent = message; container.appendChild(toast); setTimeout(() => { toast.remove(); }, duration); }
  
  // 复制文本到剪贴板
  function copy(text) { navigator.clipboard.writeText(text).then(() => showToast('已复制到剪贴板')).catch(() => showToast('复制失败')); }

  /* --- 核心数据操作函数 --- */

  /**
   * 处理添加新密钥的逻辑。
   * 它会向服务器发送一个 'add' 请求，并在成功后立即刷新页面。
   * 由于后端使用 D1 数据库，数据是强一致性的，因此可以立即刷新。
   */
  async function add() {
    const nameInput = document.getElementById('name-input');
    const secretInput = document.getElementById('secret-input');
    let name = nameInput.value.trim();
    let secret = secretInput.value.trim();

    if (secret.startsWith('otpauth://')) {
      try {
        const parsed = new URL(secret);
        const params = new URLSearchParams(parsed.search);
        secret = params.get('secret');
        if (!name) {
           name = decodeURIComponent(parsed.pathname.split('/').pop().split(':').pop()) || params.get('issuer') || '未命名';
        }
      } catch (e) { showToast('无效的 otpauth URL'); return; }
    }
    if (!name || !secret) { showToast('请填写名称和密钥'); return; }

    const res = await fetch('/', {
      method: 'POST',
      headers: {'Content-Type': 'application/x-www-form-urlencoded'},
      body: \`password=\${encodeURIComponent(PWD)}&action=add&name=\${encodeURIComponent(name)}&secret=\${encodeURIComponent(secret)}\`
    });

    if (res.ok) {
      showToast('添加成功！');
      location.reload(); 
    } else {
      showToast(\`添加失败: \${await res.text()}\`);
    }
  }

  /**
   * 处理删除密钥的逻辑。
   * 它会向服务器发送一个 'delete' 请求，并在成功后立即刷新页面。
   */
  async function remove(name) {
    if (!confirm(\`确定要删除 "\${name}" 吗？\`)) return;

    const res = await fetch('/', {
      method: 'POST',
      headers: {'Content-Type': 'application/x-www-form-urlencoded'},
      body: \`password=\${encodeURIComponent(PWD)}&action=delete&key=\${encodeURIComponent(name)}\`
    });

    if (res.ok) {
      showToast('删除成功！');
      location.reload();
    } else {
      showToast('删除失败');
    }
  }

  // 导出密钥功能的占位符
  function exportKeys() { fetch('/?auth=true').then(res => res.text()).then(html => { showToast('导出功能请通过后端实现更安全完整，此处仅为功能占位。'); }); }

  /* --- 定时器与自动刷新逻辑 --- */
  
  let timerInterval = null;
  /**
   * 每秒更新所有验证码卡片的倒计时进度条。
   * 并在每个30秒周期的开始点触发页面刷新。
   */
  function updateTimer() { 
    const seconds = new Date().getSeconds(); 
    if (seconds % 30 === 0) { 
      if (timerInterval) clearInterval(timerInterval); 
      setTimeout(() => location.reload(), 500); // 延迟一小会确保服务器时间也已同步
      return; 
    } 
    const remaining = 30 - (seconds % 30); 
    const percentage = (remaining / 30) * 100; 
    document.querySelectorAll('.progress-bar').forEach(bar => { bar.style.width = percentage + '%'; }); 
  }
  
  // 页面加载完成后立即启动定时器
  document.addEventListener('DOMContentLoaded', () => { 
    updateTimer(); 
    timerInterval = setInterval(updateTimer, 1000); 
  });
</script>
</body></html>`;
}

/**
 * TOTP 算法 (RFC 6238) 的 JavaScript 实现类。
 */
class TOTP {
  /**
   * @param {string} secret - Base32 编码的密钥字符串。
   */
  constructor(secret) {
    this.secret = base32ToBytes(secret.replace(/ /g, ''));
    this.period = 30; // 时间步长 (秒)
    this.digits = 6;  // 验证码长度
    this.algorithm = 'SHA-1'; // HMAC 哈希算法
  }

  /**
   * 生成当前时间的 TOTP 验证码。
   * @returns {Promise<string>} 6位数的验证码字符串。
   */
  async generate() { 
    const counter = Math.floor(Date.now() / 1000 / this.period); 
    return this.generateOTP(counter); 
  }

  /**
   * 根据给定的计数器值生成 HOTP 验证码 (TOTP 的核心)。
   * @param {number} counter - 时间步长计数器。
   * @returns {Promise<string>} 6位数的验证码字符串。
   */
  async generateOTP(counter) { 
    const buf = new ArrayBuffer(8); 
    const view = new DataView(buf); 
    view.setUint32(4, counter); // 将计数器写入8字节缓冲区的后半部分
    const key = await crypto.subtle.importKey('raw',this.secret,{ name: 'HMAC', hash: this.algorithm },false,['sign']); 
    const hmac = new Uint8Array(await crypto.subtle.sign('HMAC', key, buf)); 
    const offset = hmac[hmac.length - 1] & 0xf; 
    const binCode = ((hmac[offset] & 0x7f) << 24) | ((hmac[offset + 1] & 0xff) << 16) | ((hmac[offset + 2] & 0xff) << 8) | (hmac[offset + 3] & 0xff); 
    const otp = binCode % 10 ** this.digits; 
    return otp.toString().padStart(this.digits, '0'); 
  }
}

/**
 * 将 Base32 编码的字符串解码为 Uint8Array 字节数组。
 * @param {string} str - Base32 编码的字符串。
 * @returns {Uint8Array} 解码后的字节数组。
 */
function base32ToBytes(str) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const clean = str.toUpperCase().replace(/=+$/, '');
  const bytes = [];
  let bits = 0, value = 0;
  for (let i = 0; i < clean.length; i++) {
    const idx = alphabet.indexOf(clean[i]);
    if (idx === -1) throw new Error('Invalid base32 string');
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return new Uint8Array(bytes);
}
