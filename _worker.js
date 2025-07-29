export default {
  async fetch(request, env) {
    return handleRequest(request, env);
  },
};

async function handleRequest(request, env) {
  const url = new URL(request.url);
  const ACCESS_PASSWORD = env.ACCESS_PASSWORD;
  const AUTH_KV = env.AUTH_KV;

  if (request.method === 'POST') {
    const formData = await request.formData();
    const password = formData.get('password');
    const action = formData.get('action');

    if (password !== ACCESS_PASSWORD) {
      return new Response('Unauthorized: Invalid password', { status: 401 });
    }

    switch (action) {
      case 'add': {
        const name = formData.get('name');
        const secret = formData.get('secret');
        if (name && secret) {
          try {
            new TOTP(secret); // 校验合法性
            await AUTH_KV.put(name, secret);
            return new Response('Key added successfully!', { status: 200 });
          } catch (e) {
            return new Response(`Error adding key: ${e.message}`, { status: 400 });
          }
        }
        return new Response('Missing name or secret', { status: 400 });
      }

      case 'delete': {
        const keyToDelete = formData.get('key');
        if (keyToDelete) {
          await AUTH_KV.delete(keyToDelete);
          return new Response('Key deleted successfully!', { status: 200 });
        }
        return new Response('Missing key to delete', { status: 400 });
      }

      case 'auth':
        return new Response(null, { status: 200 });

      default:
        return new Response('Invalid action', { status: 400 });
    }
  }

  const isAuthenticated = url.searchParams.get('auth') === 'true';

  if (!isAuthenticated) {
    return new Response(passwordFormHtml(), {
      headers: { 'Content-Type': 'text/html' },
    });
  }

  const keys = await AUTH_KV.list();
  const totpKeys = {};
  for (const key of keys.keys) {
    totpKeys[key.name] = await AUTH_KV.get(key.name);
  }

  return new Response(await appHtml(totpKeys, ACCESS_PASSWORD), {
    headers: { 'Content-Type': 'text/html' },
  });
}

function passwordFormHtml() {
  return `
<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="UTF-8"><title>TOTP 登录</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
body { font-family: sans-serif; background: #f4f4f4; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }
.container { background: white; padding: 2em; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
input { padding: 10px; width: 100%; margin-bottom: 1em; border-radius: 4px; border: 1px solid #ccc; }
button { padding: 10px; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; }
button:hover { background: #0056b3; }
</style></head>
<body>
  <div class="container">
    <h2>请输入访问密码</h2>
    <form id="form">
      <input type="password" id="password" placeholder="密码" required>
      <button type="submit">进入</button>
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
      if (res.ok) window.location.href = '/?auth=true';
      else alert('密码错误');
    });
  </script>
</body></html>`;
}

async function appHtml(totpKeys, ACCESS_PASSWORD) {
  let html = '';
  for (const name in totpKeys) {
    const secret = totpKeys[name];
    try {
      const token = await new TOTP(secret).generate();
      html += `<div class="totp-item" style="margin-bottom:10px; display:flex; align-items:center; justify-content:space-between;">
        <span><strong>${name}</strong>: <span>${token}</span></span>
        <div>
          <button onclick="copy('${token}')">复制</button>
          <button onclick="remove('${name}')">删除</button>
        </div>
      </div>`;
    } catch (e) {
      html += `<div style="color:red">${name}: 错误密钥 (${e.message})</div>`;
    }
  }

  return `
<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="UTF-8"><title>我的验证码</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  body {
    font-family: sans-serif; padding: 2em; background: var(--bg); color: var(--text);
    --bg: #f9f9f9; --text: #222; --btn-bg: #007bff; --btn-hover: #0056b3;
  }
  body.dark {
    --bg: #121212; --text: #eee; --btn-bg: #339af0; --btn-hover: #1c7ed6;
  }
  input {
    padding: 8px; margin-right: 10px; border-radius: 4px; border: 1px solid #ccc;
    background: var(--bg); color: var(--text);
  }
  button {
    padding: 8px 12px; margin-left: 5px; border: none; border-radius: 4px;
    background: var(--btn-bg); color: white; cursor: pointer;
  }
  button:hover {
    background: var(--btn-hover);
  }
  .totp-item span {
    font-size: 1.1em;
  }
  .top-bar {
    margin-bottom: 20px;
    display: flex; justify-content: space-between; align-items: center;
  }
</style></head>
<body>
  <div class="top-bar">
    <h2>当前验证码</h2>
    <div>
      <button onclick="toggleTheme()">切换深色模式</button>
      <button onclick="exportKeys()">导出密钥</button>
    </div>
  </div>

  ${html}

  <hr>

  <h3>添加新密钥或扫码导入</h3>
  <input id="name" placeholder="名称">
  <input id="secret" placeholder="Base32 密钥或 otpauth:// URL">
  <button onclick="add()">添加</button>

  <script>
    // 主题切换
    function toggleTheme() {
      document.body.classList.toggle('dark');
      localStorage.setItem('theme', document.body.classList.contains('dark') ? 'dark' : 'light');
    }
    // 页面载入恢复主题
    if (localStorage.getItem('theme') === 'dark') {
      document.body.classList.add('dark');
    }

    // 复制到剪贴板
    function copy(text) {
      navigator.clipboard.writeText(text).then(() => alert('已复制')).catch(() => alert('复制失败'));
    }

    // 添加密钥，支持 otpauth URL 解析
    async function add() {
      let n = document.getElementById('name').value.trim();
      let s = document.getElementById('secret').value.trim();

      // 如果输入的是 otpauth:// URL，尝试解析
      if (s.startsWith('otpauth://')) {
        try {
          const parsed = parseOtpAuthUrl(s);
          if (!n) n = parsed.label || parsed.issuer || '未命名';
          s = parsed.secret;
          if (!s) {
            alert('otpauth URL 中未找到 secret');
            return;
          }
        } catch (e) {
          alert('无效的 otpauth URL: ' + e.message);
          return;
        }
      }

      if (!n || !s) {
        alert('请填写名称和密钥');
        return;
      }

      const res = await fetch('/', {
        method: 'POST',
        headers: {'Content-Type': 'application/x-www-form-urlencoded'},
        body: 'password=' + encodeURIComponent('${ACCESS_PASSWORD}') + '&action=add&name=' + encodeURIComponent(n) + '&secret=' + encodeURIComponent(s)
      });

      if (res.ok) location.reload();
      else alert(await res.text());
    }

    // 删除密钥
    async function remove(name) {
      if (!confirm('确定删除 "' + name + '"？')) return;
      const res = await fetch('/', {
        method: 'POST',
        headers: {'Content-Type': 'application/x-www-form-urlencoded'},
        body: 'password=' + encodeURIComponent('${ACCESS_PASSWORD}') + '&action=delete&key=' + encodeURIComponent(name)
      });
      if (res.ok) location.reload();
      else alert('删除失败');
    }

    // 导出所有密钥
    function exportKeys() {
      const keys = {};
      document.querySelectorAll('.totp-item strong').forEach(el => {
        const name = el.textContent;
        const secret = el.parentElement.querySelector('span:nth-child(2)')?.textContent || '';
        keys[name] = secret;
      });

      // 从页面变量读取更准确的密钥
      fetch('/?auth=true').then(res => res.text()).then(html => {
        // 简单正则提取密钥数据（因KV不能客户端直接读）
        // 建议后端另做导出接口，此处简单提示
        alert('导出功能请通过后端实现更安全完整，此处仅示例。');
      });

      // 下面是示例导出json，前提你能在页面获得密钥
      /*
      const blob = new Blob([JSON.stringify(keys, null, 2)], {type: 'application/json'});
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'totp-keys.json';
      a.click();
      URL.revokeObjectURL(url);
      */
    }

    // 解析 otpauth:// URL
    function parseOtpAuthUrl(url) {
      const u = new URL(url);
      if (u.protocol !== 'otpauth:') throw new Error('协议必须是 otpauth');
      if (u.hostname !== 'totp') throw new Error('仅支持 totp 类型');

      const label = decodeURIComponent(u.pathname.slice(1));
      const params = Object.fromEntries(u.searchParams.entries());
      return {
        label,
        secret: params.secret,
        issuer: params.issuer,
      };
    }

    // 30秒自动刷新页面，保证验证码更新
    setInterval(() => location.reload(), 30000);
  </script>
</body></html>`;
}

// 内联 TOTP 实现（精简版）
class TOTP {
  constructor(secret) {
    this.secret = base32ToBytes(secret.replace(/ /g, ''));
    this.period = 30;
    this.digits = 6;
    this.algorithm = 'SHA-1';
  }

  async generate() {
    const counter = Math.floor(Date.now() / 1000 / this.period);
    return this.generateOTP(counter);
  }

  async generateOTP(counter) {
    const buf = new ArrayBuffer(8);
    const view = new DataView(buf);
    // 设置高4字节为0，低4字节为计数器
    view.setUint32(4, counter);
    const key = await crypto.subtle.importKey(
      'raw',
      this.secret,
      { name: 'HMAC', hash: this.algorithm },
      false,
      ['sign']
    );
    const hmac = new Uint8Array(await crypto.subtle.sign('HMAC', key, buf));
    const offset = hmac[hmac.length - 1] & 0xf;
    const binCode =
      ((hmac[offset] & 0x7f) << 24) |
      ((hmac[offset + 1] & 0xff) << 16) |
      ((hmac[offset + 2] & 0xff) << 8) |
      (hmac[offset + 3] & 0xff);
    const otp = binCode % 10 ** this.digits;
    return otp.toString().padStart(this.digits, '0');
  }
}

function base32ToBytes(str) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const clean = str.toUpperCase().replace(/=+$/, '');
  const bytes = [];
  let bits = 0,
    value = 0;
  for (let i = 0; i < clean.length; i++) {
    const idx = alphabet.indexOf(clean[i]);
    if (idx === -1) throw new Error('Invalid base32');
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return new Uint8Array(bytes);
}
