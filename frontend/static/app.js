const API = '/api/v1/admin';

// 统一请求封装(带 cookie;错误抛 detail)
async function api(path, opts = {}) {
  const res = await fetch(API + path, {
    headers: { 'Content-Type': 'application/json', ...(opts.headers || {}) },
    credentials: 'same-origin',
    ...opts,
    body: opts.body ? JSON.stringify(opts.body) : undefined,
  });
  if (res.status === 204) return null;
  const ct = res.headers.get('content-type') || '';
  if (ct.includes('application/json')) {
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || data.title || ('HTTP ' + res.status));
    return data;
  }
  if (!res.ok) throw new Error('HTTP ' + res.status);
  return await res.text();
}

function toast(msg, kind = '') {
  let t = document.getElementById('toasts');
  if (!t) { t = document.createElement('div'); t.id = 'toasts'; document.body.appendChild(t); }
  const el = document.createElement('div');
  el.className = 'toast ' + kind;
  el.textContent = msg;
  t.appendChild(el);
  setTimeout(() => el.remove(), 3500);
}

const NAV_ITEMS = [
  ['/dashboard', '仪表盘', 'dashboard'],
  ['/accounts', '号池', 'accounts'],
  ['/proxies', '代理', 'proxies'],
  ['/tokens', '分发 Token', 'tokens'],
  ['/platforms', '平台', 'platforms'],
  ['/logs', '调用日志', 'logs'],
  ['/settings', '设置', 'settings'],
];

// 鉴权守卫 + 渲染导航;失败跳登录
async function guardNav(active) {
  try {
    const me = await api('/me');
    renderNav(active, me);
    return me;
  } catch (e) {
    location.href = '/login';
    throw e;
  }
}

function renderNav(active, me) {
  const nav = document.getElementById('nav');
  if (!nav) return;
  nav.innerHTML =
    '<div class="brand">◈ Research Tool Key Pool</div>' +
    NAV_ITEMS.map(([href, label, key]) =>
      `<a href="${href}" class="${active === key ? 'active' : ''}">${label}</a>`
    ).join('') +
    '<div class="spacer"></div>' +
    `<div class="muted" style="padding:8px 12px;font-size:12px">${me ? escapeHtml(me.username) : ''}</div>` +
    '<a href="#" onclick="logout();return false;">退出</a>';
}

async function logout() {
  try { await api('/logout', { method: 'POST' }); } catch (e) {}
  location.href = '/login';
}

// 状态徽章(颜色 + 文字双编码,辅助色盲)
function statusBadge(status) {
  const map = {
    healthy: ['b-ok', '健康'],
    pending: ['b-warn', '待激活'],
    manual_disabled: ['b-warn', '已停用'],
    hard_revoked: ['b-danger', '已失效'],
    active: ['b-ok', '有效'],
    revoked: ['b-muted', '已吊销'],
    available: ['b-ok', '可用'],
    manual_disabled: ['b-muted', '已禁用'],
  };
  const [cls, label] = map[status] || ['b-muted', status];
  return `<span class="badge ${cls}"><span class="dot"></span>${label}</span>`;
}
function barClass(pct) { return pct >= 90 ? 'danger' : pct >= 70 ? 'warn' : ''; }
function fmtTime(s) { return s ? new Date(s).toLocaleString('zh-CN') : '—'; }
function escapeHtml(s) {
  return (s == null ? '' : String(s)).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
}
function countryFlag(cc) { return cc ? cc.toUpperCase() : '—'; }
