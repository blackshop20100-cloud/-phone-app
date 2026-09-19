const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = Number(process.env.PORT || 3000);
const PUBLIC = path.join(__dirname, 'public');
const COOKIE = 'phone_session';
const sessions = new Map();

// Passwords are verified server-side. The frontend never contains the plaintext passwords.
const USERS = {
  user: process.env.USER_PASSWORD_HASH || '78839c0f497920c6afabffe55ade29f1:953ffe983a756c9fc59c4c190d04642831ba3201ce9970fd34d73717418615fea338b3fdfa6d7ce04808d37a3e75ceb8bfa707ef683d3fc46919d455a04f682f',
  admin: process.env.ADMIN_PASSWORD_HASH || '4069e56db40c568f92d59bb1ba34ac72:775d7137627a8cade127e83b4ce29427b2dcdfe203c09b1ccd63b8db843559db76b8eba680e126f3510211176dcf87e88015175ef152d8f503f56a2ea0822d14'
};

function parseCookies(req) {
  const out = {};
  for (const part of (req.headers.cookie || '').split(';')) {
    const i = part.indexOf('=');
    if (i > -1) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}

function verifyPassword(password, stored) {
  try {
    const [saltHex, hashHex] = stored.split(':');
    const expected = Buffer.from(hashHex, 'hex');
    const actual = crypto.scryptSync(password, Buffer.from(saltHex, 'hex'), expected.length);
    return crypto.timingSafeEqual(actual, expected);
  } catch { return false; }
}

function currentRole(req) {
  const token = parseCookies(req)[COOKIE];
  const session = token && sessions.get(token);
  if (!session) return 'guest';
  if (session.expiresAt < Date.now()) { sessions.delete(token); return 'guest'; }
  return session.role;
}

function sendJson(res, status, data, extraHeaders = {}) {
  const body = JSON.stringify(data);
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...extraHeaders });
  res.end(body);
}

function serveIndex(req, res) {
  let html = fs.readFileSync(path.join(PUBLIC, 'index.html'), 'utf8');
  const role = currentRole(req);
  html = html.replaceAll('__SERVER_ROLE__', role);
  res.writeHead(200, {
    'Content-Type': 'text/html; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'same-origin'
  });
  res.end(html);
}

const MIME = {
  '.html': 'text/html; charset=utf-8', '.js': 'application/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8', '.json': 'application/json; charset=utf-8',
  '.webmanifest': 'application/manifest+json; charset=utf-8', '.png': 'image/png',
  '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.svg': 'image/svg+xml', '.woff2': 'font/woff2'
};

function serveStatic(req, res) {
  let urlPath = decodeURIComponent(new URL(req.url, 'http://localhost').pathname);
  if (urlPath === '/') return serveIndex(req, res);
  if (urlPath === '/~flock.js') urlPath = '/flock.js';
  const file = path.resolve(PUBLIC, '.' + urlPath);
  if (!file.startsWith(PUBLIC + path.sep)) return sendJson(res, 403, { error: 'Forbidden' });
  if (!fs.existsSync(file) || !fs.statSync(file).isFile()) return sendJson(res, 404, { error: 'Not found' });
  const ext = path.extname(file).toLowerCase();
  res.writeHead(200, { 'Content-Type': MIME[ext] || 'application/octet-stream', 'Cache-Control': 'public, max-age=3600', 'X-Content-Type-Options': 'nosniff' });
  fs.createReadStream(file).pipe(res);
}

const server = http.createServer((req, res) => {
  if (req.method === 'GET' && req.url.split('?')[0] === '/api/me') {
    return sendJson(res, 200, { ok: true, role: currentRole(req) });
  }
  if (req.method === 'POST' && req.url.split('?')[0] === '/api/login') {
    let raw = '';
    req.on('data', chunk => { raw += chunk; if (raw.length > 4096) req.destroy(); });
    req.on('end', () => {
      let body;
      try { body = JSON.parse(raw || '{}'); } catch { return sendJson(res, 400, { ok: false }); }
      const password = typeof body.password === 'string' ? body.password.trim() : '';
      let role = null;
      if (verifyPassword(password, USERS.admin)) role = 'admin';
      else if (verifyPassword(password, USERS.user)) role = 'user';
      if (!role) return sendJson(res, 401, { ok: false });
      const token = crypto.randomBytes(32).toString('base64url');
      sessions.set(token, { role, expiresAt: Date.now() + 1000 * 60 * 60 * 24 * 7 });
      return sendJson(res, 200, { ok: true, role }, { 'Set-Cookie': `${COOKIE}=${encodeURIComponent(token)}; HttpOnly; SameSite=Strict; Path=/; Max-Age=604800` });
    });
    return;
  }
  if (req.method === 'POST' && req.url.split('?')[0] === '/api/logout') {
    const token = parseCookies(req)[COOKIE];
    if (token) sessions.delete(token);
    return sendJson(res, 200, { ok: true }, { 'Set-Cookie': `${COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0` });
  }
  if (req.method === 'GET') return serveStatic(req, res);
  sendJson(res, 405, { error: 'Method not allowed' });
});

server.listen(PORT, () => console.log(`Phone app running on http://localhost:${PORT}`));
