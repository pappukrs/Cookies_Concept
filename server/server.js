// Cookies concept server. Zero dependencies: only Node's built-in modules.
//
//   node server/server.js
//
// It starts TWO servers:
//   http://localhost:3000   -> the real app (our "bank")
//   http://127.0.0.1:3001   -> an "attacker" site, used for the CSRF / SameSite demo
//
// localhost and 127.0.0.1 are DIFFERENT sites to the browser, so requests
// from 3001 to 3000 count as cross-site. (Ports do NOT change the site:
// localhost:3001 -> localhost:3000 would still be same-site.)
import http from 'node:http';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  parseCookies,
  serializeCookie,
  clearCookie,
  sign,
  unsign,
  randomToken,
} from './cookie-utils.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CLIENT_DIR = path.join(__dirname, '..', 'client');
const APP_PORT = 3000;
const ATTACKER_PORT = 3001;

// In a real app this comes from an env var and is long + random.
const SECRET = process.env.COOKIE_SECRET || 'dev-only-secret-change-me';

// In-memory session store: sessionId -> { user, csrfToken, balance, createdAt }
// Real apps use Redis or a database so sessions survive restarts and
// are shared across many server instances.
const sessions = new Map();
const SESSION_TTL_SECONDS = 60 * 60;

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
};

// ---------- small helpers ----------

function sendJson(res, status, data, cookies = []) {
  const headers = { 'Content-Type': MIME['.json'] };
  if (cookies.length) headers['Set-Cookie'] = cookies; // an ARRAY = several Set-Cookie headers
  res.writeHead(status, headers);
  res.end(JSON.stringify(data, null, 2));
}

function sendHtml(res, status, html) {
  res.writeHead(status, { 'Content-Type': MIME['.html'] });
  res.end(html);
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  })[c]);
}

async function readBody(req) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > 1e5) throw new Error('Body too large');
    chunks.push(chunk);
  }
  const raw = Buffer.concat(chunks).toString('utf8');
  const type = req.headers['content-type'] || '';
  if (type.includes('application/json')) return raw ? JSON.parse(raw) : {};
  if (type.includes('application/x-www-form-urlencoded')) {
    return Object.fromEntries(new URLSearchParams(raw));
  }
  return {};
}

async function serveStatic(res, dir, urlPath) {
  const rel = urlPath === '/' ? 'index.html' : decodeURIComponent(urlPath).replace(/^\/+/, '');
  const file = path.join(dir, rel);
  // Block "../" tricks that try to read files outside the folder.
  if (!file.startsWith(dir + path.sep)) return sendHtml(res, 403, 'Forbidden');
  try {
    const data = await fs.readFile(file);
    res.writeHead(200, { 'Content-Type': MIME[path.extname(file)] || 'application/octet-stream' });
    res.end(data);
  } catch {
    sendHtml(res, 404, 'Not found');
  }
}

function getSession(req) {
  const { sid } = parseCookies(req.headers.cookie);
  if (!sid) return null;
  const s = sessions.get(sid);
  if (!s) return null;
  if (Date.now() - s.createdAt > SESSION_TTL_SECONDS * 1000) {
    sessions.delete(sid); // expired on the server too, not just in the browser
    return null;
  }
  return { sid, ...s };
}

const ALLOWED_SAMESITE = ['Strict', 'Lax', 'None'];

// ---------- the real app (port 3000) ----------

const routes = {
  // What does the server actually receive? (includes HttpOnly cookies that JS can't see)
  'GET /api/echo': (req, res) => {
    sendJson(res, 200, {
      rawCookieHeader: req.headers.cookie || '(no Cookie header was sent)',
      parsed: parseCookies(req.headers.cookie),
    });
  },

  // Set any cookie from the server, with the attributes chosen in the playground.
  'POST /api/set': async (req, res) => {
    const b = await readBody(req);
    const opts = {
      path: b.path || '/',
      httpOnly: !!b.httpOnly,
      secure: !!b.secure,
      sameSite: ALLOWED_SAMESITE.includes(b.sameSite) ? b.sameSite : undefined,
    };
    if (b.maxAge !== '' && b.maxAge !== undefined) opts.maxAge = Number(b.maxAge);
    let header;
    try {
      header = serializeCookie(String(b.name || ''), String(b.value ?? ''), opts);
    } catch (err) {
      return sendJson(res, 400, { error: err.message });
    }
    sendJson(res, 200, { sentHeader: `Set-Cookie: ${header}` }, [header]);
  },

  'POST /api/clear': async (req, res) => {
    const b = await readBody(req);
    let header;
    try {
      header = clearCookie(String(b.name || ''), { path: b.path || '/' });
    } catch (err) {
      return sendJson(res, 400, { error: err.message });
    }
    sendJson(res, 200, { sentHeader: `Set-Cookie: ${header}` }, [header]);
  },

  // Signed cookie demo: a visit counter the user cannot fake.
  'GET /api/visits': (req, res) => {
    const raw = parseCookies(req.headers.cookie).visits;
    let count = 0;
    let note = 'No visits cookie yet, starting at 1.';
    if (raw) {
      const value = unsign(raw, SECRET);
      if (value === false) {
        note = 'Signature did NOT match: someone edited the cookie. Resetting to 1.';
      } else {
        count = Number(value) || 0;
        note = 'Signature is valid, so the server trusts the value.';
      }
    }
    count += 1;
    const header = serializeCookie('visits', sign(String(count), SECRET), {
      maxAge: 60 * 60 * 24 * 30,
      sameSite: 'Lax',
    });
    sendJson(res, 200, { visits: count, note, cookieValue: sign(String(count), SECRET) }, [header]);
  },

  // Login: create a NEW session id every time (stops session fixation),
  // put it in an HttpOnly cookie so JavaScript (and XSS) can't read it.
  'POST /api/login': async (req, res) => {
    const b = await readBody(req);
    const user = String(b.username || '').trim().slice(0, 40);
    if (!user) return sendJson(res, 400, { error: 'username is required' });

    const old = getSession(req);
    if (old) sessions.delete(old.sid);

    const sid = randomToken();
    const csrfToken = randomToken(24);
    sessions.set(sid, { user, csrfToken, balance: 10000, createdAt: Date.now() });

    // Let the learner pick SameSite to see CSRF succeed (None) or fail (Lax/Strict).
    const sameSite = ALLOWED_SAMESITE.includes(b.sameSite) ? b.sameSite : 'Lax';
    const header = serializeCookie('sid', sid, {
      httpOnly: true,
      // SameSite=None is only accepted together with Secure.
      // Browsers treat http://localhost as "secure", so this works locally.
      secure: sameSite === 'None',
      sameSite,
      maxAge: SESSION_TTL_SECONDS,
    });
    sendJson(res, 200, { ok: true, user, sentHeader: `Set-Cookie: ${header}` }, [header]);
  },

  'GET /api/me': (req, res) => {
    const s = getSession(req);
    if (!s) return sendJson(res, 401, { loggedIn: false });
    // The CSRF token is given to OUR page through a normal response.
    // An attacker site can send requests but can't READ this response (CORS).
    sendJson(res, 200, { loggedIn: true, user: s.user, balance: s.balance, csrfToken: s.csrfToken });
  },

  // UNSAFE: trusts the cookie alone. Any site can trigger this with a form.
  'POST /api/transfer-unsafe': async (req, res) => {
    const b = await readBody(req);
    const s = getSession(req);
    const fromForm = !(req.headers['content-type'] || '').includes('json');
    if (!s) {
      const msg = 'Blocked: no session cookie came with this request. ' +
        '(If you logged in with SameSite=Lax or Strict, the browser did not send it cross-site.)';
      return fromForm ? sendHtml(res, 401, resultPage('Transfer failed', msg, false))
        : sendJson(res, 401, { error: msg });
    }
    const amount = Math.max(0, Number(b.amount) || 0);
    sessions.get(s.sid).balance -= amount;
    const msg = `Sent ₹${amount} to "${b.to}". ${s.user}'s balance is now ₹${s.balance - amount}. ` +
      'This endpoint only checked the cookie, so a cross-site form was enough.';
    return fromForm ? sendHtml(res, 200, resultPage('Transfer done (CSRF worked!)', msg, true))
      : sendJson(res, 200, { ok: true, message: msg });
  },

  // SAFE: needs the cookie AND a CSRF token in a custom header.
  'POST /api/transfer-safe': async (req, res) => {
    const b = await readBody(req);
    const s = getSession(req);
    const fromForm = !(req.headers['content-type'] || '').includes('json');
    if (!s) {
      const msg = 'Blocked: not logged in (no session cookie).';
      return fromForm ? sendHtml(res, 401, resultPage('Transfer failed', msg, false))
        : sendJson(res, 401, { error: msg });
    }
    if (req.headers['x-csrf-token'] !== s.csrfToken) {
      const msg = 'Blocked: the cookie was there, but the CSRF token was missing or wrong. ' +
        'An attacker site cannot read our token, so it cannot pass this check.';
      return fromForm ? sendHtml(res, 403, resultPage('Transfer blocked', msg, false))
        : sendJson(res, 403, { error: msg });
    }
    const amount = Math.max(0, Number(b.amount) || 0);
    sessions.get(s.sid).balance -= amount;
    sendJson(res, 200, { ok: true, message: `Sent ₹${amount} to "${b.to}". Balance: ₹${s.balance - amount}` });
  },

  'POST /api/logout': (req, res) => {
    const s = getSession(req);
    if (s) sessions.delete(s.sid); // kill it on the server, not only in the browser
    const header = clearCookie('sid', { path: '/' });
    sendJson(res, 200, { ok: true, sentHeader: `Set-Cookie: ${header}` }, [header]);
  },
};

function resultPage(title, message, bad) {
  return `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(title)}</title>
<style>body{font:16px/1.6 system-ui,sans-serif;max-width:640px;margin:40px auto;padding:0 16px;background:#fff;color:#1a1a1a}
.box{padding:16px;border-radius:10px;border:1px solid ${bad ? '#e5484d' : '#30a46c'};background:${bad ? '#fff1f1' : '#effaf3'}}
@media (prefers-color-scheme: dark){body{background:#111;color:#eee}.box{background:${bad ? '#2a1314' : '#11251a'}}}</style>
<h1>${escapeHtml(title)}</h1><div class="box">${escapeHtml(message)}</div>
<p><a href="http://localhost:${APP_PORT}/auth.html">Back to the bank (auth demo)</a></p>`;
}

const app = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const handler = routes[`${req.method} ${url.pathname}`];
  try {
    if (handler) return await handler(req, res);
    if (req.method === 'GET') return await serveStatic(res, CLIENT_DIR, url.pathname);
    sendJson(res, 404, { error: 'Not found' });
  } catch (err) {
    sendJson(res, 400, { error: err.message });
  }
});

// ---------- the attacker site (port 3001) ----------

const attacker = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  if (url.pathname === '/' || url.pathname === '/attacker.html') {
    const html = await fs.readFile(path.join(__dirname, 'attacker.html'), 'utf8');
    return sendHtml(res, 200, html);
  }
  sendHtml(res, 404, 'Not found');
});

app.listen(APP_PORT, () => {
  console.log(`App (bank):     http://localhost:${APP_PORT}`);
});
attacker.listen(ATTACKER_PORT, '127.0.0.1', () => {
  console.log(`Attacker site:  http://127.0.0.1:${ATTACKER_PORT}`);
});
