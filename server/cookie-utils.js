// Small cookie helpers written from scratch (no npm packages), so you can see
// exactly what libraries like `cookie` / `cookie-parser` do under the hood.
import crypto from 'node:crypto';

// "Cookie: a=1; b=hello%20world"  ->  { a: '1', b: 'hello world' }
export function parseCookies(header = '') {
  const out = {};
  for (const part of header.split(';')) {
    const i = part.indexOf('=');
    if (i === -1) continue;
    const name = part.slice(0, i).trim();
    const raw = part.slice(i + 1).trim();
    if (!name || name in out) continue; // first one wins (most specific path comes first)
    try {
      out[name] = decodeURIComponent(raw);
    } catch {
      out[name] = raw;
    }
  }
  return out;
}

// Build one Set-Cookie header value.
// serializeCookie('sid', 'abc', { httpOnly: true, sameSite: 'Lax', maxAge: 3600 })
//   -> "sid=abc; Max-Age=3600; Path=/; HttpOnly; SameSite=Lax"
export function serializeCookie(name, value, opts = {}) {
  if (!/^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/.test(name)) {
    throw new Error(`Invalid cookie name: ${name}`);
  }
  const parts = [`${name}=${encodeURIComponent(value)}`];
  if (opts.maxAge !== undefined) parts.push(`Max-Age=${Math.floor(opts.maxAge)}`);
  if (opts.expires) parts.push(`Expires=${opts.expires.toUTCString()}`);
  if (opts.domain) parts.push(`Domain=${opts.domain}`);
  parts.push(`Path=${opts.path || '/'}`);
  if (opts.secure) parts.push('Secure');
  if (opts.httpOnly) parts.push('HttpOnly');
  if (opts.sameSite) parts.push(`SameSite=${opts.sameSite}`);
  if (opts.partitioned) parts.push('Partitioned');
  return parts.join('; ');
}

// Deleting a cookie = sending it again with the SAME name + path (+ domain)
// and an expiry in the past.
export function clearCookie(name, opts = {}) {
  return serializeCookie(name, '', { ...opts, maxAge: 0, expires: new Date(0) });
}

// Signed cookie: "value.signature". The browser can still READ the value,
// but if anyone changes it, the signature no longer matches.
// Signing is NOT encryption: never put secrets in a signed cookie.
export function sign(value, secret) {
  const mac = crypto.createHmac('sha256', secret).update(value).digest('base64url');
  return `${value}.${mac}`;
}

export function unsign(signed, secret) {
  const i = signed.lastIndexOf('.');
  if (i === -1) return false;
  const value = signed.slice(0, i);
  const expected = Buffer.from(sign(value, secret));
  const given = Buffer.from(signed);
  // timingSafeEqual stops attackers guessing the signature byte by byte
  if (expected.length !== given.length || !crypto.timingSafeEqual(expected, given)) {
    return false;
  }
  return value;
}

export function randomToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString('base64url');
}
