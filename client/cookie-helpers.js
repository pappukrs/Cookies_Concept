// Browser-side cookie helpers. Everything goes through `document.cookie`,
// which is a strange API:
//   - READING it gives ONE string with all visible cookies: "a=1; b=2"
//     (no attributes, no HttpOnly cookies).
//   - WRITING it sets or updates ONE cookie. It does NOT replace the others.

export function getAllCookies() {
  if (!document.cookie) return {};
  return Object.fromEntries(
    document.cookie.split('; ').map((pair) => {
      const i = pair.indexOf('=');
      const name = pair.slice(0, i);
      const value = pair.slice(i + 1);
      try {
        return [name, decodeURIComponent(value)];
      } catch {
        return [name, value];
      }
    }),
  );
}

export function getCookie(name) {
  return getAllCookies()[name] ?? null;
}

// setCookie('theme', 'dark', { maxAge: 7 * 24 * 3600, sameSite: 'Lax' })
export function setCookie(name, value, opts = {}) {
  let str = `${name}=${encodeURIComponent(value)}`;
  if (opts.maxAge !== undefined) str += `; max-age=${opts.maxAge}`;
  if (opts.expires) str += `; expires=${opts.expires.toUTCString()}`;
  str += `; path=${opts.path || '/'}`;
  if (opts.domain) str += `; domain=${opts.domain}`;
  if (opts.secure) str += '; secure';
  if (opts.sameSite) str += `; samesite=${opts.sameSite}`;
  // NOTE: you can't add "HttpOnly" here. Only the server can set HttpOnly cookies.
  document.cookie = str;
  return str;
}

// Delete = set it again with the same name + path, already expired.
export function deleteCookie(name, path = '/') {
  document.cookie = `${name}=; max-age=0; path=${path}`;
}
