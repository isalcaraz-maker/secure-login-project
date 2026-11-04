import http from 'node:http';
import https from 'node:https';
import { readFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
import { equalText, token, validateCredentials, verifyCredentials } from './auth.mjs';
import { landingPage, loginPage, messagePage } from './views.mjs';

const DEFAULTS = Object.freeze({
  requestCount: 120, requestWindow: 60_000,
  loginCount: 10, loginWindow: 15 * 60_000,
  globalLoginCount: 60, globalLoginWindow: 15 * 60_000,
  idle: 15 * 60_000, absolute: 60 * 60_000, preauth: 10 * 60_000,
  maxSessions: 2048, maxIPs: 4096, maxHashes: 2,
});

function statusError(status) { return Object.assign(new Error('Request rejected'), { status }); }

function getCookie(req, name) {
  const matches = (req.headers.cookie ?? '').split(';').map(s => s.trim()).filter(s => s.startsWith(name + '='));
  // Duplicate cookies and invalid tokens fail closed.
  if (matches.length !== 1) return null;
  const value = matches[0].slice(name.length + 1);
  return /^[A-Za-z0-9_-]{43}$/.test(value) ? value : null;
}

function readForm(req) {
  if (!/^application\/x-www-form-urlencoded(?:\s*;\s*charset=utf-8)?$/i.test(req.headers['content-type'] ?? '')) {
    throw statusError(415);
  }
  if (Number(req.headers['content-length'] ?? 0) > 4096) throw statusError(413);
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    const timer = setTimeout(() => finish(statusError(408)), 5000);
    function finish(error, result) {
      clearTimeout(timer);
      req.off('data', onData); req.off('end', onEnd); req.off('error', onError); req.off('aborted', onAbort);
      if (error) { req.resume(); reject(error); } else resolve(result);
    }
    function onData(chunk) {
      size += chunk.length;
      if (size > 4096) return finish(statusError(413));
      chunks.push(chunk);
    }
    function onEnd() { finish(null, new URLSearchParams(Buffer.concat(chunks).toString('utf8'))); }
    function onError() { finish(statusError(400)); }
    function onAbort() { finish(statusError(400)); }
    req.on('data', onData); req.once('end', onEnd); req.once('error', onError); req.once('aborted', onAbort);
  });
}

function validFields(form, names) {
  return [...form.keys()].length === names.length && names.every(name => form.getAll(name).length === 1);
}

export async function createApplication({ credentials, origin, development = false, now = Date.now, limits = {} }) {
  validateCredentials(credentials);
  const site = new URL(origin);
  if (site.origin !== origin || site.username || site.password || site.pathname !== '/' || site.search || site.hash) {
    throw new Error('APP_ORIGIN must be an exact origin, without a trailing slash, path, credentials or query.');
  }
  if (development) {
    if (site.protocol !== 'http:' || !['localhost', '127.0.0.1'].includes(site.hostname)) throw new Error('Development mode is restricted to local HTTP.');
  } else if (site.protocol !== 'https:') throw new Error('HTTPS is required outside development.');
  const policy = { ...DEFAULTS, ...limits };
  const cookieName = development ? 'dev_session' : '__Host-session';
  const sessions = new Map();
  const requests = new Map();
  const attempts = new Map();
  let globalAttempts = { count: 0, until: 0 };
  let activeHashes = 0;
  const css = await readFile(new URL('./styles.css', import.meta.url), 'utf8');

  function sweep(time) {
    for (const [id, session] of sessions) {
      if (time - session.created >= (session.authenticated ? policy.absolute : policy.preauth)
          || (session.authenticated && time - session.lastSeen >= policy.idle)) sessions.delete(id);
    }
    for (const map of [requests, attempts]) for (const [ip, bucket] of map) if (time >= bucket.until) map.delete(ip);
  }
  function take(map, ip, count, window, time) {
    let bucket = map.get(ip);
    if (!bucket || time >= bucket.until) {
      if (!bucket && map.size >= policy.maxIPs) return window;
      bucket = { count: 0, until: time + window }; map.set(ip, bucket);
    }
    if (bucket.count >= count) return bucket.until - time;
    bucket.count++;
    return 0;
  }
  function writeCookie(res, id, authenticated) {
    const maxAge = authenticated ? policy.absolute : policy.preauth;
    res.setHeader('Set-Cookie', `${cookieName}=${id}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${Math.ceil(maxAge / 1000)}${development ? '' : '; Secure'}`);
  }
  function issueSession(res, authenticated, time) {
    if (sessions.size >= policy.maxSessions) throw statusError(503);
    const id = token();
    const session = { authenticated, csrf: token(), created: time, lastSeen: time };
    sessions.set(id, session); writeCookie(res, id, authenticated);
    return session;
  }

  return async function handler(req, res) {
    const time = now();
    const send = (status, body, type = 'text/html; charset=utf-8') => {
      res.statusCode = status;
      res.setHeader('Content-Type', type);
      res.setHeader('Content-Length', Buffer.byteLength(body));
      res.end(req.method === 'HEAD' ? undefined : body);
    };
    const redirect = location => { res.setHeader('Location', location); send(303, ''); };
    const reject = (status, title, text) => send(status, messagePage(title, text));
    const throttle = delay => { res.setHeader('Retry-After', Math.max(1, Math.ceil(delay / 1000))); reject(429, 'Please wait', 'Too many requests. Please try again later.'); };
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Content-Security-Policy', "default-src 'none'; style-src 'self'; img-src data:; form-action 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'");
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
    res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
    if (!development) res.setHeader('Strict-Transport-Security', 'max-age=31536000');
    try {
      // Never trust X-Forwarded-For or a browser-supplied login flag.
      if (!development && !req.socket.encrypted) return reject(400, 'HTTPS required', 'Use the HTTPS address.');
      if (req.headers.host !== site.host) return reject(400, 'Invalid request', 'The requested host is not allowed.');
      if (!req.url?.startsWith('/') || req.url.startsWith('//') || req.url.includes('\\')) throw statusError(400);
      const path = new URL(req.url, site).pathname;
      if (!['GET', 'HEAD', 'POST'].includes(req.method)) {
        res.setHeader('Allow', 'GET, HEAD, POST'); return reject(405, 'Method not allowed', 'This request method is not supported.');
      }
      sweep(time);
      const ip = req.socket.remoteAddress ?? 'unknown';
      const requestDelay = take(requests, ip, policy.requestCount, policy.requestWindow, time);
      if (requestDelay) return throttle(requestDelay);

      if (req.method === 'POST') {
        if (req.headers.origin !== site.origin || (req.headers['sec-fetch-site'] && req.headers['sec-fetch-site'] !== 'same-origin')) {
          return reject(403, 'Request rejected', 'Reload the sign-in page and try again.');
        }
      }
      const id = getCookie(req, cookieName);
      const session = id ? sessions.get(id) : undefined;

      if (['GET', 'HEAD'].includes(req.method)) {
        if (path === '/styles.css') return send(200, css, 'text/css; charset=utf-8');
        if (path === '/') return redirect(session?.authenticated ? '/landing' : '/login');
        if (path === '/login') {
          if (session?.authenticated) return redirect('/landing');
          const preauth = session ?? issueSession(res, false, time);
          return send(200, loginPage(preauth.csrf));
        }
        if (path === '/landing') {
          if (!session?.authenticated) return redirect('/login');
          session.lastSeen = time;
          return send(200, landingPage(credentials.username, session.csrf));
        }
        // No generic static-file serving: source, configuration and templates stay private.
        return reject(404, 'Page not found', 'This page is unavailable.');
      }

      if (path !== '/login' && path !== '/logout') return reject(404, 'Page not found', 'This page is unavailable.');
      const form = await readForm(req);
      const names = path === '/login' ? ['username', 'password', 'csrf'] : ['csrf'];
      if (!validFields(form, names)) throw statusError(400);
      if (!session || !equalText(form.get('csrf'), session.csrf)) return reject(403, 'Request rejected', 'Reload the sign-in page and try again.');

      if (path === '/logout') {
        if (!session.authenticated) return redirect('/login');
        sessions.delete(id);
        res.setHeader('Set-Cookie', `${cookieName}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0${development ? '' : '; Secure'}`);
        return redirect('/login');
      }
      if (session.authenticated) return redirect('/landing');
      const username = form.get('username');
      const password = form.get('password');
      if (!username || Buffer.byteLength(username) > 64 || !password || Buffer.byteLength(password) > 512) throw statusError(400);
      const loginDelay = take(attempts, ip, policy.loginCount, policy.loginWindow, time);
      if (loginDelay) return throttle(loginDelay);
      if (time >= globalAttempts.until) globalAttempts = { count: 0, until: time + policy.globalLoginWindow };
      if (globalAttempts.count >= policy.globalLoginCount) return throttle(globalAttempts.until - time);
      globalAttempts.count++;
      if (activeHashes >= policy.maxHashes) return reject(503, 'Please retry', 'The sign-in service is busy. Please try again shortly.');
      activeHashes++;
      let valid;
      try { valid = await verifyCredentials(credentials, username, password); }
      finally { activeHashes--; }
      // Re-check expiry and concurrent logout/login after the asynchronous hash operation.
      const completed = now();
      if (sessions.get(id) !== session || completed - session.created >= policy.preauth) {
        return reject(403, 'Request rejected', 'Reload the sign-in page and try again.');
      }
      if (!valid) return send(401, loginPage(session.csrf, 'Invalid username or password.'));
      sessions.delete(id);
      issueSession(res, true, completed); // Fresh identifier defeats session fixation.
      return redirect('/landing');
    } catch (error) {
      if (res.destroyed || res.writableEnded) return;
      res.setHeader('Connection', 'close');
      if (error.status) return reject(error.status, 'Request rejected', 'Reload the sign-in page and try again.');
      console.error('An internal request error occurred.'); // Never print credentials, cookies or form bodies.
      return reject(500, 'Unable to continue', 'Please try again later.');
    }
  };
}

export async function start() {
  const development = process.argv.includes('--dev');
  const port = Number(process.env.PORT ?? (development ? 3000 : 3443));
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('PORT must be 1–65535.');
  const origin = process.env.APP_ORIGIN ?? (development ? `http://localhost:${port}` : '');
  if (!origin) throw new Error('Set APP_ORIGIN to your exact HTTPS origin. See README.md.');
  const credentials = JSON.parse(await readFile(new URL('./.auth-config.json', import.meta.url), 'utf8'));
  const handler = await createApplication({ credentials, origin, development });
  let server;
  if (development) {
    server = http.createServer({ maxHeaderSize: 8192 }, handler);
  } else {
    if (!process.env.TLS_KEY || !process.env.TLS_CERT) throw new Error('TLS_KEY and TLS_CERT are required. See README.md.');
    const [key, cert] = await Promise.all([readFile(process.env.TLS_KEY), readFile(process.env.TLS_CERT)]);
    server = https.createServer({ key, cert, minVersion: 'TLSv1.3', maxHeaderSize: 8192 }, handler);
  }
  server.requestTimeout = 10_000;
  server.headersTimeout = 10_000;
  server.timeout = 15_000;
  server.keepAliveTimeout = 5000;
  server.maxRequestsPerSocket = 100;
  const host = development ? '127.0.0.1' : (process.env.HOST ?? '127.0.0.1');
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(port, host, resolve); });
  console.log(`${development ? 'LOCAL DEVELOPMENT ONLY' : 'HTTPS server'}: ${origin}`);
  const shutdown = () => { server.close(); server.closeAllConnections(); };
  process.once('SIGINT', shutdown); process.once('SIGTERM', shutdown);
  return server;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  start().catch(error => { console.error(`Startup failed: ${error.message}`); process.exitCode = 1; });
}
