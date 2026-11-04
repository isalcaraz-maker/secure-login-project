import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import https from 'node:https';
import { once } from 'node:events';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';
import { createApplication } from '../server.mjs';
import { createCredentials, verifyCredentials } from '../auth.mjs';

const USER = 'classroom_team';
const PASSWORD = 'Test-only-long-passphrase-6u5wN2';
let credentials;
before(async () => { credentials = await createCredentials(USER, PASSWORD); });

async function fixture(t, { limits, clock } = {}) {
  let handler;
  const server = http.createServer((req, res) => handler(req, res));
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const origin = `http://127.0.0.1:${server.address().port}`;
  handler = await createApplication({ credentials, origin, development: true, limits, now: clock });
  t.after(() => new Promise(resolve => { server.close(resolve); server.closeAllConnections(); }));
  const request = (path, options = {}) => fetch(origin + path, { redirect: 'manual', ...options });
  async function preauth() {
    const response = await request('/login');
    assert.equal(response.status, 200);
    const cookie = response.headers.get('set-cookie').split(';')[0];
    const csrf = (await response.text()).match(/name="csrf" value="([A-Za-z0-9_-]+)"/)[1];
    return { cookie, csrf };
  }
  const post = (path, data, cookie, headers = {}) => request(path, {
    method: 'POST', body: new URLSearchParams(data),
    headers: { Origin: origin, Cookie: cookie ?? '', ...headers },
  });
  async function login() {
    const pre = await preauth();
    const response = await post('/login', { username: USER, password: PASSWORD, csrf: pre.csrf }, pre.cookie);
    assert.equal(response.status, 303);
    return { pre, response, cookie: response.headers.get('set-cookie').split(';')[0] };
  }
  return { request, preauth, post, login, origin };
}

test('Argon2id accepts the correct password and rejects incorrect credentials', async () => {
  assert.equal(await verifyCredentials(credentials, USER, PASSWORD), true);
  assert.equal(await verifyCredentials(credentials, USER, 'wrong-password'), false);
  assert.equal(await verifyCredentials(credentials, 'unknown-user', PASSWORD), false);
  const other = await createCredentials(USER, PASSWORD);
  assert.notEqual(other.salt, credentials.salt);
  assert.notEqual(other.hash, credentials.hash);
  assert.equal(JSON.stringify(credentials).includes(PASSWORD), false);
});

test('private landing content is never sent before authentication', async t => {
  const app = await fixture(t);
  for (const path of ['/landing', '/landing?authenticated=true', '/landing?user=admin', '/%2e%2e/landing']) {
    const response = await app.request(path);
    assert.equal(response.status, 303);
    assert.equal(response.headers.get('location'), '/login');
    assert.equal((await response.text()).includes('Make yourself at home'), false);
  }
});

test('configuration, source, templates and guessed static landing files are unavailable', async t => {
  const app = await fixture(t);
  for (const path of ['/.auth-config.json', '/server.mjs', '/auth.mjs', '/views.mjs', '/README.md', '/landing.html', '/package.json', '/certs/server-key.pem', '/.git/config']) {
    const response = await app.request(path);
    assert.equal(response.status, 404, path);
    assert.equal((await response.text()).includes(credentials.hash), false);
  }
});

test('forged cookies and client login flags do not authenticate', async t => {
  const app = await fixture(t);
  for (const cookie of ['dev_session=' + 'A'.repeat(43), 'authenticated=true; admin=true', 'dev_session=../../server.mjs']) {
    assert.equal((await app.request('/landing', { headers: { Cookie: cookie } })).status, 303);
  }
});

test('successful login rotates the session and permits access', async t => {
  const app = await fixture(t);
  const { pre, cookie, response } = await app.login();
  assert.notEqual(cookie, pre.cookie);
  assert.equal(response.headers.get('location'), '/landing');
  const page = await app.request('/landing', { headers: { Cookie: cookie } });
  assert.equal(page.status, 200);
  assert.match(await page.text(), /Make yourself at home/);
  assert.equal((await app.request('/landing', { headers: { Cookie: pre.cookie } })).status, 303);
});

test('wrong username/password and injection-looking credentials fail with the same response', async t => {
  const app = await fixture(t);
  const pre = await app.preauth();
  const outputs = [];
  for (const [username, password] of [[USER, 'wrong'], ['unknown', PASSWORD], ["' OR 1=1 --", PASSWORD], ['<script>alert(1)</script>', PASSWORD]]) {
    const response = await app.post('/login', { username, password, csrf: pre.csrf }, pre.cookie);
    assert.equal(response.status, 401);
    outputs.push(await response.text());
    assert.equal(response.headers.has('set-cookie'), false);
  }
  assert.equal(new Set(outputs).size, 1);
});

test('login rejects missing or wrong CSRF tokens', async t => {
  const app = await fixture(t);
  const pre = await app.preauth();
  assert.equal((await app.post('/login', { username: USER, password: PASSWORD }, pre.cookie)).status, 400);
  assert.equal((await app.post('/login', { username: USER, password: PASSWORD, csrf: 'bad' }, pre.cookie)).status, 403);
  assert.equal((await app.post('/login', { username: USER, password: PASSWORD, csrf: pre.csrf }, '')).status, 403);
});

test('login rejects missing/cross-site origins and cross-site fetch metadata', async t => {
  const app = await fixture(t);
  const pre = await app.preauth();
  const data = { username: USER, password: PASSWORD, csrf: pre.csrf };
  for (const headers of [{ Origin: '' }, { Origin: 'https://attacker.invalid' }, { 'Sec-Fetch-Site': 'cross-site' }]) {
    assert.equal((await app.post('/login', data, pre.cookie, headers)).status, 403);
  }
});

test('duplicate form fields, unexpected fields and oversized input are rejected', async t => {
  const app = await fixture(t);
  const pre = await app.preauth();
  const fields = [['username', USER], ['password', PASSWORD], ['csrf', pre.csrf]];
  for (const data of [[...fields, ['username', 'admin']], [...fields, ['authenticated', 'true']]]) {
    assert.equal((await app.post('/login', data, pre.cookie)).status, 400);
  }
  assert.equal((await app.post('/login', { username: USER, password: 'a'.repeat(600), csrf: pre.csrf }, pre.cookie)).status, 400);
  assert.equal((await app.post('/login', { username: USER, password: 'a'.repeat(5000), csrf: pre.csrf }, pre.cookie)).status, 413);
  assert.equal((await app.request('/login', { method: 'POST', body: '{}', headers: { Origin: app.origin, 'Content-Type': 'application/json' } })).status, 415);
});

test('chunked requests cannot bypass the body size limit', async t => {
  const app = await fixture(t);
  const status = await new Promise((resolve, reject) => {
    const req = http.request(app.origin + '/login', { method: 'POST', headers: { Origin: app.origin, 'Content-Type': 'application/x-www-form-urlencoded' } }, res => {
      res.resume(); res.on('end', () => resolve(res.statusCode));
    });
    req.on('error', reject); req.write('password='); req.end('x'.repeat(5000));
  });
  assert.equal(status, 413);
});

test('duplicate session cookies fail closed', async t => {
  const app = await fixture(t);
  const { cookie } = await app.login();
  assert.equal((await app.request('/landing', { headers: { Cookie: `${cookie}; ${cookie}` } })).status, 303);
});

test('logout requires CSRF and invalidates the server-side session', async t => {
  const app = await fixture(t);
  const { cookie } = await app.login();
  assert.equal((await app.post('/logout', { csrf: 'bad' }, cookie)).status, 403);
  const page = await app.request('/landing', { headers: { Cookie: cookie } });
  const csrf = (await page.text()).match(/name="csrf" value="([A-Za-z0-9_-]+)"/)[1];
  const response = await app.post('/logout', { csrf }, cookie);
  assert.equal(response.status, 303);
  assert.match(response.headers.get('set-cookie'), /Max-Age=0/);
  assert.equal((await app.request('/landing', { headers: { Cookie: cookie } })).status, 303);
});

test('idle expiry and absolute expiry block previously valid sessions', async t => {
  let time = 1_000_000;
  const app = await fixture(t, { clock: () => time, limits: { idle: 1000, absolute: 2500 } });
  let { cookie } = await app.login();
  time += 1001;
  assert.equal((await app.request('/landing', { headers: { Cookie: cookie } })).status, 303);
  ({ cookie } = await app.login());
  for (let i = 0; i < 3; i++) {
    time += 800;
    assert.equal((await app.request('/landing', { headers: { Cookie: cookie } })).status, 200);
  }
  time += 101;
  assert.equal((await app.request('/landing', { headers: { Cookie: cookie } })).status, 303);
});

test('expired pre-login session cannot be used to authenticate', async t => {
  let time = 1_000_000;
  const app = await fixture(t, { clock: () => time, limits: { preauth: 1000 } });
  const pre = await app.preauth();
  time += 1001;
  assert.equal((await app.post('/login', { username: USER, password: PASSWORD, csrf: pre.csrf }, pre.cookie)).status, 403);
});

test('per-IP login limit survives new cookies and spoofed forwarded addresses', async t => {
  let time = 1_000_000;
  const app = await fixture(t, { clock: () => time, limits: { loginCount: 2, loginWindow: 1000 } });
  for (let i = 0; i < 2; i++) {
    const pre = await app.preauth();
    assert.equal((await app.post('/login', { username: USER, password: 'wrong', csrf: pre.csrf }, pre.cookie, { 'X-Forwarded-For': `10.0.0.${i}` })).status, 401);
  }
  let pre = await app.preauth();
  const blocked = await app.post('/login', { username: USER, password: PASSWORD, csrf: pre.csrf }, pre.cookie, { 'X-Forwarded-For': '8.8.8.8' });
  assert.equal(blocked.status, 429);
  assert.ok(Number(blocked.headers.get('retry-after')) >= 1);
  time += 1001;
  pre = await app.preauth();
  assert.equal((await app.post('/login', { username: USER, password: PASSWORD, csrf: pre.csrf }, pre.cookie)).status, 303);
});

test('global login budget limits attempts across the application', async t => {
  const app = await fixture(t, { limits: { loginCount: 100, globalLoginCount: 1 } });
  const pre = await app.preauth();
  const data = { username: USER, password: 'wrong', csrf: pre.csrf };
  assert.equal((await app.post('/login', data, pre.cookie)).status, 401);
  assert.equal((await app.post('/login', data, pre.cookie)).status, 429);
});

test('request rate limit applies beyond the login endpoint', async t => {
  const app = await fixture(t, { limits: { requestCount: 2 } });
  assert.equal((await app.request('/styles.css')).status, 200);
  assert.equal((await app.request('/does-not-exist')).status, 404);
  assert.equal((await app.request('/landing')).status, 429);
});

test('bounded session store refuses additional sessions without evicting a logged-in user', async t => {
  const app = await fixture(t, { limits: { maxSessions: 1 } });
  const { cookie } = await app.login();
  assert.equal((await app.request('/login')).status, 503);
  assert.equal((await app.request('/landing', { headers: { Cookie: cookie } })).status, 200);
});

test('password hashing concurrency is bounded under parallel attempts', async t => {
  const app = await fixture(t, { limits: { maxHashes: 1 } });
  const a = await app.preauth(); const b = await app.preauth();
  const responses = await Promise.all([a, b].map(pre => app.post('/login', { username: USER, password: 'wrong', csrf: pre.csrf }, pre.cookie)));
  assert.deepEqual(responses.map(r => r.status).sort(), [401, 503]);
});

test('security headers and cookie flags are present', async t => {
  const app = await fixture(t);
  const response = await app.request('/login');
  assert.match(response.headers.get('content-security-policy'), /default-src 'none'/);
  assert.match(response.headers.get('content-security-policy'), /frame-ancestors 'none'/);
  assert.equal(response.headers.get('cache-control'), 'no-store');
  assert.equal(response.headers.get('x-content-type-options'), 'nosniff');
  assert.equal(response.headers.get('referrer-policy'), 'no-referrer');
  assert.match(response.headers.get('set-cookie'), /HttpOnly/);
  assert.match(response.headers.get('set-cookie'), /SameSite=Strict/);
});

test('HEAD does not leak private content and unsupported methods are rejected', async t => {
  const app = await fixture(t);
  const response = await app.request('/landing', { method: 'HEAD' });
  assert.equal(response.status, 303);
  assert.equal(await response.text(), '');
  assert.equal((await app.request('/landing', { method: 'PUT' })).status, 405);
});

test('unrecognized Host header is rejected', async t => {
  const app = await fixture(t);
  const status = await new Promise((resolve, reject) => {
    http.get(app.origin + '/login', { headers: { Host: 'attacker.invalid' } }, res => {
      res.resume(); res.on('end', () => resolve(res.statusCode));
    }).on('error', reject);
  });
  assert.equal(status, 400);
});

test('production refuses insecure origins and unencrypted connections', async t => {
  await assert.rejects(createApplication({ credentials, origin: 'http://example.com' }), /HTTPS/);
  await assert.rejects(createApplication({ credentials, origin: 'http://example.com', development: true }), /local HTTP/);
  await assert.rejects(createApplication({ credentials, origin: 'https://example.com/' }), /exact origin/);
  const handler = await createApplication({ credentials, origin: 'https://example.com' });
  const server = http.createServer(handler);
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(() => new Promise(resolve => { server.close(resolve); server.closeAllConnections(); }));
  const response = await fetch(`http://127.0.0.1:${server.address().port}/login`, { headers: { Host: 'example.com' } });
  assert.equal(response.status, 400);
});

test('real HTTPS uses Secure host-only cookies and protects the landing page', async t => {
  const dir = await mkdtemp(join(dirname(fileURLToPath(import.meta.url)), 'tmp-tls-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const keyPath = join(dir, 'key.pem'); const certPath = join(dir, 'cert.pem');
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', keyPath, '-out', certPath, '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1'], { stdio: 'ignore' });
  const [key, cert] = await Promise.all([readFile(keyPath), readFile(certPath)]);
  let handler;
  const server = https.createServer({ key, cert, minVersion: 'TLSv1.3' }, (req, res) => handler(req, res));
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(() => new Promise(resolve => { server.close(resolve); server.closeAllConnections(); }));
  const origin = `https://127.0.0.1:${server.address().port}`;
  handler = await createApplication({ credentials, origin });
  const request = (path, options = {}, body) => new Promise((resolve, reject) => {
    // Explicitly trust this temporary test certificate; verification remains enabled.
    const req = https.request(origin + path, { ca: cert, ...options }, res => {
      let text = ''; res.on('data', chunk => { text += chunk; });
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, text }));
    });
    req.on('error', reject); req.end(body);
  });
  const pre = await request('/login');
  const preCookie = pre.headers['set-cookie'][0].split(';')[0];
  assert.match(pre.headers['set-cookie'][0], /^__Host-session=/);
  assert.match(pre.headers['set-cookie'][0], /; Secure/);
  assert.equal(pre.headers['strict-transport-security'], 'max-age=31536000');
  const csrf = pre.text.match(/name="csrf" value="([A-Za-z0-9_-]+)"/)[1];
  const body = new URLSearchParams({ username: USER, password: PASSWORD, csrf }).toString();
  const loggedIn = await request('/login', { method: 'POST', headers: { Origin: origin, Cookie: preCookie, 'Content-Type': 'application/x-www-form-urlencoded' } }, body);
  assert.equal(loggedIn.status, 303);
  const cookie = loggedIn.headers['set-cookie'][0].split(';')[0];
  assert.equal((await request('/landing', { headers: { Cookie: cookie } })).status, 200);
  assert.equal((await request('/landing')).status, 303);
});
