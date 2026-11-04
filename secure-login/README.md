# Haven — JavaScript login with a protected landing page

A complete, single-account Node.js application for your classroom defense exercise. It uses JavaScript, HTML and CSS, with no database or third-party npm packages.

**This must run on a backend server.** Pasting a script into public HTML cannot protect another public HTML file. The server in this project checks authorization before sending any landing-page content.

## 1. Requirements

- An up-to-date Node.js release with native `crypto.argon2` support: **24.7.0 or newer**. Check using `node --version`.
- A terminal in the extracted `secure-login` folder. VS Code's integrated terminal works.
- OpenSSL for the automated HTTPS test and the optional local certificate example. Kali Linux / WSL is suitable.

There are no packages to install. Do not open an HTML file directly or use VS Code Live Server for this project.

## 2. Create your private account

```bash
npm run setup -- mygroup
```

This generates a random 32-character password and displays it once. Save it privately; do not send it to the attacking team. The username in this example is `mygroup`.

Only the username, random salt, Argon2id parameters and password hash are saved in `.auth-config.json`. That file is never available through a website route. Keep it on the server, outside any separately hosted public directory. File mode `0600` is requested on creation; on Windows, restrict its filesystem permissions to the server account.

Setup refuses to overwrite an existing account. To rotate credentials, stop the server, securely remove the old `.auth-config.json`, run setup again and restart the server. Restarting also invalidates all sessions.

## 3. Preview on your own computer

```bash
npm run dev
```

Open **http://localhost:3000/login** using that exact hostname. Sign in with the generated credentials. You should reach `/landing`.

Local development uses HTTP and a development cookie. It binds only to `127.0.0.1`. **Use the HTTPS mode below for the attacking team's network access.** Do not expose development mode through a tunnel or public forwarding service.

To confirm the landing page is protected, open an incognito window and enter `http://localhost:3000/landing` directly. It should redirect to sign-in without sending the private content.

## 4. Run the classroom website over HTTPS

This application serves HTTPS itself. Obtain a certificate and its private key for your actual domain or classroom server IP. Use a browser-trusted certificate, or have the classroom administrator distribute and trust the class certificate authority. The certificate must include the exact hostname or IP that students will visit.

Set these environment variables before starting:

| Variable | Example | Meaning |
| --- | --- | --- |
| `APP_ORIGIN` | `https://your-class-domain.example:3443` | Exact public origin, including a non-default port; no trailing slash |
| `PORT` | `3443` | Port Node listens on |
| `HOST` | `0.0.0.0` | Listen on the classroom network; otherwise defaults to loopback |
| `TLS_KEY` | `/absolute/path/server-key.pem` | Private key file |
| `TLS_CERT` | `/absolute/path/server-cert.pem` | Certificate / certificate-chain file |

Bash / Kali / WSL example — replace the example domain and file paths first:

```bash
export APP_ORIGIN='https://your-class-domain.example:3443'
export PORT='3443'
export HOST='0.0.0.0'
export TLS_KEY='/absolute/path/server-key.pem'
export TLS_CERT='/absolute/path/server-cert.pem'
npm start
```

PowerShell equivalent:

```powershell
$env:APP_ORIGIN = 'https://your-class-domain.example:3443'
$env:PORT = '3443'
$env:HOST = '0.0.0.0'
$env:TLS_KEY = 'C:\private\server-key.pem'
$env:TLS_CERT = 'C:\private\server-cert.pem'
npm start
```

For a local HTTPS exercise, this OpenSSL example creates a self-signed certificate for `localhost` and `127.0.0.1`. It does **not** cover a classroom LAN IP:

```bash
mkdir -p certs
openssl req -x509 -newkey rsa:3072 -nodes -keyout certs/server-key.pem -out certs/server-cert.pem -days 7 -subj '/CN=localhost' -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1'
chmod 600 certs/server-key.pem
export APP_ORIGIN='https://localhost:3443'
export TLS_KEY='./certs/server-key.pem'
export TLS_CERT='./certs/server-cert.pem'
npm start
```

Have the administrator configure trust for the exercise certificate. Certificate validation should remain enabled. Never share or commit the private key.

**Hosting:** use one persistent Node.js process. This implementation does not include a reverse-proxy mode and will reject unencrypted backend requests in HTTPS mode. It is not a static hosting / GitHub Pages / serverless deployment. If your school requires a TLS-terminating reverse proxy or a different stack, adapt transport and trusted-proxy configuration deliberately before deployment.

## Add this protection to your group's design

1. Change `loginPage()` in `views.mjs` to match your login design. Preserve the POST action `/login`, the `username` and `password` fields, and the hidden `csrf` field.
2. Put your private landing-page markup inside `landingPage()` in `views.mjs`. Preserve the logout form and its CSRF field.
3. Adjust `styles.css` for your design. It is the only public asset served by default.
4. Keep all private files behind backend session checks. Do not add a separately public `landing.html` file, public private-content JSON, or a second unprotected hosting copy.
5. If you add API routes, downloads or images containing private information, require the same authenticated server-side session on every one of those routes.

No browser JavaScript is required by these pages. The content security policy intentionally blocks scripts. Do not weaken it just to add a client-side login check.

## Defense layers included

| Layer | Implementation |
| --- | --- |
| Password storage | Native Argon2id, 64 MiB memory, 3 passes, parallelism 1, random 16-byte salt, 32-byte hash |
| Credential strength | Setup generates a random password from 24 random bytes; no default password |
| Password verification | Server-side hashing for known and unknown usernames; fixed-length timing-safe comparisons |
| Transport | HTTPS required outside loopback development; minimum TLS 1.3; HSTS |
| Protected landing page | Server checks authentication on each request before rendering private content |
| Session identifiers | 32 cryptographically random bytes; cookie stores only an opaque session ID |
| Cookie protection | `__Host-session`, `Secure`, `HttpOnly`, `SameSite=Strict`, `Path=/`, no `Domain` in HTTPS mode |
| Session fixation | New session ID and CSRF token after successful login; old ID deleted |
| Expiry and logout | 15-minute idle timeout, 1-hour absolute timeout; logout deletes server-side session |
| CSRF | Session-bound token plus exact Origin check on login/logout; rejects cross-site fetch metadata |
| Login guessing | 10 attempts per socket IP per 15 minutes; 60 attempts application-wide per 15 minutes |
| Request abuse | 120 requests per socket IP per minute; bounded IP/session maps; at most 2 concurrent password hashes |
| Input handling | 4 KiB body limit, bounded credentials, exact form fields, no duplicate parameters, request timeouts |
| Injection / browser attacks | No SQL or command execution from user input; HTML escaping; restrictive CSP; anti-framing headers |
| Error handling | Same error for incorrect username/password; no secrets or stack traces returned |
| Private file protection | Explicit route allowlist; no generic directory or static-source serving |
| Cache protection | `Cache-Control: no-store`; logout/expiry blocks future authenticated requests |

## Run the security tests

```bash
npm test
```

The suite tests password verification, unauthorized direct URL access, source-file exposure, forged and duplicate cookies, authentication, injection-looking inputs, session rotation, CSRF and Origin checks, oversized and chunked requests, idle and absolute expiration, logout, login/request throttling, spoofed forwarded headers, session capacity, password-hash concurrency, response headers, HTTP rejection and a real TLS login with certificate verification enabled.

The temporary certificate used by the TLS test is generated at test time and removed afterward. Test credentials are synthetic and are not used by setup or the running website.

## Practical limits

- No system can promise that it will never be breached. These controls need to be preserved when you integrate your design.
- This is a **single-process classroom implementation**. Sessions and rate limits live in memory and reset on restart. Multiple workers or servers would need shared session and limiter storage.
- Students behind the same NAT share the IP login limit. The global budget and bounded session store can be exhausted to deny legitimate logins; they limit resource use rather than guarantee availability against a distributed attack. For a short exercise, adjust budgets only after considering that tradeoff.
- It intentionally ignores `X-Forwarded-For`; arbitrary browser headers cannot reset the IP counter. A proxy would need an explicit, restricted trust design.
- Password hashing protects stolen hashes; it does not stop weak passwords from being guessed. Use the generated credentials. MFA or passkeys are possible future additions and are not included here.
- A stolen authenticated session cookie can still be replayed until revoked/expired. Protect the server, certificates and users' devices; do not publish credentials or cookies.
- Logout prevents future authorized responses. It cannot erase information someone already viewed or copied.
- Keep Node.js and the host patched, and do not expose the project directory using another file server.

## References

- OWASP Password Storage: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
- OWASP Authentication: https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
- OWASP Session Management: https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
- OWASP CSRF Prevention: https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html
- Node.js native Argon2 API: https://nodejs.org/api/crypto.html#cryptoargon2algorithm-parameters-callback
