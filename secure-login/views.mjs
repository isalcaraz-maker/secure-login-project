const escape = value => String(value).replace(/[&<>"']/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[char]);

function shell(title, body) {
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${title} · Haven</title><link rel="stylesheet" href="/styles.css"><link rel="icon" href="data:,"></head>
<body><header class="topbar"><a class="brand" href="/">H<span class="brand-dot">•</span> HAVEN</a><span class="top-note">PRIVATE WORKSPACE</span></header>
<main>${body}</main><footer>Haven <span>Restricted access · Authorized members only</span></footer></body></html>`;
}

export function loginPage(csrf, message = '') {
  return shell('Sign in', `<section class="login-layout"><div class="intro"><p class="eyebrow">A SPACE FOR YOUR TEAM</p>
<h1>Your work.<br>Your people.<br><span>Your space.</span></h1><p class="lede">A quiet place to begin. Sign in to enter your private workspace.</p>
<div class="intro-line"></div><p class="small">One account. One protected space.</p></div>
<section class="card" aria-labelledby="signin-title"><div class="badge" aria-hidden="true">H</div><p class="eyebrow">WELCOME BACK</p><h2 id="signin-title">Sign in to Haven</h2><p class="muted">Enter your team credentials to continue.</p>
${message ? `<p class="alert" role="alert">${escape(message)}</p>` : ''}
<form method="post" action="/login"><input type="hidden" name="csrf" value="${escape(csrf)}">
<label for="username">Username</label><input id="username" name="username" autocomplete="username" autocapitalize="none" spellcheck="false" maxlength="64" required>
<label for="password">Password</label><input id="password" name="password" type="password" autocomplete="current-password" maxlength="128" required>
<button type="submit">Sign in <span aria-hidden="true">→</span></button></form><p class="card-note">Access is limited to authorized team members.</p></section></section>`);
}

export function landingPage(username, csrf) {
  // Keep ALL private page content inside this backend-rendered function.
  // Do not create a public copy named landing.html or a public JSON endpoint.
  return shell('Workspace', `<section class="workspace"><div class="workspace-header"><p class="eyebrow">YOUR PRIVATE WORKSPACE</p><form method="post" action="/logout"><input type="hidden" name="csrf" value="${escape(csrf)}"><button class="secondary" type="submit">Sign out ↗</button></form></div>
<h1>You're in,<br><span>${escape(username)}.</span></h1><p class="lede">Welcome to your team's landing page.</p>
<div class="welcome-panel"><span class="status-dot" aria-hidden="true"></span><div><h2>Make yourself at home.</h2><p>This is your team's space. Add your landing-page content here.</p></div><span class="panel-number" aria-hidden="true">01</span></div></section>`);
}

export const messagePage = (title, message) => shell(escape(title), `<section class="message card"><p class="eyebrow">HAVEN</p><h1>${escape(title)}</h1><p>${escape(message)}</p><a href="/login">Return to sign in →</a></section>`);
