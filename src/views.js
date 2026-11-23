'use strict';

/**
 * Server-rendered HTML views.
 *
 * The dashboard is rendered on the server from the same store the API uses —
 * no separate client app, no build step. All user-controlled strings pass
 * through esc() before interpolation.
 */

function esc(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function layout({ title, user, body, flash = '' }) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(title)} · VulnDesk</title>
<link rel="stylesheet" href="/style.css">
</head>
<body>
<header class="topbar">
  <a class="brand" href="/">VulnDesk</a>
  <nav>
    ${user ? `<span class="who">${esc(user.name)} (${esc(user.email)})</span>
    <form method="post" action="/auth/logout" class="inline"><button type="submit" class="linkbtn">Log out</button></form>`
      : `<a href="/login">Log in</a> <a href="/register">Register</a>`}
  </nav>
</header>
<main>
${flash ? `<div class="flash">${esc(flash)}</div>` : ''}
${body}
</main>
<footer class="foot">VulnDesk — vulnerability management &amp; bug-bounty triage</footer>
</body>
</html>`;
}

function loginPage(error = '') {
  return layout({
    title: 'Log in',
    user: null,
    body: `
<h1>Log in</h1>
${error ? `<div class="error">${esc(error)}</div>` : ''}
<form method="post" action="/auth/login" class="card form">
  <label>Email <input type="email" name="email" required autocomplete="email"></label>
  <label>Password <input type="password" name="password" required autocomplete="current-password"></label>
  <button type="submit">Log in</button>
</form>
<p>No account yet? <a href="/register">Register</a></p>`,
  });
}

function registerPage(error = '') {
  return layout({
    title: 'Register',
    user: null,
    body: `
<h1>Create your account</h1>
${error ? `<div class="error">${esc(error)}</div>` : ''}
<form method="post" action="/auth/register" class="card form">
  <label>Name <input type="text" name="name" required autocomplete="name"></label>
  <label>Email <input type="email" name="email" required autocomplete="email"></label>
  <label>Password (min 8 characters) <input type="password" name="password" required autocomplete="new-password"></label>
  <button type="submit">Register</button>
</form>
<p>Already registered? <a href="/login">Log in</a></p>`,
  });
}

function homePage({ user, workspaces }) {
  const rows = workspaces
    .map(
      (w) => `<li class="card"><a href="/w/${esc(w.id)}/dashboard"><strong>${esc(w.name)}</strong></a>
      <span class="muted">${esc(w.slug)}</span></li>`,
    )
    .join('');
  return layout({
    title: 'Workspaces',
    user,
    body: `
<h1>Your workspaces</h1>
<ul class="plain">${rows || '<li class="muted">No workspaces yet.</li>'}</ul>
<h2>Create a workspace</h2>
<form method="post" action="/workspaces" class="card form">
  <label>Name <input type="text" name="name" required></label>
  <button type="submit">Create workspace</button>
</form>`,
  });
}

function severityBadge(band, score) {
  return `<span class="badge sev-${esc(band)}">${esc(band)} ${score != null ? esc(score.toFixed(1)) : ''}</span>`;
}

function dashboardPage({ user, workspace, role, stats, programmes, recentFindings, activity, memberNames }) {
  const sevRows = ['critical', 'high', 'medium', 'low', 'none']
    .map((b) => `<tr><td>${severityBadge(b)}</td><td>${stats.bySeverity[b] || 0}</td></tr>`)
    .join('');
  const statusRows = Object.entries(stats.byStatus)
    .map(([s, n]) => `<tr><td><span class="badge st-${esc(s)}">${esc(s)}</span></td><td>${n}</td></tr>`)
    .join('');
  const progRows = programmes
    .map((p) => {
      const s = stats.byProgramme[p.id] || { total: 0, open: 0 };
      return `<tr><td><a href="/w/${esc(workspace.id)}/findings?programmeId=${esc(p.id)}">${esc(p.name)}</a></td>
        <td>${esc(p.platform)}</td><td>${s.total}</td><td>${s.open}</td></tr>`;
    })
    .join('');
  const recentRows = recentFindings
    .map(
      (f) => `<tr><td><a href="/w/${esc(workspace.id)}/findings/${esc(f.id)}">${esc(f.title)}</a></td>
        <td>${severityBadge(f.severityBand, f.severityScore)}</td>
        <td><span class="badge st-${esc(f.status)}">${esc(f.status)}</span></td>
        <td>${esc(f.createdAt.slice(0, 10))}</td></tr>`,
    )
    .join('');
  const activityRows = activity
    .map(
      (a) => `<li><span class="muted">${esc(a.createdAt.slice(0, 16).replace('T', ' '))}</span>
        <strong>${esc(a.action)}</strong> ${esc(a.entity)} — ${esc(memberNames[a.userId] || a.userId || 'system')}</li>`,
    )
    .join('');
  return layout({
    title: workspace.name,
    user,
    body: `
<p class="muted"><a href="/">← Workspaces</a></p>
<h1>${esc(workspace.name)} <span class="muted">(${esc(role)})</span></h1>
<div class="grid">
  <section class="card"><h2>Findings by severity</h2><table>${sevRows}</table></section>
  <section class="card"><h2>Findings by status</h2><table>${statusRows}</table></section>
  <section class="card"><h2>Programmes</h2>
    <table><tr><th>Name</th><th>Platform</th><th>Total</th><th>Open</th></tr>${progRows || '<tr><td colspan="4" class="muted">None yet</td></tr>'}</table>
    <p><a href="/w/${esc(workspace.id)}/programmes">Manage programmes</a></p></section>
</div>
<section class="card"><h2>Recent findings</h2>
  <table><tr><th>Title</th><th>Severity</th><th>Status</th><th>Reported</th></tr>${recentRows || '<tr><td colspan="4" class="muted">No findings yet</td></tr>'}</table>
  <p><a href="/w/${esc(workspace.id)}/findings">All findings</a> · <a href="/w/${esc(workspace.id)}/findings/new">Submit a finding</a></p></section>
<section class="card"><h2>Recent activity</h2><ul class="plain">${activityRows || '<li class="muted">No activity yet</li>'}</ul></section>`,
  });
}

function programmesPage({ user, workspace, role, programmes }) {
  const canWrite = role === 'owner' || role === 'admin';
  const rows = programmes
    .map(
      (p) => `<li class="card"><strong>${esc(p.name)}</strong> <span class="muted">${esc(p.platform)} · ${esc(p.status)}</span>
      <div>${esc(p.scope)}</div></li>`,
    )
    .join('');
  return layout({
    title: 'Programmes',
    user,
    body: `
<p class="muted"><a href="/w/${esc(workspace.id)}/dashboard">← Dashboard</a></p>
<h1>Programmes</h1>
<ul class="plain">${rows || '<li class="muted">No programmes yet.</li>'}</ul>
${canWrite ? `<h2>New programme</h2>
<form method="post" action="/w/${esc(workspace.id)}/programmes" class="card form">
  <label>Name <input type="text" name="name" required></label>
  <label>Platform <input type="text" name="platform" placeholder="HackerOne / Bugcrowd / self-hosted"></label>
  <label>Scope <textarea name="scope" rows="3"></textarea></label>
  <button type="submit">Create programme</button>
</form>` : ''}`,
  });
}

function findingsPage({ user, workspace, findings, filters, programmes }) {
  const progName = (id) => (programmes.find((p) => p.id === id) || {}).name || id;
  const rows = findings
    .map(
      (f) => `<tr>
        <td><a href="/w/${esc(workspace.id)}/findings/${esc(f.id)}">${esc(f.title)}</a>${f.duplicateOf ? ' <span class="badge dup">possible duplicate</span>' : ''}</td>
        <td>${esc(progName(f.programmeId))}</td>
        <td>${severityBadge(f.severityBand, f.severityScore)}</td>
        <td><span class="badge st-${esc(f.status)}">${esc(f.status)}</span></td>
        <td>${esc(f.vulnClass)}</td>
        <td>${esc(f.createdAt.slice(0, 10))}</td></tr>`,
    )
    .join('');
  return layout({
    title: 'Findings',
    user,
    body: `
<p class="muted"><a href="/w/${esc(workspace.id)}/dashboard">← Dashboard</a></p>
<h1>Findings</h1>
<form method="get" class="card form inline-form">
  <label>Status <select name="status"><option value="">any</option>
    ${['new', 'triaged', 'accepted', 'duplicate', 'informative', 'fixed'].map((s) => `<option ${filters.status === s ? 'selected' : ''}>${s}</option>`).join('')}
  </select></label>
  <label>Severity <select name="severity"><option value="">any</option>
    ${['critical', 'high', 'medium', 'low', 'none'].map((s) => `<option ${filters.severity === s ? 'selected' : ''}>${s}</option>`).join('')}
  </select></label>
  <button type="submit">Filter</button>
</form>
<table class="card"><tr><th>Title</th><th>Programme</th><th>Severity</th><th>Status</th><th>Class</th><th>Reported</th></tr>
${rows || '<tr><td colspan="6" class="muted">No findings match.</td></tr>'}</table>
<p><a href="/w/${esc(workspace.id)}/findings/new">Submit a finding</a></p>`,
  });
}

function newFindingPage({ user, workspace, programmes, error = '' }) {
  const options = programmes.map((p) => `<option value="${esc(p.id)}">${esc(p.name)}</option>`).join('');
  return layout({
    title: 'Submit finding',
    user,
    body: `
<p class="muted"><a href="/w/${esc(workspace.id)}/findings">← Findings</a></p>
<h1>Submit a finding</h1>
${error ? `<div class="error">${esc(error)}</div>` : ''}
<form method="post" action="/w/${esc(workspace.id)}/findings" class="card form">
  <label>Programme <select name="programmeId" required>${options}</select></label>
  <label>Title <input type="text" name="title" required></label>
  <label>Vulnerability class <input type="text" name="vulnClass" required placeholder="idor, stored-xss, ssrf…"></label>
  <label>Target <input type="text" name="target" required placeholder="https://app.example.com/api/orders"></label>
  <label>Parameter <input type="text" name="parameter" placeholder="order_id"></label>
  <label>CVSS 3.1 vector <input type="text" name="cvssVector" required value="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"></label>
  <label>Reporter <input type="text" name="reporter" placeholder="researcher handle"></label>
  <label>Description <textarea name="description" rows="4"></textarea></label>
  <label>Steps to reproduce <textarea name="reproduction" rows="4"></textarea></label>
  <label>Impact <textarea name="impact" rows="3"></textarea></label>
  <label>Remediation <textarea name="remediation" rows="3"></textarea></label>
  <button type="submit">Submit finding</button>
</form>`,
  });
}

function findingPage({ user, workspace, role, finding, programme, assigneeName, dedupeInfo, members }) {
  const canTriage = ['owner', 'admin', 'analyst'].includes(role);
  const transitions = { new: ['triaged', 'duplicate', 'informative'], triaged: ['accepted', 'duplicate', 'informative', 'new'], accepted: ['fixed', 'duplicate'], duplicate: ['new'], informative: ['new'], fixed: ['new'] };
  const nextStatuses = transitions[finding.status] || [];
  const memberOptions = members
    .map((m) => `<option value="${esc(m.userId)}" ${finding.assigneeId === m.userId ? 'selected' : ''}>${esc(m.name)} (${esc(m.role)})</option>`)
    .join('');
  return layout({
    title: finding.title,
    user,
    body: `
<p class="muted"><a href="/w/${esc(workspace.id)}/findings">← Findings</a></p>
<h1>${esc(finding.title)}</h1>
<p>${severityBadge(finding.severityBand, finding.severityScore)} <span class="badge st-${esc(finding.status)}">${esc(finding.status)}</span>
<span class="muted">${esc(finding.cvssVector)}</span></p>
${finding.duplicateOf ? `<div class="error">Possible duplicate of <a href="/w/${esc(workspace.id)}/findings/${esc(finding.duplicateOf)}">${esc(finding.duplicateOf)}</a> (same target + class + parameter fingerprint).</div>` : ''}
${dedupeInfo && dedupeInfo.similar && dedupeInfo.similar.length ? `<div class="flash">Similar findings (same class &amp; host): ${dedupeInfo.similar.map((s) => `<a href="/w/${esc(workspace.id)}/findings/${esc(s.id)}">${esc(s.title)}</a>`).join(', ')}</div>` : ''}
<section class="card">
  <p><strong>Programme:</strong> ${esc(programme ? programme.name : finding.programmeId)}<br>
  <strong>Class:</strong> ${esc(finding.vulnClass)}<br>
  <strong>Target:</strong> ${esc(finding.target)}${finding.parameter ? ` · <strong>Parameter:</strong> <code>${esc(finding.parameter)}</code>` : ''}<br>
  <strong>Reporter:</strong> ${esc(finding.reporter || '—')}<br>
  <strong>Assignee:</strong> ${esc(assigneeName || 'unassigned')}<br>
  <strong>Fingerprint:</strong> <code>${esc(finding.fingerprint)}</code></p>
  <h2>Description</h2><p>${esc(finding.description) || '<span class="muted">—</span>'}</p>
  <h2>Steps to Reproduce</h2><pre>${esc(finding.reproduction)}</pre>
  <h2>Impact</h2><p>${esc(finding.impact) || '<span class="muted">—</span>'}</p>
  <h2>Remediation</h2><p>${esc(finding.remediation) || '<span class="muted">—</span>'}</p>
  <p><a href="/w/${esc(workspace.id)}/findings/${esc(finding.id)}/report">View report</a> ·
     <a href="/api/workspaces/${esc(workspace.id)}/findings/${esc(finding.id)}/report.md">Download Markdown</a></p>
</section>
${canTriage ? `<section class="card"><h2>Triage</h2>
  <form method="post" action="/w/${esc(workspace.id)}/findings/${esc(finding.id)}/status" class="inline-form">
    <label>Move to <select name="status">${nextStatuses.map((s) => `<option>${s}</option>`).join('')}</select></label>
    <button type="submit">Change status</button>
  </form>
  <form method="post" action="/w/${esc(workspace.id)}/findings/${esc(finding.id)}/assign" class="inline-form">
    <label>Assign to <select name="assigneeId"><option value="">unassigned</option>${memberOptions}</select></label>
    <button type="submit">Assign</button>
  </form>
</section>` : ''}`,
  });
}

function reportPage({ user, workspace, finding, markdown }) {
  return layout({
    title: `Report — ${finding.title}`,
    user,
    body: `
<p class="muted"><a href="/w/${esc(workspace.id)}/findings/${esc(finding.id)}">← Finding</a></p>
<h1>Report</h1>
<section class="card"><pre class="report">${esc(markdown)}</pre></section>`,
  });
}

module.exports = {
  esc,
  layout,
  loginPage,
  registerPage,
  homePage,
  dashboardPage,
  programmesPage,
  findingsPage,
  newFindingPage,
  findingPage,
  reportPage,
};
