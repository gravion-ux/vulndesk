'use strict';

const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const {
  startTestApp, closeApp, request, registerAndLogin, createWorkspace, createProgramme, createFinding,
} = require('./helpers');

let app, owner, ws, progA, progB;

before(async () => {
  app = await startTestApp();
  owner = await registerAndLogin(app.base, { email: 'dash@acme.test', name: 'Dana' });
  ws = await createWorkspace(app.base, owner.token, 'Dashboard Workspace');
  progA = await createProgramme(app.base, owner.token, ws.id, 'Web Programme');
  progB = await createProgramme(app.base, owner.token, ws.id, 'API Programme');

  // 3 findings on A: critical/new, critical/triaged, medium/new
  await createFinding(app.base, owner.token, ws.id, progA.id, { target: 'https://a.example.com/1', parameter: 'p1' });
  const f2 = await createFinding(app.base, owner.token, ws.id, progA.id, { target: 'https://a.example.com/2', parameter: 'p2' });
  await request(app.base, 'POST', `/api/workspaces/${ws.id}/findings/${f2.json.id}/status`, {
    token: owner.token, body: { status: 'triaged' },
  });
  await createFinding(app.base, owner.token, ws.id, progA.id, {
    target: 'https://a.example.com/3', parameter: 'p3',
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N', // 6.1 medium
  });
  // 1 finding on B: high/new
  await createFinding(app.base, owner.token, ws.id, progB.id, {
    target: 'https://b.example.com/1', parameter: 'q1',
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N', // 7.5 high
  });
});

after(async () => { await closeApp(app); });

test('stats endpoint reports totals, severity, status and per-programme counts', async () => {
  const res = await request(app.base, 'GET', `/api/workspaces/${ws.id}/stats`, { token: owner.token });
  assert.equal(res.status, 200);
  assert.equal(res.json.total, 4);
  assert.equal(res.json.bySeverity.critical, 2);
  assert.equal(res.json.bySeverity.medium, 1);
  assert.equal(res.json.bySeverity.high, 1);
  assert.equal(res.json.bySeverity.low, 0);
  assert.equal(res.json.byStatus.new, 3);
  assert.equal(res.json.byStatus.triaged, 1);
  assert.equal(res.json.byProgramme[progA.id].total, 3);
  assert.equal(res.json.byProgramme[progA.id].open, 3);
  assert.equal(res.json.byProgramme[progB.id].total, 1);
});

test('dashboard page renders counts, programmes and recent activity', async () => {
  const res = await request(app.base, 'GET', `/w/${ws.id}/dashboard`, { cookie: owner.cookie });
  assert.equal(res.status, 200);
  assert.match(res.text, /Dashboard Workspace/);
  assert.match(res.text, /Findings by severity/);
  assert.match(res.text, /Findings by status/);
  assert.match(res.text, /Web Programme/);
  assert.match(res.text, /API Programme/);
  assert.match(res.text, /Recent activity/);
  assert.match(res.text, /finding\.create/);
});

test('findings list page renders and honours filters', async () => {
  const all = await request(app.base, 'GET', `/w/${ws.id}/findings`, { cookie: owner.cookie });
  assert.equal(all.status, 200);
  assert.match(all.text, /IDOR on invoices/);
  const filtered = await request(app.base, 'GET', `/w/${ws.id}/findings?status=triaged`, { cookie: owner.cookie });
  assert.equal(filtered.status, 200);
  assert.match(filtered.text, /triaged/);
});

test('finding detail page renders the full report content', async () => {
  const list = await request(app.base, 'GET', `/api/workspaces/${ws.id}/findings`, { token: owner.token });
  const id = list.json[0].id;
  const page = await request(app.base, 'GET', `/w/${ws.id}/findings/${id}`, { cookie: owner.cookie });
  assert.equal(page.status, 200);
  assert.match(page.text, /Steps to Reproduce/);
  assert.match(page.text, /Impact/);
  assert.match(page.text, /Remediation/);
  assert.match(page.text, /Fingerprint/);
});

test('pages require authentication', async () => {
  const res = await request(app.base, 'GET', `/w/${ws.id}/dashboard`);
  assert.equal(res.status, 303);
  assert.match(res.headers.get('location'), /\/login/);
});

test('health endpoint is public', async () => {
  const res = await request(app.base, 'GET', '/healthz');
  assert.equal(res.status, 200);
  assert.equal(res.json.ok, true);
});
