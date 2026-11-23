'use strict';

const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const {
  startTestApp, closeApp, request, registerAndLogin, createWorkspace, createProgramme, createFinding,
} = require('./helpers');
const { renderMarkdown } = require('../src/report');

let app, owner, ws, prog, finding;

before(async () => {
  app = await startTestApp();
  owner = await registerAndLogin(app.base, { email: 'report@acme.test', name: 'Rita Reporter' });
  ws = await createWorkspace(app.base, owner.token, 'Report Workspace');
  prog = await createProgramme(app.base, owner.token, ws.id, 'Storefront Bounty');
  const res = await createFinding(app.base, owner.token, ws.id, prog.id);
  finding = res.json;
});

after(async () => { await closeApp(app); });

test('markdown report contains every professional section', () => {
  const md = renderMarkdown(finding, { programmeName: 'Storefront Bounty', assigneeName: 'Rita Reporter' });
  assert.match(md, /^# IDOR on invoices/);
  assert.match(md, /\| Severity \| CRITICAL \(9\.8\) \|/);
  assert.match(md, /CVSS:3\.1\/AV:N\/AC:L\/PR:N\/UI:N\/S:U\/C:H\/I:H\/A:H/);
  assert.match(md, /## Description/);
  assert.match(md, /## Steps to Reproduce/);
  assert.match(md, /GET \/api\/invoices\/\{other-id\}/);
  assert.match(md, /## Impact/);
  assert.match(md, /Cross-account PII exposure/);
  assert.match(md, /## Remediation/);
  assert.match(md, /Check object ownership server-side/);
  assert.match(md, new RegExp(finding.fingerprint));
});

test('report endpoint serves downloadable markdown', async () => {
  const res = await request(app.base, 'GET', `/api/workspaces/${ws.id}/findings/${finding.id}/report.md`, { token: owner.token });
  assert.equal(res.status, 200);
  assert.match(res.headers.get('content-type'), /text\/markdown/);
  assert.match(res.headers.get('content-disposition'), /attachment/);
  assert.match(res.text, /# IDOR on invoices/);
});

test('HTML report page renders for workspace members', async () => {
  const res = await request(app.base, 'GET', `/w/${ws.id}/findings/${finding.id}/report`, { cookie: owner.cookie });
  assert.equal(res.status, 200);
  assert.match(res.text, /Steps to Reproduce/);
  assert.match(res.text, /Remediation/);
});

test('report of a nonexistent finding is a 404', async () => {
  const res = await request(app.base, 'GET', `/api/workspaces/${ws.id}/findings/fnd_nope/report.md`, { token: owner.token });
  assert.equal(res.status, 404);
});

test('report output escapes nothing it should not and includes dedupe provenance', async () => {
  const dup = await createFinding(app.base, owner.token, ws.id, prog.id, { title: 'Copy of the IDOR' });
  assert.equal(dup.json.duplicateOf, finding.id);
  const md = renderMarkdown(dup.json, {});
  assert.match(md, /Duplicate of/);
});
