'use strict';

/**
 * End-to-end smoke test against the SQLite backend (the production default
 * on Node >= 22). The rest of the suite runs against the JSON backend; this
 * file proves the primary backend carries the full product flow.
 */

const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const {
  startTestApp, closeApp, request, registerAndLogin, createWorkspace, createProgramme, createFinding,
} = require('./helpers');

let SqliteStore = null;
try {
  ({ SqliteStore } = require('../src/store/sqlite-store'));
  require('node:sqlite');
} catch {
  SqliteStore = null;
}

const maybe = SqliteStore ? test : test.skip;

let app;

before(async () => {
  if (!SqliteStore) return;
  app = await startTestApp(new SqliteStore(':memory:'));
});

after(async () => {
  if (app) await closeApp(app);
});

maybe('sqlite backend: register -> workspace -> programme -> finding -> dedupe -> report', async () => {
  const owner = await registerAndLogin(app.base, { email: 'sqlite@acme.test', name: 'Sql' });
  const ws = await createWorkspace(app.base, owner.token, 'SQLite Workspace');
  const prog = await createProgramme(app.base, owner.token, ws.id);

  const first = await createFinding(app.base, owner.token, ws.id, prog.id);
  assert.equal(first.status, 201);
  assert.equal(first.json.severityScore, 9.8);

  const copy = await createFinding(app.base, owner.token, ws.id, prog.id, { title: 'Duplicate submission' });
  assert.equal(copy.json.duplicateOf, first.json.id);

  const stats = await request(app.base, 'GET', `/api/workspaces/${ws.id}/stats`, { token: owner.token });
  assert.equal(stats.json.total, 2);
  assert.equal(stats.json.bySeverity.critical, 2);

  const report = await request(app.base, 'GET', `/api/workspaces/${ws.id}/findings/${first.json.id}/report.md`, { token: owner.token });
  assert.equal(report.status, 200);
  assert.match(report.text, /## Remediation/);

  const dash = await request(app.base, 'GET', `/w/${ws.id}/dashboard`, { cookie: owner.cookie });
  assert.equal(dash.status, 200);
  assert.match(dash.text, /SQLite Workspace/);
});
