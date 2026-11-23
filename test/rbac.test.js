'use strict';

const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const {
  startTestApp, closeApp, request, registerAndLogin, createWorkspace, createProgramme, createFinding,
} = require('./helpers');

let app;
let owner, analyst, viewer, outsider;
let ws, programme, findingId;

before(async () => {
  app = await startTestApp();
  owner = await registerAndLogin(app.base, { email: 'owner@acme.test', name: 'Owner' });
  analyst = await registerAndLogin(app.base, { email: 'analyst@acme.test', name: 'Analyst' });
  viewer = await registerAndLogin(app.base, { email: 'viewer@acme.test', name: 'Viewer' });
  outsider = await registerAndLogin(app.base, { email: 'outsider@acme.test', name: 'Outsider' });
  ws = await createWorkspace(app.base, owner.token, 'RBAC Workspace');
  programme = await createProgramme(app.base, owner.token, ws.id);

  for (const [member, role] of [[analyst, 'analyst'], [viewer, 'viewer']]) {
    const res = await request(app.base, 'POST', `/api/workspaces/${ws.id}/members`, {
      token: owner.token, body: { email: member.email, role },
    });
    assert.equal(res.status, 201);
  }
  const f = await createFinding(app.base, owner.token, ws.id, programme.id);
  assert.equal(f.status, 201);
  findingId = f.json.id;
});

after(async () => { await closeApp(app); });

test('viewer can read but cannot create findings (403)', async () => {
  const read = await request(app.base, 'GET', `/api/workspaces/${ws.id}/findings`, { token: viewer.token });
  assert.equal(read.status, 200);
  const write = await createFinding(app.base, viewer.token, ws.id, programme.id, { title: 'viewer attempt' });
  assert.equal(write.status, 403);
});

test('viewer cannot triage or assign (403)', async () => {
  const status = await request(app.base, 'POST', `/api/workspaces/${ws.id}/findings/${findingId}/status`, {
    token: viewer.token, body: { status: 'triaged' },
  });
  assert.equal(status.status, 403);
  const assign = await request(app.base, 'POST', `/api/workspaces/${ws.id}/findings/${findingId}/assign`, {
    token: viewer.token, body: { assigneeId: analyst.user.id },
  });
  assert.equal(assign.status, 403);
});

test('analyst can create and triage findings but cannot manage members or programmes', async () => {
  const created = await createFinding(app.base, analyst.token, ws.id, programme.id, {
    title: 'Analyst finding', target: 'https://app.example.com/api/users', parameter: 'user_id',
  });
  assert.equal(created.status, 201);
  const triage = await request(app.base, 'POST', `/api/workspaces/${ws.id}/findings/${created.json.id}/status`, {
    token: analyst.token, body: { status: 'triaged' },
  });
  assert.equal(triage.status, 200);
  assert.equal(triage.json.status, 'triaged');

  const memberAdd = await request(app.base, 'POST', `/api/workspaces/${ws.id}/members`, {
    token: analyst.token, body: { email: outsider.email, role: 'viewer' },
  });
  assert.equal(memberAdd.status, 403);
  const progWrite = await request(app.base, 'POST', `/api/workspaces/${ws.id}/programmes`, {
    token: analyst.token, body: { name: 'Nope' },
  });
  assert.equal(progWrite.status, 403);
  const del = await request(app.base, 'DELETE', `/api/workspaces/${ws.id}/findings/${created.json.id}`, {
    token: analyst.token,
  });
  assert.equal(del.status, 403);
});

test('analyst cannot read the audit log; admin/owner can', async () => {
  const denied = await request(app.base, 'GET', `/api/workspaces/${ws.id}/audit`, { token: analyst.token });
  assert.equal(denied.status, 403);
  const allowed = await request(app.base, 'GET', `/api/workspaces/${ws.id}/audit`, { token: owner.token });
  assert.equal(allowed.status, 200);
  assert.ok(Array.isArray(allowed.json));
  assert.ok(allowed.json.some((a) => a.action === 'finding.create'));
});

test('admin can manage members and delete findings, but cannot manage the workspace itself', async () => {
  const admin = await registerAndLogin(app.base, { email: 'admin@acme.test', name: 'Admin' });
  const add = await request(app.base, 'POST', `/api/workspaces/${ws.id}/members`, {
    token: owner.token, body: { email: admin.email, role: 'admin' },
  });
  assert.equal(add.status, 201);

  const memberAdd = await request(app.base, 'POST', `/api/workspaces/${ws.id}/members`, {
    token: admin.token, body: { email: outsider.email, role: 'viewer' },
  });
  assert.equal(memberAdd.status, 201);

  const wsPatch = await request(app.base, 'PATCH', `/api/workspaces/${ws.id}`, {
    token: admin.token, body: { name: 'Renamed by admin' },
  });
  assert.equal(wsPatch.status, 403);

  const del = await request(app.base, 'DELETE', `/api/workspaces/${ws.id}/findings/${findingId}`, {
    token: admin.token,
  });
  assert.equal(del.status, 200);
});

test('the owner role cannot be granted, re-roled or removed', async () => {
  const grant = await request(app.base, 'POST', `/api/workspaces/${ws.id}/members`, {
    token: owner.token, body: { email: outsider.email, role: 'owner' },
  });
  assert.equal(grant.status, 400);
  const rerole = await request(app.base, 'POST', `/api/workspaces/${ws.id}/members`, {
    token: owner.token, body: { email: owner.email, role: 'viewer' },
  });
  assert.equal(rerole.status, 400);
  const remove = await request(app.base, 'DELETE', `/api/workspaces/${ws.id}/members/${owner.user.id}`, {
    token: owner.token,
  });
  assert.equal(remove.status, 400);
});

test('adding an unregistered email as a member is a 404', async () => {
  const res = await request(app.base, 'POST', `/api/workspaces/${ws.id}/members`, {
    token: owner.token, body: { email: 'nobody@acme.test', role: 'viewer' },
  });
  assert.equal(res.status, 404);
});
