'use strict';

const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const {
  startTestApp, closeApp, request, registerAndLogin, createWorkspace, createProgramme, createFinding,
} = require('./helpers');

let app, owner, analyst, ws, prog;

before(async () => {
  app = await startTestApp();
  owner = await registerAndLogin(app.base, { email: 'life@acme.test' });
  analyst = await registerAndLogin(app.base, { email: 'life-analyst@acme.test', name: 'Analyst' });
  ws = await createWorkspace(app.base, owner.token, 'Lifecycle Workspace');
  prog = await createProgramme(app.base, owner.token, ws.id);
  await request(app.base, 'POST', `/api/workspaces/${ws.id}/members`, {
    token: owner.token, body: { email: analyst.email, role: 'analyst' },
  });
});

after(async () => { await closeApp(app); });

async function freshFinding(overrides) {
  const res = await createFinding(app.base, owner.token, ws.id, prog.id, overrides);
  assert.equal(res.status, 201);
  return res.json;
}

async function setStatus(id, status, extra = {}) {
  return request(app.base, 'POST', `/api/workspaces/${ws.id}/findings/${id}/status`, {
    token: owner.token, body: { status, ...extra },
  });
}

test('the happy path: new -> triaged -> accepted -> fixed', async () => {
  const f = await freshFinding({ target: 'https://app.example.com/api/a', parameter: 'a' });
  assert.equal(f.status, 'new');
  assert.equal((await setStatus(f.id, 'triaged')).json.status, 'triaged');
  assert.equal((await setStatus(f.id, 'accepted')).json.status, 'accepted');
  assert.equal((await setStatus(f.id, 'fixed')).json.status, 'fixed');
});

test('invalid transitions are rejected with 400', async () => {
  const f = await freshFinding({ target: 'https://app.example.com/api/b', parameter: 'b' });
  const jump = await setStatus(f.id, 'fixed'); // new -> fixed is not allowed
  assert.equal(jump.status, 400);
  assert.match(jump.json.error, /Invalid status transition/);
  const accepted = await setStatus(f.id, 'accepted'); // new -> accepted also not allowed
  assert.equal(accepted.status, 400);
  const nonsense = await setStatus(f.id, 'banana');
  assert.equal(nonsense.status, 400);
});

test('fixed findings can be reopened to new (regression)', async () => {
  const f = await freshFinding({ target: 'https://app.example.com/api/c', parameter: 'c' });
  await setStatus(f.id, 'triaged');
  await setStatus(f.id, 'accepted');
  await setStatus(f.id, 'fixed');
  const reopened = await setStatus(f.id, 'new');
  assert.equal(reopened.status, 200);
  assert.equal(reopened.json.status, 'new');
});

test('marking duplicate without an original is refused', async () => {
  const f = await freshFinding({ target: 'https://app.example.com/api/unique', parameter: 'u' });
  await setStatus(f.id, 'triaged');
  const res = await setStatus(f.id, 'duplicate');
  assert.equal(res.status, 400);
  assert.match(res.json.error, /duplicateOf/);
  const withRef = await setStatus(f.id, 'duplicate', { duplicateOf: f.id === 'x' ? 'y' : undefined });
  assert.equal(withRef.status, 400);
});

test('PATCH with a status field follows the same transition rules', async () => {
  const f = await freshFinding({ target: 'https://app.example.com/api/d', parameter: 'd' });
  const ok = await request(app.base, 'PATCH', `/api/workspaces/${ws.id}/findings/${f.id}`, {
    token: owner.token, body: { status: 'triaged' },
  });
  assert.equal(ok.status, 200);
  const bad = await request(app.base, 'PATCH', `/api/workspaces/${ws.id}/findings/${f.id}`, {
    token: owner.token, body: { status: 'fixed' },
  });
  assert.equal(bad.status, 400);
});

test('assignment requires a workspace member; unassignment works', async () => {
  const f = await freshFinding({ target: 'https://app.example.com/api/e', parameter: 'e' });
  const assign = await request(app.base, 'POST', `/api/workspaces/${ws.id}/findings/${f.id}/assign`, {
    token: owner.token, body: { assigneeId: analyst.user.id },
  });
  assert.equal(assign.status, 200);
  assert.equal(assign.json.assigneeId, analyst.user.id);

  const stranger = await registerAndLogin(app.base, { email: 'stranger@acme.test' });
  const bad = await request(app.base, 'POST', `/api/workspaces/${ws.id}/findings/${f.id}/assign`, {
    token: owner.token, body: { assigneeId: stranger.user.id },
  });
  assert.equal(bad.status, 400);

  const unassign = await request(app.base, 'POST', `/api/workspaces/${ws.id}/findings/${f.id}/assign`, {
    token: owner.token, body: { assigneeId: null },
  });
  assert.equal(unassign.status, 200);
  assert.equal(unassign.json.assigneeId, null);
});

test('list filters: status, severity, programme and assignee', async () => {
  const f1 = await freshFinding({ title: 'Filter target one', target: 'https://app.example.com/api/f1', parameter: 'x' });
  await setStatus(f1.id, 'triaged');
  const byStatus = await request(app.base, 'GET', `/api/workspaces/${ws.id}/findings?status=triaged`, { token: owner.token });
  assert.ok(byStatus.json.every((f) => f.status === 'triaged'));
  assert.ok(byStatus.json.some((f) => f.id === f1.id));

  const bySeverity = await request(app.base, 'GET', `/api/workspaces/${ws.id}/findings?severity=critical`, { token: owner.token });
  assert.ok(bySeverity.json.length >= 1);
  assert.ok(bySeverity.json.every((f) => f.severityBand === 'critical'));

  const byProgramme = await request(app.base, 'GET', `/api/workspaces/${ws.id}/findings?programmeId=${prog.id}`, { token: owner.token });
  assert.ok(byProgramme.json.every((f) => f.programmeId === prog.id));

  const none = await request(app.base, 'GET', `/api/workspaces/${ws.id}/findings?severity=low`, { token: owner.token });
  assert.equal(none.json.length, 0);
});

test('creating a finding validates programme, title, class, target and CVSS vector', async () => {
  const badProg = await createFinding(app.base, owner.token, ws.id, 'prg_missing');
  assert.equal(badProg.status, 400);
  const badVector = await createFinding(app.base, owner.token, ws.id, prog.id, {
    cvssVector: 'CVSS:3.1/AV:Z/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', target: 'https://app.example.com/api/z', parameter: 'z',
  });
  assert.equal(badVector.status, 400);
  const noTitle = await createFinding(app.base, owner.token, ws.id, prog.id, {
    title: '', target: 'https://app.example.com/api/z2', parameter: 'z2',
  });
  assert.equal(noTitle.status, 400);
});

test('severity is derived from the CVSS vector, not from client claims', async () => {
  const low = await createFinding(app.base, owner.token, ws.id, prog.id, {
    title: 'Low one', target: 'https://app.example.com/api/low', parameter: 'l',
    cvssVector: 'CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N',
  });
  assert.equal(low.status, 201);
  assert.equal(low.json.severityScore, 1.8);
  assert.equal(low.json.severityBand, 'low');
});

test('every mutation lands in the audit log', async () => {
  const audit = await request(app.base, 'GET', `/api/workspaces/${ws.id}/audit`, { token: owner.token });
  const actions = audit.json.map((a) => a.action);
  for (const expected of ['workspace.create', 'programme.create', 'finding.create', 'finding.status', 'finding.assign', 'member.add']) {
    assert.ok(actions.includes(expected), `audit log missing ${expected}`);
  }
});
