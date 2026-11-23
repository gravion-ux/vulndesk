'use strict';

const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const {
  startTestApp, closeApp, request, registerAndLogin, createWorkspace, createProgramme, createFinding,
} = require('./helpers');

let app;
let alice, bob; // owners of workspace A and B respectively
let wsA, wsB, progA, progB, findingA;

before(async () => {
  app = await startTestApp();
  alice = await registerAndLogin(app.base, { email: 'alice@a.test', name: 'Alice' });
  bob = await registerAndLogin(app.base, { email: 'bob@b.test', name: 'Bob' });
  wsA = await createWorkspace(app.base, alice.token, 'Tenant A');
  wsB = await createWorkspace(app.base, bob.token, 'Tenant B');
  progA = await createProgramme(app.base, alice.token, wsA.id, 'A Web');
  progB = await createProgramme(app.base, bob.token, wsB.id, 'B Web');
  const f = await createFinding(app.base, alice.token, wsA.id, progA.id);
  assert.equal(f.status, 201);
  findingA = f.json;
});

after(async () => { await closeApp(app); });

test('a non-member cannot even see the other workspace (404, not 403)', async () => {
  const res = await request(app.base, 'GET', `/api/workspaces/${wsA.id}`, { token: bob.token });
  assert.equal(res.status, 404);
});

test('cross-tenant finding read is a 404', async () => {
  const res = await request(app.base, 'GET', `/api/workspaces/${wsB.id}/findings/${findingA.id}`, { token: bob.token });
  assert.equal(res.status, 404);
  // Even addressing it under the victim workspace id fails: Bob is not a member.
  const res2 = await request(app.base, 'GET', `/api/workspaces/${wsA.id}/findings/${findingA.id}`, { token: bob.token });
  assert.equal(res2.status, 404);
});

test('cross-tenant finding mutation is impossible', async () => {
  const patch = await request(app.base, 'PATCH', `/api/workspaces/${wsB.id}/findings/${findingA.id}`, {
    token: bob.token, body: { title: 'pwned' },
  });
  assert.equal(patch.status, 404);
  const status = await request(app.base, 'POST', `/api/workspaces/${wsB.id}/findings/${findingA.id}/status`, {
    token: bob.token, body: { status: 'triaged' },
  });
  assert.equal(status.status, 404);
  const del = await request(app.base, 'DELETE', `/api/workspaces/${wsB.id}/findings/${findingA.id}`, { token: bob.token });
  assert.equal(del.status, 404);
  // And the finding is untouched in its own tenant.
  const check = await request(app.base, 'GET', `/api/workspaces/${wsA.id}/findings/${findingA.id}`, { token: alice.token });
  assert.equal(check.status, 200);
  assert.equal(check.json.title, 'IDOR on invoices');
  assert.equal(check.json.status, 'new');
});

test('finding lists, programmes, stats and audit are tenant-isolated', async () => {
  const listB = await request(app.base, 'GET', `/api/workspaces/${wsB.id}/findings`, { token: bob.token });
  assert.equal(listB.status, 200);
  assert.equal(listB.json.length, 0);

  const progsB = await request(app.base, 'GET', `/api/workspaces/${wsB.id}/programmes`, { token: bob.token });
  assert.deepEqual(progsB.json.map((p) => p.id), [progB.id]);

  const statsB = await request(app.base, 'GET', `/api/workspaces/${wsB.id}/stats`, { token: bob.token });
  assert.equal(statsB.json.total, 0);
  const statsA = await request(app.base, 'GET', `/api/workspaces/${wsA.id}/stats`, { token: alice.token });
  assert.equal(statsA.json.total, 1);

  const auditB = await request(app.base, 'GET', `/api/workspaces/${wsB.id}/audit`, { token: bob.token });
  assert.equal(auditB.status, 200);
  assert.ok(auditB.json.every((a) => a.workspaceId === wsB.id));
});

test('creating a finding in tenant B referencing tenant A\u2019s programme fails', async () => {
  const res = await createFinding(app.base, bob.token, wsB.id, progA.id, { title: 'cross-tenant ref' });
  assert.equal(res.status, 400);
});

test('identical findings in different tenants do not leak dedupe information', async () => {
  // Same target/class/parameter as findingA, but in tenant B.
  const res = await createFinding(app.base, bob.token, wsB.id, progB.id);
  assert.equal(res.status, 201);
  assert.equal(res.json.dedupe.possibleDuplicateOf, null);
  assert.deepEqual(res.json.dedupe.similar, []);
});
