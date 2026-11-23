'use strict';

const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const {
  startTestApp, closeApp, request, registerAndLogin, createWorkspace, createProgramme, createFinding,
} = require('./helpers');
const dedupe = require('../src/dedupe');

let app, owner, ws, prog;

before(async () => {
  app = await startTestApp();
  owner = await registerAndLogin(app.base, { email: 'dedupe@acme.test' });
  ws = await createWorkspace(app.base, owner.token, 'Dedupe Workspace');
  prog = await createProgramme(app.base, owner.token, ws.id);
});

after(async () => { await closeApp(app); });

test('normalisation: scheme, case, default port, trailing slash and query are ignored', () => {
  const a = dedupe.fingerprint({ target: 'https://APP.example.com:443/api/orders/', vulnClass: 'IDOR', parameter: 'Order_ID' });
  const b = dedupe.fingerprint({ target: 'app.example.com/api/orders?x=1', vulnClass: 'idor', parameter: 'order_id' });
  assert.equal(a, b);
  const c = dedupe.fingerprint({ target: 'app.example.com/api/orders', vulnClass: 'idor', parameter: 'user_id' });
  assert.notEqual(a, c);
});

test('an exact duplicate submission is flagged with the original\u2019s id', async () => {
  const first = await createFinding(app.base, owner.token, ws.id, prog.id);
  assert.equal(first.status, 201);
  assert.equal(first.json.dedupe.possibleDuplicateOf, null);

  const second = await createFinding(app.base, owner.token, ws.id, prog.id, { title: 'Same bug, second report' });
  assert.equal(second.status, 201);
  assert.equal(second.json.duplicateOf, first.json.id);
  assert.equal(second.json.dedupe.possibleDuplicateOf, first.json.id);

  // The flag is persisted, not just returned once.
  const fetched = await request(app.base, 'GET', `/api/workspaces/${ws.id}/findings/${second.json.id}`, { token: owner.token });
  assert.equal(fetched.json.duplicateOf, first.json.id);
});

test('same class and host but a different parameter is "similar", not a duplicate', async () => {
  const res = await createFinding(app.base, owner.token, ws.id, prog.id, {
    title: 'IDOR on invoices via customer_id',
    parameter: 'customer_id',
  });
  assert.equal(res.status, 201);
  assert.equal(res.json.dedupe.possibleDuplicateOf, null);
  assert.ok(res.json.dedupe.similar.length >= 1);
});

test('a different class on the same endpoint is neither duplicate nor similar', async () => {
  const res = await createFinding(app.base, owner.token, ws.id, prog.id, {
    title: 'XSS on invoices page',
    vulnClass: 'stored-xss',
    parameter: 'invoice_id',
  });
  assert.equal(res.status, 201);
  assert.equal(res.json.dedupe.possibleDuplicateOf, null);
  assert.deepEqual(res.json.dedupe.similar, []);
});

test('triage can confirm a duplicate and reopen it; reopening clears the link', async () => {
  const original = await createFinding(app.base, owner.token, ws.id, prog.id, {
    title: 'SSRF original', vulnClass: 'ssrf', target: 'https://app.example.com/api/fetch', parameter: 'url',
  });
  const copy = await createFinding(app.base, owner.token, ws.id, prog.id, {
    title: 'SSRF copy', vulnClass: 'ssrf', target: 'https://app.example.com/api/fetch', parameter: 'url',
  });
  assert.equal(copy.json.duplicateOf, original.json.id);

  const triaged = await request(app.base, 'POST', `/api/workspaces/${ws.id}/findings/${copy.json.id}/status`, {
    token: owner.token, body: { status: 'triaged' },
  });
  assert.equal(triaged.status, 200);
  const dup = await request(app.base, 'POST', `/api/workspaces/${ws.id}/findings/${copy.json.id}/status`, {
    token: owner.token, body: { status: 'duplicate' },
  });
  assert.equal(dup.status, 200);
  assert.equal(dup.json.duplicateOf, original.json.id);

  const reopened = await request(app.base, 'POST', `/api/workspaces/${ws.id}/findings/${copy.json.id}/status`, {
    token: owner.token, body: { status: 'new' },
  });
  assert.equal(reopened.status, 200);
  assert.equal(reopened.json.duplicateOf, null);
});
