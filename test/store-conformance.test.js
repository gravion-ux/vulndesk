'use strict';

/**
 * Store conformance: the SAME behavioural contract must hold for every
 * backend. If a backend is added tomorrow, it passes this file or it does
 * not ship.
 */

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { JsonStore } = require('../src/store/json-store');
const { STORE_METHODS } = require('../src/store/contract');

function exerciseContract(label, makeStore) {
  test(`${label}: implements the full store interface`, () => {
    const store = makeStore();
    for (const m of STORE_METHODS) {
      assert.equal(typeof store[m], 'function', `missing method ${m}`);
    }
    store.close();
  });

  test(`${label}: CRUD + tenant scoping + dedupe-relevant queries`, () => {
    const store = makeStore();
    const ts = '2026-01-01T00:00:00.000Z';
    const u1 = store.createUser({ id: 'usr_1', email: 'a@x.test', name: 'A', passwordHash: 'h', createdAt: ts });
    assert.equal(store.getUserByEmail('A@X.TEST').id, u1.id);
    assert.equal(store.getUserById('usr_1').email, 'a@x.test');
    assert.equal(store.getUserByEmail('none@x.test'), null);

    const w1 = store.createWorkspace({ id: 'wsp_1', name: 'One', slug: 'one', createdBy: 'usr_1', createdAt: ts });
    const w2 = store.createWorkspace({ id: 'wsp_2', name: 'Two', slug: 'two', createdBy: 'usr_1', createdAt: ts });
    store.setMembership({ id: 'mem_1', workspaceId: w1.id, userId: 'usr_1', role: 'owner', createdAt: ts });
    assert.equal(store.getMembership(w1.id, 'usr_1').role, 'owner');
    assert.equal(store.getMembership(w2.id, 'usr_1'), null);
    assert.deepEqual(store.listWorkspacesForUser('usr_1').map((w) => w.id), ['wsp_1']);
    // Role update through setMembership keeps a single row.
    store.setMembership({ id: 'mem_2', workspaceId: w1.id, userId: 'usr_1', role: 'admin', createdAt: ts });
    assert.equal(store.listMembers(w1.id).length, 1);
    assert.equal(store.getMembership(w1.id, 'usr_1').role, 'admin');

    const p1 = store.createProgramme({
      id: 'prg_1', workspaceId: w1.id, name: 'P', platform: 'H1', scope: '', status: 'active',
      createdAt: ts, updatedAt: ts,
    });
    assert.equal(store.getProgramme(w2.id, p1.id), null, 'programme must not leak across tenants');
    assert.equal(store.getProgramme(w1.id, p1.id).name, 'P');

    const f1 = store.createFinding({
      id: 'fnd_1', workspaceId: w1.id, programmeId: p1.id, title: 'T', vulnClass: 'idor',
      target: 'https://x.test/a', parameter: 'id', cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
      severityScore: 9.8, severityBand: 'critical', status: 'new', reporter: 'r', assigneeId: null,
      description: '', reproduction: '', impact: '', remediation: '', fingerprint: 'fp1',
      duplicateOf: null, createdBy: 'usr_1', createdAt: ts, updatedAt: ts,
    });
    assert.equal(store.getFinding(w2.id, f1.id), null, 'finding must not leak across tenants');
    assert.equal(store.getFinding(w1.id, f1.id).fingerprint, 'fp1');
    assert.equal(store.listFindings(w1.id, { status: 'new' }).length, 1);
    assert.equal(store.listFindings(w1.id, { status: 'fixed' }).length, 0);
    assert.equal(store.listFindings(w1.id, { severity: 'critical' }).length, 1);
    const updated = store.updateFinding(w1.id, f1.id, { status: 'triaged' });
    assert.equal(updated.status, 'triaged');
    assert.equal(store.updateFinding(w2.id, f1.id, { status: 'fixed' }), null);
    assert.equal(store.deleteFinding(w2.id, f1.id), false);
    assert.equal(store.deleteFinding(w1.id, f1.id), true);

    store.insertAudit({ id: 'aud_1', workspaceId: w1.id, userId: 'usr_1', action: 'x', entity: 'finding', entityId: 'fnd_1', detail: '', createdAt: ts });
    assert.equal(store.listAudit(w1.id).length, 1);
    assert.equal(store.listAudit(w2.id).length, 0);

    const s1 = store.createSession({ id: 'ses_1', userId: 'usr_1', tokenHash: 'th', expiresAt: '2999-01-01T00:00:00.000Z', createdAt: ts });
    assert.equal(store.getSessionByTokenHash('th').id, s1.id);
    assert.equal(store.deleteSession(s1.id), true);
    assert.equal(store.getSessionByTokenHash('th'), null);

    assert.equal(store.deleteWorkspace(w1.id), true);
    assert.equal(store.getWorkspaceById(w1.id), null);
    assert.equal(store.listProgrammes(w1.id).length, 0, 'workspace delete cascades');
    store.close();
  });
}

exerciseContract('JsonStore (memory)', () => new JsonStore(null, { memory: true }));

exerciseContract('JsonStore (file persistence)', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vulndesk-json-'));
  return new JsonStore(path.join(dir, 'db.json'));
});

test('JsonStore (file) actually persists across instances', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vulndesk-json-'));
  const file = path.join(dir, 'db.json');
  const a = new JsonStore(file);
  a.createUser({ id: 'usr_p', email: 'p@x.test', name: 'P', passwordHash: 'h', createdAt: '2026-01-01T00:00:00.000Z' });
  const b = new JsonStore(file);
  assert.equal(b.getUserByEmail('p@x.test').id, 'usr_p');
});

// SQLite backend: only where node:sqlite exists (Node >= 22).
let SqliteStore = null;
try {
  ({ SqliteStore } = require('../src/store/sqlite-store'));
  require('node:sqlite');
} catch {
  SqliteStore = null;
}

if (SqliteStore) {
  exerciseContract('SqliteStore (:memory:)', () => new SqliteStore(':memory:'));
} else {
  test('SqliteStore skipped on this Node version (node:sqlite unavailable)', { skip: true }, () => {});
}
