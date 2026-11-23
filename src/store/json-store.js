'use strict';

const fs = require('node:fs');
const path = require('node:path');

/**
 * JSON-file store.
 *
 * The portable backend: zero native dependencies, runs on any Node >= 18.
 * Data lives in memory as Maps and is persisted write-through to a single
 * JSON document using an atomic write (temp file + rename), so a crash
 * mid-write can never corrupt the store. With { memory: true } nothing
 * touches disk (used by tests).
 *
 * This is a real data layer, not a dump of route logic: it owns all
 * persistence concerns and enforces the tenant-scoping contract.
 */

const TABLES = ['users', 'sessions', 'workspaces', 'memberships', 'programmes', 'findings', 'audit'];

class JsonStore {
  constructor(filePath, { memory = false } = {}) {
    this.filePath = memory ? null : filePath;
    this.data = {};
    for (const t of TABLES) this.data[t] = new Map();
    if (this.filePath && fs.existsSync(this.filePath)) {
      const raw = JSON.parse(fs.readFileSync(this.filePath, 'utf8'));
      for (const t of TABLES) {
        for (const row of raw[t] || []) this.data[t].set(row.id, row);
      }
    }
  }

  _persist() {
    if (!this.filePath) return;
    const out = {};
    for (const t of TABLES) out[t] = [...this.data[t].values()];
    fs.mkdirSync(path.dirname(this.filePath), { recursive: true });
    const tmp = `${this.filePath}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(out, null, 2));
    fs.renameSync(tmp, this.filePath);
  }

  _put(table, row) {
    this.data[table].set(row.id, { ...row });
    this._persist();
    return { ...row };
  }

  _get(table, id) {
    const row = this.data[table].get(id);
    return row ? { ...row } : null;
  }

  _all(table) {
    return [...this.data[table].values()].map((r) => ({ ...r }));
  }

  _patch(table, id, patch) {
    const row = this.data[table].get(id);
    if (!row) return null;
    const next = { ...row, ...patch };
    this.data[table].set(id, next);
    this._persist();
    return { ...next };
  }

  _del(table, id) {
    const ok = this.data[table].delete(id);
    if (ok) this._persist();
    return ok;
  }

  // ---- users & sessions -------------------------------------------------
  createUser(u) { return this._put('users', u); }
  getUserByEmail(email) {
    return this._all('users').find((u) => u.email === String(email).toLowerCase()) || null;
  }
  getUserById(id) { return this._get('users', id); }

  createSession(s) { return this._put('sessions', s); }
  getSessionByTokenHash(tokenHash) {
    return this._all('sessions').find((s) => s.tokenHash === tokenHash) || null;
  }
  deleteSession(id) { return this._del('sessions', id); }

  // ---- workspaces & memberships ----------------------------------------
  createWorkspace(w) { return this._put('workspaces', w); }
  getWorkspaceById(id) { return this._get('workspaces', id); }
  listWorkspacesForUser(userId) {
    const ids = new Set(
      this._all('memberships').filter((m) => m.userId === userId).map((m) => m.workspaceId),
    );
    return this._all('workspaces').filter((w) => ids.has(w.id));
  }
  updateWorkspace(id, patch) { return this._patch('workspaces', id, patch); }
  deleteWorkspace(id) {
    // Cascade: everything owned by the workspace goes with it.
    for (const t of ['memberships', 'programmes', 'findings', 'audit']) {
      for (const row of this._all(t)) {
        if (row.workspaceId === id) this.data[t].delete(row.id);
      }
    }
    const ok = this._del('workspaces', id);
    this._persist();
    return ok;
  }

  setMembership(m) {
    const existing = this._all('memberships').find(
      (x) => x.workspaceId === m.workspaceId && x.userId === m.userId,
    );
    if (existing) return this._patch('memberships', existing.id, { role: m.role });
    return this._put('memberships', m);
  }
  getMembership(workspaceId, userId) {
    return (
      this._all('memberships').find(
        (m) => m.workspaceId === workspaceId && m.userId === userId,
      ) || null
    );
  }
  listMembers(workspaceId) {
    return this._all('memberships').filter((m) => m.workspaceId === workspaceId);
  }
  removeMembership(workspaceId, userId) {
    const m = this.getMembership(workspaceId, userId);
    return m ? this._del('memberships', m.id) : false;
  }

  // ---- programmes --------------------------------------------------------
  createProgramme(p) { return this._put('programmes', p); }
  getProgramme(workspaceId, id) {
    const p = this._get('programmes', id);
    return p && p.workspaceId === workspaceId ? p : null;
  }
  listProgrammes(workspaceId) {
    return this._all('programmes').filter((p) => p.workspaceId === workspaceId);
  }
  updateProgramme(workspaceId, id, patch) {
    return this.getProgramme(workspaceId, id) ? this._patch('programmes', id, patch) : null;
  }
  deleteProgramme(workspaceId, id) {
    return this.getProgramme(workspaceId, id) ? this._del('programmes', id) : false;
  }

  // ---- findings ----------------------------------------------------------
  createFinding(f) { return this._put('findings', f); }
  getFinding(workspaceId, id) {
    const f = this._get('findings', id);
    return f && f.workspaceId === workspaceId ? f : null;
  }
  listFindings(workspaceId, filters = {}) {
    let rows = this._all('findings').filter((f) => f.workspaceId === workspaceId);
    if (filters.programmeId) rows = rows.filter((f) => f.programmeId === filters.programmeId);
    if (filters.status) rows = rows.filter((f) => f.status === filters.status);
    if (filters.severity) rows = rows.filter((f) => f.severityBand === filters.severity);
    if (filters.assigneeId) rows = rows.filter((f) => f.assigneeId === filters.assigneeId);
    rows.sort((a, b) => (a.createdAt < b.createdAt ? 1 : -1));
    return rows;
  }
  updateFinding(workspaceId, id, patch) {
    return this.getFinding(workspaceId, id) ? this._patch('findings', id, patch) : null;
  }
  deleteFinding(workspaceId, id) {
    return this.getFinding(workspaceId, id) ? this._del('findings', id) : false;
  }

  // ---- audit ---------------------------------------------------------------
  insertAudit(a) { return this._put('audit', a); }
  listAudit(workspaceId, limit = 100) {
    return this._all('audit')
      .filter((a) => a.workspaceId === workspaceId)
      .sort((a, b) => (a.createdAt < b.createdAt ? 1 : -1))
      .slice(0, limit);
  }

  close() {}
}

module.exports = { JsonStore };
