'use strict';

/**
 * SQLite store — the primary backend on Node >= 22 (node:sqlite).
 *
 * Real relational schema with foreign keys and tenant-scoped queries: every
 * read or write of a workspace-owned row includes its workspace_id in the
 * WHERE clause, so cross-tenant access is impossible at the data layer, not
 * just by route-level convention.
 */

const SCHEMA = `
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL UNIQUE,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS workspaces (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  slug TEXT NOT NULL,
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS memberships (
  id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role TEXT NOT NULL,
  created_at TEXT NOT NULL,
  UNIQUE (workspace_id, user_id)
);
CREATE TABLE IF NOT EXISTS programmes (
  id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  platform TEXT NOT NULL DEFAULT '',
  scope TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'active',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS findings (
  id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  programme_id TEXT NOT NULL,
  title TEXT NOT NULL,
  vuln_class TEXT NOT NULL,
  target TEXT NOT NULL,
  parameter TEXT NOT NULL DEFAULT '',
  cvss_vector TEXT NOT NULL,
  severity_score REAL NOT NULL,
  severity_band TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'new',
  reporter TEXT NOT NULL DEFAULT '',
  assignee_id TEXT,
  description TEXT NOT NULL DEFAULT '',
  reproduction TEXT NOT NULL DEFAULT '',
  impact TEXT NOT NULL DEFAULT '',
  remediation TEXT NOT NULL DEFAULT '',
  fingerprint TEXT NOT NULL,
  duplicate_of TEXT,
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_findings_ws ON findings(workspace_id);
CREATE INDEX IF NOT EXISTS idx_findings_fp ON findings(workspace_id, fingerprint);
CREATE TABLE IF NOT EXISTS audit (
  id TEXT PRIMARY KEY,
  workspace_id TEXT,
  user_id TEXT,
  action TEXT NOT NULL,
  entity TEXT NOT NULL,
  entity_id TEXT,
  detail TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_ws ON audit(workspace_id, created_at);
`;

function userFromRow(r) {
  return r ? { id: r.id, email: r.email, name: r.name, passwordHash: r.password_hash, createdAt: r.created_at } : null;
}
function sessionFromRow(r) {
  return r ? { id: r.id, userId: r.user_id, tokenHash: r.token_hash, expiresAt: r.expires_at, createdAt: r.created_at } : null;
}
function workspaceFromRow(r) {
  return r ? { id: r.id, name: r.name, slug: r.slug, createdBy: r.created_by, createdAt: r.created_at } : null;
}
function membershipFromRow(r) {
  return r ? { id: r.id, workspaceId: r.workspace_id, userId: r.user_id, role: r.role, createdAt: r.created_at } : null;
}
function programmeFromRow(r) {
  return r ? {
    id: r.id, workspaceId: r.workspace_id, name: r.name, platform: r.platform,
    scope: r.scope, status: r.status, createdAt: r.created_at, updatedAt: r.updated_at,
  } : null;
}
function findingFromRow(r) {
  return r ? {
    id: r.id, workspaceId: r.workspace_id, programmeId: r.programme_id, title: r.title,
    vulnClass: r.vuln_class, target: r.target, parameter: r.parameter,
    cvssVector: r.cvss_vector, severityScore: r.severity_score, severityBand: r.severity_band,
    status: r.status, reporter: r.reporter, assigneeId: r.assignee_id,
    description: r.description, reproduction: r.reproduction, impact: r.impact,
    remediation: r.remediation, fingerprint: r.fingerprint, duplicateOf: r.duplicate_of,
    createdBy: r.created_by, createdAt: r.created_at, updatedAt: r.updated_at,
  } : null;
}
function auditFromRow(r) {
  return r ? {
    id: r.id, workspaceId: r.workspace_id, userId: r.user_id, action: r.action,
    entity: r.entity, entityId: r.entity_id, detail: r.detail, createdAt: r.created_at,
  } : null;
}

class SqliteStore {
  constructor(filePath) {
    // Required lazily so this module can be loaded on Node versions
    // without node:sqlite (the factory decides which backend to build).
    const { DatabaseSync } = require('node:sqlite');
    this.db = new DatabaseSync(filePath);
    this.db.exec(SCHEMA);
  }

  // ---- users & sessions -------------------------------------------------
  createUser(u) {
    this.db.prepare(
      'INSERT INTO users (id, email, name, password_hash, created_at) VALUES (?, ?, ?, ?, ?)',
    ).run(u.id, u.email, u.name, u.passwordHash, u.createdAt);
    return { ...u };
  }
  getUserByEmail(email) {
    return userFromRow(
      this.db.prepare('SELECT * FROM users WHERE email = ?').get(String(email).toLowerCase()),
    );
  }
  getUserById(id) {
    return userFromRow(this.db.prepare('SELECT * FROM users WHERE id = ?').get(id));
  }
  createSession(s) {
    this.db.prepare(
      'INSERT INTO sessions (id, user_id, token_hash, expires_at, created_at) VALUES (?, ?, ?, ?, ?)',
    ).run(s.id, s.userId, s.tokenHash, s.expiresAt, s.createdAt);
    return { ...s };
  }
  getSessionByTokenHash(tokenHash) {
    return sessionFromRow(
      this.db.prepare('SELECT * FROM sessions WHERE token_hash = ?').get(tokenHash),
    );
  }
  deleteSession(id) {
    return this.db.prepare('DELETE FROM sessions WHERE id = ?').run(id).changes > 0;
  }

  // ---- workspaces & memberships ----------------------------------------
  createWorkspace(w) {
    this.db.prepare(
      'INSERT INTO workspaces (id, name, slug, created_by, created_at) VALUES (?, ?, ?, ?, ?)',
    ).run(w.id, w.name, w.slug, w.createdBy, w.createdAt);
    return { ...w };
  }
  getWorkspaceById(id) {
    return workspaceFromRow(this.db.prepare('SELECT * FROM workspaces WHERE id = ?').get(id));
  }
  listWorkspacesForUser(userId) {
    return this.db
      .prepare(
        `SELECT w.* FROM workspaces w
         JOIN memberships m ON m.workspace_id = w.id
         WHERE m.user_id = ? ORDER BY w.created_at`,
      )
      .all(userId)
      .map(workspaceFromRow);
  }
  updateWorkspace(id, patch) {
    const current = this.getWorkspaceById(id);
    if (!current) return null;
    const next = { ...current, ...patch };
    this.db.prepare('UPDATE workspaces SET name = ?, slug = ? WHERE id = ?')
      .run(next.name, next.slug, id);
    return next;
  }
  deleteWorkspace(id) {
    return this.db.prepare('DELETE FROM workspaces WHERE id = ?').run(id).changes > 0;
  }

  setMembership(m) {
    this.db.prepare(
      `INSERT INTO memberships (id, workspace_id, user_id, role, created_at)
       VALUES (?, ?, ?, ?, ?)
       ON CONFLICT (workspace_id, user_id) DO UPDATE SET role = excluded.role`,
    ).run(m.id, m.workspaceId, m.userId, m.role, m.createdAt);
    return this.getMembership(m.workspaceId, m.userId);
  }
  getMembership(workspaceId, userId) {
    return membershipFromRow(
      this.db.prepare('SELECT * FROM memberships WHERE workspace_id = ? AND user_id = ?')
        .get(workspaceId, userId),
    );
  }
  listMembers(workspaceId) {
    return this.db.prepare('SELECT * FROM memberships WHERE workspace_id = ?')
      .all(workspaceId).map(membershipFromRow);
  }
  removeMembership(workspaceId, userId) {
    return this.db.prepare('DELETE FROM memberships WHERE workspace_id = ? AND user_id = ?')
      .run(workspaceId, userId).changes > 0;
  }

  // ---- programmes --------------------------------------------------------
  createProgramme(p) {
    this.db.prepare(
      `INSERT INTO programmes (id, workspace_id, name, platform, scope, status, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run(p.id, p.workspaceId, p.name, p.platform, p.scope, p.status, p.createdAt, p.updatedAt);
    return { ...p };
  }
  getProgramme(workspaceId, id) {
    return programmeFromRow(
      this.db.prepare('SELECT * FROM programmes WHERE workspace_id = ? AND id = ?')
        .get(workspaceId, id),
    );
  }
  listProgrammes(workspaceId) {
    return this.db.prepare('SELECT * FROM programmes WHERE workspace_id = ? ORDER BY created_at')
      .all(workspaceId).map(programmeFromRow);
  }
  updateProgramme(workspaceId, id, patch) {
    const current = this.getProgramme(workspaceId, id);
    if (!current) return null;
    const next = { ...current, ...patch };
    this.db.prepare(
      `UPDATE programmes SET name = ?, platform = ?, scope = ?, status = ?, updated_at = ?
       WHERE workspace_id = ? AND id = ?`,
    ).run(next.name, next.platform, next.scope, next.status, next.updatedAt, workspaceId, id);
    return next;
  }
  deleteProgramme(workspaceId, id) {
    return this.db.prepare('DELETE FROM programmes WHERE workspace_id = ? AND id = ?')
      .run(workspaceId, id).changes > 0;
  }

  // ---- findings ----------------------------------------------------------
  createFinding(f) {
    this.db.prepare(
      `INSERT INTO findings (id, workspace_id, programme_id, title, vuln_class, target, parameter,
        cvss_vector, severity_score, severity_band, status, reporter, assignee_id, description,
        reproduction, impact, remediation, fingerprint, duplicate_of, created_by, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run(
      f.id, f.workspaceId, f.programmeId, f.title, f.vulnClass, f.target, f.parameter,
      f.cvssVector, f.severityScore, f.severityBand, f.status, f.reporter, f.assigneeId,
      f.description, f.reproduction, f.impact, f.remediation, f.fingerprint, f.duplicateOf,
      f.createdBy, f.createdAt, f.updatedAt,
    );
    return { ...f };
  }
  getFinding(workspaceId, id) {
    return findingFromRow(
      this.db.prepare('SELECT * FROM findings WHERE workspace_id = ? AND id = ?')
        .get(workspaceId, id),
    );
  }
  listFindings(workspaceId, filters = {}) {
    let sql = 'SELECT * FROM findings WHERE workspace_id = ?';
    const args = [workspaceId];
    if (filters.programmeId) { sql += ' AND programme_id = ?'; args.push(filters.programmeId); }
    if (filters.status) { sql += ' AND status = ?'; args.push(filters.status); }
    if (filters.severity) { sql += ' AND severity_band = ?'; args.push(filters.severity); }
    if (filters.assigneeId) { sql += ' AND assignee_id = ?'; args.push(filters.assigneeId); }
    sql += ' ORDER BY created_at DESC';
    return this.db.prepare(sql).all(...args).map(findingFromRow);
  }
  updateFinding(workspaceId, id, patch) {
    const current = this.getFinding(workspaceId, id);
    if (!current) return null;
    const next = { ...current, ...patch };
    this.db.prepare(
      `UPDATE findings SET programme_id = ?, title = ?, vuln_class = ?, target = ?, parameter = ?,
         cvss_vector = ?, severity_score = ?, severity_band = ?, status = ?, reporter = ?,
         assignee_id = ?, description = ?, reproduction = ?, impact = ?, remediation = ?,
         fingerprint = ?, duplicate_of = ?, updated_at = ?
       WHERE workspace_id = ? AND id = ?`,
    ).run(
      next.programmeId, next.title, next.vulnClass, next.target, next.parameter,
      next.cvssVector, next.severityScore, next.severityBand, next.status, next.reporter,
      next.assigneeId, next.description, next.reproduction, next.impact, next.remediation,
      next.fingerprint, next.duplicateOf, next.updatedAt, workspaceId, id,
    );
    return next;
  }
  deleteFinding(workspaceId, id) {
    return this.db.prepare('DELETE FROM findings WHERE workspace_id = ? AND id = ?')
      .run(workspaceId, id).changes > 0;
  }

  // ---- audit ---------------------------------------------------------------
  insertAudit(a) {
    this.db.prepare(
      `INSERT INTO audit (id, workspace_id, user_id, action, entity, entity_id, detail, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run(a.id, a.workspaceId, a.userId, a.action, a.entity, a.entityId, a.detail, a.createdAt);
    return { ...a };
  }
  listAudit(workspaceId, limit = 100) {
    return this.db.prepare(
      'SELECT * FROM audit WHERE workspace_id = ? ORDER BY created_at DESC, rowid DESC LIMIT ?',
    ).all(workspaceId, limit).map(auditFromRow);
  }

  close() {
    this.db.close();
  }
}

module.exports = { SqliteStore };
