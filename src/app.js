'use strict';

const fs = require('node:fs');
const path = require('node:path');

const {
  hashPassword, verifyPassword, generateSessionToken, hashToken, newId, SESSION_TTL_MS,
} = require('./auth');
const { isRole, can } = require('./rbac');
const cvss = require('./cvss');
const dedupe = require('./dedupe');
const { STATUSES, canTransition } = require('./store/contract');
const { recordAudit } = require('./audit');
const { renderMarkdown } = require('./report');
const views = require('./views');

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

const now = () => new Date().toISOString();

// ---------------------------------------------------------------------------
// HTTP plumbing
// ---------------------------------------------------------------------------

function parseCookies(req) {
  const out = {};
  const header = req.headers.cookie || '';
  for (const part of header.split(';')) {
    const idx = part.indexOf('=');
    if (idx > -1) out[part.slice(0, idx).trim()] = decodeURIComponent(part.slice(idx + 1).trim());
  }
  return out;
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > 1024 * 1024) {
        reject(new HttpError(413, 'Request body too large'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      const raw = Buffer.concat(chunks).toString('utf8');
      if (!raw) return resolve({});
      const type = req.headers['content-type'] || '';
      try {
        if (type.includes('application/json')) return resolve(JSON.parse(raw));
        if (type.includes('application/x-www-form-urlencoded')) {
          return resolve(Object.fromEntries(new URLSearchParams(raw)));
        }
        return resolve(JSON.parse(raw));
      } catch {
        return reject(new HttpError(400, 'Malformed request body'));
      }
    });
    req.on('error', reject);
  });
}

function sendJson(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8' });
  res.end(body);
}

function sendHtml(res, status, html) {
  res.writeHead(status, { 'content-type': 'text/html; charset=utf-8' });
  res.end(html);
}

function redirect(res, location) {
  res.writeHead(303, { location });
  res.end();
}

function wantsJson(req, body) {
  return (req.headers['content-type'] || '').includes('application/json') ||
    (req.headers.accept || '').includes('application/json') && body !== undefined && req.method !== 'GET';
}

// ---------------------------------------------------------------------------
// Router (tiny, path params only)
// ---------------------------------------------------------------------------

function compile(pattern) {
  const keys = [];
  const regex = new RegExp(
    '^' +
      pattern
        .split('/')
        .map((seg) => {
          if (seg.startsWith(':')) {
            keys.push(seg.slice(1));
            return '([^/]+)';
          }
          return seg.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        })
        .join('/') +
      '$',
  );
  return { regex, keys };
}

// ---------------------------------------------------------------------------
// App factory
// ---------------------------------------------------------------------------

function createApp({ store }) {
  if (!store) throw new Error('createApp requires a store');
  const routes = [];
  const route = (method, pattern, handler) => {
    const { regex, keys } = compile(pattern);
    routes.push({ method, regex, keys, handler });
  };

  // ---- session / tenancy helpers -----------------------------------------

  function sessionUser(req) {
    let token = null;
    const authz = req.headers.authorization || '';
    if (authz.startsWith('Bearer ')) token = authz.slice(7);
    if (!token) token = parseCookies(req).vd_session || null;
    if (!token) return null;
    const session = store.getSessionByTokenHash(hashToken(token));
    if (!session) return null;
    if (new Date(session.expiresAt) < new Date()) {
      store.deleteSession(session.id);
      return null;
    }
    const user = store.getUserById(session.userId);
    return user ? { user, session } : null;
  }

  function startSession(res, userId) {
    const token = generateSessionToken();
    store.createSession({
      id: newId('ses'),
      userId,
      tokenHash: hashToken(token),
      expiresAt: new Date(Date.now() + SESSION_TTL_MS).toISOString(),
      createdAt: now(),
    });
    const secure = process.env.VULNDESK_SECURE_COOKIES === '1' ? '; Secure' : '';
    res.setHeader(
      'set-cookie',
      `vd_session=${token}; HttpOnly; Path=/; SameSite=Lax; Max-Age=${Math.floor(SESSION_TTL_MS / 1000)}${secure}`,
    );
    return token;
  }

  function requireApiAuth(req) {
    const ctx = sessionUser(req);
    if (!ctx) throw new HttpError(401, 'Authentication required');
    return ctx;
  }

  function requirePageAuth(req, res) {
    const ctx = sessionUser(req);
    if (!ctx) {
      redirect(res, '/login');
      return null;
    }
    return ctx;
  }

  /**
   * Resolve the tenant context. A workspace the user does not belong to is
   * indistinguishable from one that does not exist: 404 either way.
   */
  function tenant(req, wsId) {
    const { user } = requireApiAuth(req);
    const workspace = store.getWorkspaceById(wsId);
    if (!workspace) throw new HttpError(404, 'Workspace not found');
    const membership = store.getMembership(wsId, user.id);
    if (!membership) throw new HttpError(404, 'Workspace not found');
    return { user, workspace, membership, role: membership.role };
  }

  function guard(ctx, permission) {
    if (!can(ctx.role, permission)) {
      throw new HttpError(403, `Role "${ctx.role}" lacks permission "${permission}"`);
    }
  }

  function memberDirectory(wsId) {
    return store.listMembers(wsId).map((m) => {
      const u = store.getUserById(m.userId);
      return { userId: m.userId, role: m.role, name: u ? u.name : m.userId, email: u ? u.email : '' };
    });
  }

  function computeStats(wsId) {
    const findings = store.listFindings(wsId);
    const bySeverity = Object.fromEntries(cvss.BANDS.map((b) => [b, 0]));
    const byStatus = Object.fromEntries(STATUSES.map((s) => [s, 0]));
    const byProgramme = {};
    for (const f of findings) {
      bySeverity[f.severityBand] = (bySeverity[f.severityBand] || 0) + 1;
      byStatus[f.status] = (byStatus[f.status] || 0) + 1;
      const p = (byProgramme[f.programmeId] ||= { total: 0, open: 0 });
      p.total += 1;
      if (['new', 'triaged', 'accepted'].includes(f.status)) p.open += 1;
    }
    return { total: findings.length, bySeverity, byStatus, byProgramme };
  }

  // ---- finding creation / mutation (shared by API + forms) ----------------

  function buildFinding(ctx, body) {
    const programme = store.getProgramme(ctx.workspace.id, body.programmeId || '');
    if (!programme) throw new HttpError(400, 'programmeId does not reference a programme in this workspace');
    if (!body.title || !String(body.title).trim()) throw new HttpError(400, 'title is required');
    if (!body.vulnClass || !String(body.vulnClass).trim()) throw new HttpError(400, 'vulnClass is required');
    if (!body.target || !String(body.target).trim()) throw new HttpError(400, 'target is required');
    if (!body.cvssVector) throw new HttpError(400, 'cvssVector is required');
    let scored;
    try {
      scored = cvss.baseScore(String(body.cvssVector));
    } catch (err) {
      throw new HttpError(400, `Invalid CVSS vector: ${err.message}`);
    }
    const draft = {
      vulnClass: String(body.vulnClass),
      target: String(body.target),
      parameter: body.parameter ? String(body.parameter) : '',
    };
    const assessment = dedupe.assess(draft, store.listFindings(ctx.workspace.id));
    const ts = now();
    const finding = {
      id: newId('fnd'),
      workspaceId: ctx.workspace.id,
      programmeId: programme.id,
      title: String(body.title).trim(),
      vulnClass: draft.vulnClass,
      target: draft.target,
      parameter: draft.parameter,
      cvssVector: scored.vector,
      severityScore: scored.score,
      severityBand: cvss.severityBand(scored.score),
      status: 'new',
      reporter: body.reporter ? String(body.reporter) : '',
      assigneeId: null,
      description: body.description ? String(body.description) : '',
      reproduction: body.reproduction ? String(body.reproduction) : '',
      impact: body.impact ? String(body.impact) : '',
      remediation: body.remediation ? String(body.remediation) : '',
      fingerprint: assessment.fingerprint,
      duplicateOf: assessment.exactMatch ? assessment.exactMatch.id : null,
      createdBy: ctx.user.id,
      createdAt: ts,
      updatedAt: ts,
    };
    store.createFinding(finding);
    recordAudit(store, {
      workspaceId: ctx.workspace.id, userId: ctx.user.id,
      action: 'finding.create', entity: 'finding', entityId: finding.id,
      detail: assessment.exactMatch ? `possible duplicate of ${assessment.exactMatch.id}` : '',
    });
    return { finding, assessment };
  }

  function changeStatus(ctx, finding, nextStatus, duplicateOf) {
    if (!STATUSES.includes(nextStatus)) throw new HttpError(400, `Unknown status: ${nextStatus}`);
    if (!canTransition(finding.status, nextStatus)) {
      throw new HttpError(
        400,
        `Invalid status transition ${finding.status} -> ${nextStatus}. Allowed: ${(require('./store/contract').TRANSITIONS[finding.status] || []).join(', ') || '(none)'}`,
      );
    }
    const patch = { status: nextStatus, updatedAt: now() };
    if (nextStatus === 'duplicate') {
      if (duplicateOf) {
        const original = store.getFinding(ctx.workspace.id, duplicateOf);
        if (!original) throw new HttpError(400, 'duplicateOf does not reference a finding in this workspace');
        patch.duplicateOf = duplicateOf;
      } else if (!finding.duplicateOf) {
        throw new HttpError(400, 'Marking as duplicate requires duplicateOf (the original finding id)');
      }
    }
    if (finding.status === 'duplicate' && nextStatus === 'new') patch.duplicateOf = null;
    const updated = store.updateFinding(ctx.workspace.id, finding.id, patch);
    recordAudit(store, {
      workspaceId: ctx.workspace.id, userId: ctx.user.id,
      action: 'finding.status', entity: 'finding', entityId: finding.id,
      detail: `${finding.status} -> ${nextStatus}`,
    });
    return updated;
  }

  // =========================================================================
  // Auth routes
  // =========================================================================

  async function handleRegister(req, res) {
    const body = await readBody(req);
    const email = String(body.email || '').trim().toLowerCase();
    const name = String(body.name || '').trim();
    const password = String(body.password || '');
    if (!name) throw new HttpError(400, 'name is required');
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) throw new HttpError(400, 'A valid email is required');
    if (store.getUserByEmail(email)) throw new HttpError(409, 'An account with this email already exists');
    let passwordHash;
    try {
      passwordHash = hashPassword(password);
    } catch (err) {
      throw new HttpError(400, err.message);
    }
    const user = { id: newId('usr'), email, name, passwordHash, createdAt: now() };
    store.createUser(user);
    recordAudit(store, { userId: user.id, action: 'auth.register', entity: 'user', entityId: user.id });
    startSession(res, user.id);
    if (wantsJson(req, body)) {
      return sendJson(res, 201, { id: user.id, email: user.email, name: user.name });
    }
    return redirect(res, '/');
  }

  async function handleLogin(req, res) {
    const body = await readBody(req);
    const email = String(body.email || '').trim().toLowerCase();
    const user = store.getUserByEmail(email);
    if (!user || !verifyPassword(String(body.password || ''), user.passwordHash)) {
      if (wantsJson(req, body)) throw new HttpError(401, 'Invalid email or password');
      return sendHtml(res, 401, views.loginPage('Invalid email or password'));
    }
    startSession(res, user.id);
    if (wantsJson(req, body)) {
      return sendJson(res, 200, { id: user.id, email: user.email, name: user.name });
    }
    return redirect(res, '/');
  }

  async function handleLogout(req, res) {
    const ctx = sessionUser(req);
    if (ctx) store.deleteSession(ctx.session.id);
    res.setHeader('set-cookie', 'vd_session=; HttpOnly; Path=/; Max-Age=0');
    if ((req.headers['content-type'] || '').includes('application/json') || (req.url || '').startsWith('/api/')) {
      return sendJson(res, 200, { ok: true });
    }
    return redirect(res, '/login');
  }

  route('POST', '/auth/register', handleRegister);
  route('POST', '/api/auth/register', handleRegister);
  route('POST', '/auth/login', handleLogin);
  route('POST', '/api/auth/login', handleLogin);
  route('POST', '/auth/logout', handleLogout);
  route('POST', '/api/auth/logout', handleLogout);

  route('GET', '/api/me', async (req, res) => {
    const { user } = requireApiAuth(req);
    sendJson(res, 200, { id: user.id, email: user.email, name: user.name });
  });

  // =========================================================================
  // Workspaces API
  // =========================================================================

  route('POST', '/api/workspaces', async (req, res) => {
    const { user } = requireApiAuth(req);
    const body = await readBody(req);
    const name = String(body.name || '').trim();
    if (!name) throw new HttpError(400, 'name is required');
    const slug =
      name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '') +
      '-' + newId('').slice(1, 5).toLowerCase();
    const workspace = { id: newId('wsp'), name, slug, createdBy: user.id, createdAt: now() };
    store.createWorkspace(workspace);
    store.setMembership({
      id: newId('mem'), workspaceId: workspace.id, userId: user.id, role: 'owner', createdAt: now(),
    });
    recordAudit(store, {
      workspaceId: workspace.id, userId: user.id,
      action: 'workspace.create', entity: 'workspace', entityId: workspace.id,
    });
    sendJson(res, 201, workspace);
  });

  route('GET', '/api/workspaces', async (req, res) => {
    const { user } = requireApiAuth(req);
    sendJson(res, 200, store.listWorkspacesForUser(user.id));
  });

  route('GET', '/api/workspaces/:wsId', async (req, res, params) => {
    const ctx = tenant(req, params.wsId);
    sendJson(res, 200, { ...ctx.workspace, role: ctx.role });
  });

  route('PATCH', '/api/workspaces/:wsId', async (req, res, params) => {
    const ctx = tenant(req, params.wsId);
    guard(ctx, 'workspace.manage');
    const body = await readBody(req);
    const patch = {};
    if (body.name) patch.name = String(body.name).trim();
    const updated = store.updateWorkspace(ctx.workspace.id, patch);
    recordAudit(store, {
      workspaceId: ctx.workspace.id, userId: ctx.user.id,
      action: 'workspace.update', entity: 'workspace', entityId: ctx.workspace.id,
      detail: JSON.stringify(patch),
    });
    sendJson(res, 200, updated);
  });

  route('DELETE', '/api/workspaces/:wsId', async (req, res, params) => {
    const ctx = tenant(req, params.wsId);
    guard(ctx, 'workspace.manage');
    store.deleteWorkspace(ctx.workspace.id);
    sendJson(res, 200, { ok: true });
  });

  // ---- members -------------------------------------------------------------

  route('GET', '/api/workspaces/:wsId/members', async (req, res, params) => {
    const ctx = tenant(req, params.wsId);
    guard(ctx, 'workspace.read');
    sendJson(res, 200, memberDirectory(ctx.workspace.id));
  });

  route('POST', '/api/workspaces/:wsId/members', async (req, res, params) => {
    const ctx = tenant(req, params.wsId);
    guard(ctx, 'members.manage');
    const body = await readBody(req);
    const role = String(body.role || 'viewer');
    if (!isRole(role)) throw new HttpError(400, `Unknown role: ${role}`);
    if (role === 'owner') throw new HttpError(400, 'The owner role cannot be granted');
    const target = store.getUserByEmail(String(body.email || ''));
    if (!target) throw new HttpError(404, 'No registered user with that email');
    const existing = store.getMembership(ctx.workspace.id, target.id);
    if (existing && existing.role === 'owner') throw new HttpError(400, 'The workspace owner cannot be re-roled');
    store.setMembership({
      id: existing ? existing.id : newId('mem'),
      workspaceId: ctx.workspace.id, userId: target.id, role, createdAt: now(),
    });
    recordAudit(store, {
      workspaceId: ctx.workspace.id, userId: ctx.user.id,
      action: existing ? 'member.role' : 'member.add', entity: 'user', entityId: target.id,
      detail: `role=${role}`,
    });
    sendJson(res, 201, { userId: target.id, email: target.email, name: target.name, role });
  });

  route('DELETE', '/api/workspaces/:wsId/members/:userId', async (req, res, params) => {
    const ctx = tenant(req, params.wsId);
    guard(ctx, 'members.manage');
    const existing = store.getMembership(ctx.workspace.id, params.userId);
    if (!existing) throw new HttpError(404, 'Membership not found');
    if (existing.role === 'owner') throw new HttpError(400, 'The workspace owner cannot be removed');
    store.removeMembership(ctx.workspace.id, params.userId);
    recordAudit(store, {
      workspaceId: ctx.workspace.id, userId: ctx.user.id,
      action: 'member.remove', entity: 'user', entityId: params.userId,
    });
    sendJson(res, 200, { ok: true });
  });

  // ---- programmes ------------------------------------------------------------

  route('GET', '/api/workspaces/:wsId/programmes', async (req, res, params) => {
    const ctx = tenant(req, params.wsId);
    guard(ctx, 'workspace.read');
    sendJson(res, 200, store.listProgrammes(ctx.workspace.id));
  });

  route('POST', '/api/workspaces/:wsId/programmes', async (req, res, params) => {
    const ctx = tenant(req, params.wsId);
    guard(ctx, 'programmes.write');
    const body = await readBody(req);
    if (!body.name || !String(body.name).trim()) throw new HttpError(400, 'name is required');
    const ts = now();
    const programme = {
      id: newId('prg'), workspaceId: ctx.workspace.id, name: String(body.name).trim(),
      platform: body.platform ? String(body.platform) : '',
      scope: body.scope ? String(body.scope) : '',
      status: body.status ? String(body.status) : 'active',
      createdAt: ts, updatedAt: ts,
    };
    store.createProgramme(programme);
    recordAudit(store, {
      workspaceId: ctx.workspace.id, userId: ctx.user.id,
      action: 'programme.create', entity: 'programme', entityId: programme.id,
    });
    sendJson(res, 201, programme);
  });

  route('GET', '/api/workspaces/:wsId/programmes/:id', async (req, res, params) => {
    const ctx = tenant(req, params.wsId);
    guard(ctx, 'workspace.read');
    const programme = store.getProgramme(ctx.workspace.id, params.id);
    if (!programme) throw new HttpError(404, 'Programme not found');
    sendJson(res, 200, programme);
  });

  route('PATCH', '/api/workspaces/:wsId/programmes/:id', async (req, res, params) => {
    const ctx = tenant(req, params.wsId);
    guard(ctx, 'programmes.write');
    const body = await readBody(req);
    const patch = { updatedAt: now() };
    for (const k of ['name', 'platform', 'scope', 'status']) {
      if (body[k] !== undefined) patch[k] = String(body[k]);
    }
    const updated = store.updateProgramme(ctx.workspace.id, params.id, patch);
    if (!updated) throw new HttpError(404, 'Programme not found');
    recordAudit(store, {
      workspaceId: ctx.workspace.id, userId: ctx.user.id,
      action: 'programme.update', entity: 'programme', entityId: params.id,
    });
    sendJson(res, 200, updated);
  });

  route('DELETE', '/api/workspaces/:wsId/programmes/:id', async (req, res, params) => {
    const ctx = tenant(req, params.wsId);
    guard(ctx, 'programmes.write');
    if (!store.deleteProgramme(ctx.workspace.id, params.id)) {
      throw new HttpError(404, 'Programme not found');
    }
    recordAudit(store, {
      workspaceId: ctx.workspace.id, userId: ctx.user.id,
      action: 'programme.delete', entity: 'programme', entityId: params.id,
    });
    sendJson(res, 200, { ok: true });
  });

  // ---- findings ---------------------------------------------------------------

  route('GET', '/api/workspaces/:wsId/findings', async (req, res, params, query) => {
    const ctx = tenant(req, params.wsId);
    guard(ctx, 'findings.read');
    const filters = {};
    if (query.programmeId) filters.programmeId = query.programmeId;
    if (query.status) filters.status = query.status;
    if (query.severity) filters.severity = query.severity;
    if (query.assigneeId) filters.assigneeId = query.assigneeId;
    sendJson(res, 200, store.listFindings(ctx.workspace.id, filters));
  });

  route('POST', '/api/workspaces/:wsId/findings', async (req, res, params) => {
    const ctx = tenant(req, params.wsId);
    guard(ctx, 'findings.write');
    const body = await readBody(req);
    const { finding, assessment } = buildFinding(ctx, body);
    sendJson(res, 201, {
      ...finding,
      dedupe: {
        fingerprint: assessment.fingerprint,
        possibleDuplicateOf: assessment.exactMatch ? assessment.exactMatch.id : null,
        similar: assessment.similar.map((f) => f.id),
      },
    });
  });

  route('GET', '/api/workspaces/:wsId/findings/:id', async (req, res, params) => {
    const ctx = tenant(req, params.wsId);
    guard(ctx, 'findings.read');
    const finding = store.getFinding(ctx.workspace.id, params.id);
    if (!finding) throw new HttpError(404, 'Finding not found');
    const assessment = dedupe.assess(finding, store.listFindings(ctx.workspace.id));
    sendJson(res, 200, {
      ...finding,
      dedupe: {
        fingerprint: assessment.fingerprint,
        possibleDuplicateOf: assessment.exactMatch ? assessment.exactMatch.id : null,
        similar: assessment.similar.map((f) => f.id),
      },
    });
  });

  route('PATCH', '/api/workspaces/:wsId/findings/:id', async (req, res, params) => {
    const ctx = tenant(req, params.wsId);
    guard(ctx, 'findings.triage');
    const finding = store.getFinding(ctx.workspace.id, params.id);
    if (!finding) throw new HttpError(404, 'Finding not found');
    const body = await readBody(req);
    if (body.status !== undefined && body.status !== finding.status) {
      const updated = changeStatus(ctx, finding, String(body.status), body.duplicateOf);
      return sendJson(res, 200, updated);
    }
    const patch = { updatedAt: now() };
    for (const k of ['title', 'vulnClass', 'target', 'parameter', 'description', 'reproduction', 'impact', 'remediation', 'reporter']) {
      if (body[k] !== undefined) patch[k] = String(body[k]);
    }
    if (body.programmeId !== undefined) {
      if (!store.getProgramme(ctx.workspace.id, String(body.programmeId))) {
        throw new HttpError(400, 'programmeId does not reference a programme in this workspace');
      }
      patch.programmeId = String(body.programmeId);
    }
    if (body.cvssVector !== undefined) {
      let scored;
      try {
        scored = cvss.baseScore(String(body.cvssVector));
      } catch (err) {
        throw new HttpError(400, `Invalid CVSS vector: ${err.message}`);
      }
      patch.cvssVector = scored.vector;
      patch.severityScore = scored.score;
      patch.severityBand = cvss.severityBand(scored.score);
    }
    if (body.assigneeId !== undefined) {
      if (body.assigneeId !== null && body.assigneeId !== '') {
        if (!store.getMembership(ctx.workspace.id, String(body.assigneeId))) {
          throw new HttpError(400, 'assigneeId must be a workspace member (or null)');
        }
        patch.assigneeId = String(body.assigneeId);
      } else {
        patch.assigneeId = null;
      }
    }
    // Re-fingerprint if the dedupe triple changed.
    const merged = { ...finding, ...patch };
    patch.fingerprint = dedupe.fingerprint(merged);
    const updated = store.updateFinding(ctx.workspace.id, finding.id, patch);
    recordAudit(store, {
      workspaceId: ctx.workspace.id, userId: ctx.user.id,
      action: 'finding.update', entity: 'finding', entityId: finding.id,
      detail: Object.keys(patch).filter((k) => k !== 'updatedAt').join(','),
    });
    sendJson(res, 200, updated);
  });

  route('POST', '/api/workspaces/:wsId/findings/:id/status', async (req, res, params) => {
    const ctx = tenant(req, params.wsId);
    guard(ctx, 'findings.triage');
    const finding = store.getFinding(ctx.workspace.id, params.id);
    if (!finding) throw new HttpError(404, 'Finding not found');
    const body = await readBody(req);
    const updated = changeStatus(ctx, finding, String(body.status || ''), body.duplicateOf);
    sendJson(res, 200, updated);
  });

  route('POST', '/api/workspaces/:wsId/findings/:id/assign', async (req, res, params) => {
    const ctx = tenant(req, params.wsId);
    guard(ctx, 'findings.triage');
    const finding = store.getFinding(ctx.workspace.id, params.id);
    if (!finding) throw new HttpError(404, 'Finding not found');
    const body = await readBody(req);
    let assigneeId = body.assigneeId ? String(body.assigneeId) : null;
    if (assigneeId && !store.getMembership(ctx.workspace.id, assigneeId)) {
      throw new HttpError(400, 'assigneeId must be a workspace member (or null)');
    }
    const updated = store.updateFinding(ctx.workspace.id, finding.id, { assigneeId, updatedAt: now() });
    recordAudit(store, {
      workspaceId: ctx.workspace.id, userId: ctx.user.id,
      action: 'finding.assign', entity: 'finding', entityId: finding.id,
      detail: `assignee=${assigneeId || 'none'}`,
    });
    sendJson(res, 200, updated);
  });

  route('DELETE', '/api/workspaces/:wsId/findings/:id', async (req, res, params) => {
    const ctx = tenant(req, params.wsId);
    guard(ctx, 'findings.delete');
    if (!store.deleteFinding(ctx.workspace.id, params.id)) {
      throw new HttpError(404, 'Finding not found');
    }
    recordAudit(store, {
      workspaceId: ctx.workspace.id, userId: ctx.user.id,
      action: 'finding.delete', entity: 'finding', entityId: params.id,
    });
    sendJson(res, 200, { ok: true });
  });

  route('GET', '/api/workspaces/:wsId/findings/:id/report.md', async (req, res, params) => {
    const ctx = tenant(req, params.wsId);
    guard(ctx, 'findings.read');
    const finding = store.getFinding(ctx.workspace.id, params.id);
    if (!finding) throw new HttpError(404, 'Finding not found');
    const programme = store.getProgramme(ctx.workspace.id, finding.programmeId);
    const assignee = finding.assigneeId ? store.getUserById(finding.assigneeId) : null;
    const md = renderMarkdown(finding, {
      programmeName: programme ? programme.name : '',
      assigneeName: assignee ? assignee.name : '',
    });
    res.writeHead(200, {
      'content-type': 'text/markdown; charset=utf-8',
      'content-disposition': `attachment; filename="finding-${finding.id}.md"`,
    });
    res.end(md);
  });

  // ---- stats & audit -------------------------------------------------------------

  route('GET', '/api/workspaces/:wsId/stats', async (req, res, params) => {
    const ctx = tenant(req, params.wsId);
    guard(ctx, 'workspace.read');
    sendJson(res, 200, computeStats(ctx.workspace.id));
  });

  route('GET', '/api/workspaces/:wsId/audit', async (req, res, params, query) => {
    const ctx = tenant(req, params.wsId);
    guard(ctx, 'audit.read');
    const limit = Math.min(Number(query.limit) || 100, 500);
    sendJson(res, 200, store.listAudit(ctx.workspace.id, limit));
  });

  // =========================================================================
  // Pages (server-rendered)
  // =========================================================================

  route('GET', '/login', async (req, res) => {
    if (sessionUser(req)) return redirect(res, '/');
    sendHtml(res, 200, views.loginPage());
  });

  route('GET', '/register', async (req, res) => {
    if (sessionUser(req)) return redirect(res, '/');
    sendHtml(res, 200, views.registerPage());
  });

  route('GET', '/', async (req, res) => {
    const ctx = requirePageAuth(req, res);
    if (!ctx) return;
    const workspaces = store.listWorkspacesForUser(ctx.user.id);
    sendHtml(res, 200, views.homePage({ user: ctx.user, workspaces }));
  });

  route('POST', '/workspaces', async (req, res) => {
    const ctx = requirePageAuth(req, res);
    if (!ctx) return;
    const body = await readBody(req);
    const name = String(body.name || '').trim();
    if (!name) return sendHtml(res, 400, views.layout({ title: 'Error', user: ctx.user, body: '<h1>Workspace name is required</h1>' }));
    const slug =
      name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '') +
      '-' + newId('').slice(1, 5).toLowerCase();
    const workspace = { id: newId('wsp'), name, slug, createdBy: ctx.user.id, createdAt: now() };
    store.createWorkspace(workspace);
    store.setMembership({
      id: newId('mem'), workspaceId: workspace.id, userId: ctx.user.id, role: 'owner', createdAt: now(),
    });
    recordAudit(store, {
      workspaceId: workspace.id, userId: ctx.user.id,
      action: 'workspace.create', entity: 'workspace', entityId: workspace.id,
    });
    redirect(res, `/w/${workspace.id}/dashboard`);
  });

  function pageTenant(req, res, wsId) {
    const auth = requirePageAuth(req, res);
    if (!auth) return null;
    const workspace = store.getWorkspaceById(wsId);
    if (!workspace) {
      sendHtml(res, 404, views.layout({ title: 'Not found', user: auth.user, body: '<h1>Workspace not found</h1>' }));
      return null;
    }
    const membership = store.getMembership(wsId, auth.user.id);
    if (!membership) {
      sendHtml(res, 404, views.layout({ title: 'Not found', user: auth.user, body: '<h1>Workspace not found</h1>' }));
      return null;
    }
    return { user: auth.user, workspace, membership, role: membership.role };
  }

  route('GET', '/w/:wsId/dashboard', async (req, res, params) => {
    const ctx = pageTenant(req, res, params.wsId);
    if (!ctx) return;
    const stats = computeStats(ctx.workspace.id);
    const programmes = store.listProgrammes(ctx.workspace.id);
    const recentFindings = store.listFindings(ctx.workspace.id).slice(0, 10);
    const activity = store.listAudit(ctx.workspace.id, 10);
    const memberNames = Object.fromEntries(memberDirectory(ctx.workspace.id).map((m) => [m.userId, m.name]));
    sendHtml(res, 200, views.dashboardPage({
      user: ctx.user, workspace: ctx.workspace, role: ctx.role,
      stats, programmes, recentFindings, activity, memberNames,
    }));
  });

  route('GET', '/w/:wsId/programmes', async (req, res, params) => {
    const ctx = pageTenant(req, res, params.wsId);
    if (!ctx) return;
    sendHtml(res, 200, views.programmesPage({
      user: ctx.user, workspace: ctx.workspace, role: ctx.role,
      programmes: store.listProgrammes(ctx.workspace.id),
    }));
  });

  route('POST', '/w/:wsId/programmes', async (req, res, params) => {
    const ctx = pageTenant(req, res, params.wsId);
    if (!ctx) return;
    if (!can(ctx.role, 'programmes.write')) {
      return sendHtml(res, 403, views.layout({ title: 'Forbidden', user: ctx.user, body: '<h1>Your role cannot manage programmes</h1>' }));
    }
    const body = await readBody(req);
    const ts = now();
    const programme = {
      id: newId('prg'), workspaceId: ctx.workspace.id, name: String(body.name || '').trim(),
      platform: body.platform ? String(body.platform) : '',
      scope: body.scope ? String(body.scope) : '',
      status: 'active', createdAt: ts, updatedAt: ts,
    };
    if (!programme.name) {
      return sendHtml(res, 400, views.layout({ title: 'Error', user: ctx.user, body: '<h1>Programme name is required</h1>' }));
    }
    store.createProgramme(programme);
    recordAudit(store, {
      workspaceId: ctx.workspace.id, userId: ctx.user.id,
      action: 'programme.create', entity: 'programme', entityId: programme.id,
    });
    redirect(res, `/w/${ctx.workspace.id}/programmes`);
  });

  route('GET', '/w/:wsId/findings', async (req, res, params, query) => {
    const ctx = pageTenant(req, res, params.wsId);
    if (!ctx) return;
    const filters = {};
    if (query.programmeId) filters.programmeId = query.programmeId;
    if (query.status) filters.status = query.status;
    if (query.severity) filters.severity = query.severity;
    sendHtml(res, 200, views.findingsPage({
      user: ctx.user, workspace: ctx.workspace,
      findings: store.listFindings(ctx.workspace.id, filters),
      filters, programmes: store.listProgrammes(ctx.workspace.id),
    }));
  });

  route('GET', '/w/:wsId/findings/new', async (req, res, params) => {
    const ctx = pageTenant(req, res, params.wsId);
    if (!ctx) return;
    if (!can(ctx.role, 'findings.write')) {
      return sendHtml(res, 403, views.layout({ title: 'Forbidden', user: ctx.user, body: '<h1>Your role cannot submit findings</h1>' }));
    }
    sendHtml(res, 200, views.newFindingPage({
      user: ctx.user, workspace: ctx.workspace,
      programmes: store.listProgrammes(ctx.workspace.id),
    }));
  });

  route('POST', '/w/:wsId/findings', async (req, res, params) => {
    const ctx = pageTenant(req, res, params.wsId);
    if (!ctx) return;
    if (!can(ctx.role, 'findings.write')) {
      return sendHtml(res, 403, views.layout({ title: 'Forbidden', user: ctx.user, body: '<h1>Your role cannot submit findings</h1>' }));
    }
    const body = await readBody(req);
    try {
      const { finding } = buildFinding(ctx, body);
      redirect(res, `/w/${ctx.workspace.id}/findings/${finding.id}`);
    } catch (err) {
      if (err instanceof HttpError) {
        return sendHtml(res, err.status, views.newFindingPage({
          user: ctx.user, workspace: ctx.workspace,
          programmes: store.listProgrammes(ctx.workspace.id), error: err.message,
        }));
      }
      throw err;
    }
  });

  route('GET', '/w/:wsId/findings/:id', async (req, res, params) => {
    const ctx = pageTenant(req, res, params.wsId);
    if (!ctx) return;
    const finding = store.getFinding(ctx.workspace.id, params.id);
    if (!finding) {
      return sendHtml(res, 404, views.layout({ title: 'Not found', user: ctx.user, body: '<h1>Finding not found</h1>' }));
    }
    const programme = store.getProgramme(ctx.workspace.id, finding.programmeId);
    const assignee = finding.assigneeId ? store.getUserById(finding.assigneeId) : null;
    const assessment = dedupe.assess(finding, store.listFindings(ctx.workspace.id));
    const members = memberDirectory(ctx.workspace.id);
    sendHtml(res, 200, views.findingPage({
      user: ctx.user, workspace: ctx.workspace, role: ctx.role, finding,
      programme, assigneeName: assignee ? assignee.name : '',
      dedupeInfo: { similar: assessment.similar }, members,
    }));
  });

  route('POST', '/w/:wsId/findings/:id/status', async (req, res, params) => {
    const ctx = pageTenant(req, res, params.wsId);
    if (!ctx) return;
    if (!can(ctx.role, 'findings.triage')) {
      return sendHtml(res, 403, views.layout({ title: 'Forbidden', user: ctx.user, body: '<h1>Your role cannot triage findings</h1>' }));
    }
    const finding = store.getFinding(ctx.workspace.id, params.id);
    if (!finding) return sendHtml(res, 404, views.layout({ title: 'Not found', user: ctx.user, body: '<h1>Finding not found</h1>' }));
    const body = await readBody(req);
    try {
      changeStatus(ctx, finding, String(body.status || ''), body.duplicateOf);
    } catch (err) {
      if (err instanceof HttpError) {
        return sendHtml(res, err.status, views.layout({ title: 'Error', user: ctx.user, body: `<h1>${views.esc(err.message)}</h1>` }));
      }
      throw err;
    }
    redirect(res, `/w/${ctx.workspace.id}/findings/${finding.id}`);
  });

  route('POST', '/w/:wsId/findings/:id/assign', async (req, res, params) => {
    const ctx = pageTenant(req, res, params.wsId);
    if (!ctx) return;
    if (!can(ctx.role, 'findings.triage')) {
      return sendHtml(res, 403, views.layout({ title: 'Forbidden', user: ctx.user, body: '<h1>Your role cannot triage findings</h1>' }));
    }
    const finding = store.getFinding(ctx.workspace.id, params.id);
    if (!finding) return sendHtml(res, 404, views.layout({ title: 'Not found', user: ctx.user, body: '<h1>Finding not found</h1>' }));
    const body = await readBody(req);
    const assigneeId = body.assigneeId ? String(body.assigneeId) : null;
    if (assigneeId && !store.getMembership(ctx.workspace.id, assigneeId)) {
      return sendHtml(res, 400, views.layout({ title: 'Error', user: ctx.user, body: '<h1>Assignee must be a workspace member</h1>' }));
    }
    store.updateFinding(ctx.workspace.id, finding.id, { assigneeId, updatedAt: now() });
    recordAudit(store, {
      workspaceId: ctx.workspace.id, userId: ctx.user.id,
      action: 'finding.assign', entity: 'finding', entityId: finding.id,
      detail: `assignee=${assigneeId || 'none'}`,
    });
    redirect(res, `/w/${ctx.workspace.id}/findings/${finding.id}`);
  });

  route('GET', '/w/:wsId/findings/:id/report', async (req, res, params) => {
    const ctx = pageTenant(req, res, params.wsId);
    if (!ctx) return;
    const finding = store.getFinding(ctx.workspace.id, params.id);
    if (!finding) {
      return sendHtml(res, 404, views.layout({ title: 'Not found', user: ctx.user, body: '<h1>Finding not found</h1>' }));
    }
    const programme = store.getProgramme(ctx.workspace.id, finding.programmeId);
    const assignee = finding.assigneeId ? store.getUserById(finding.assigneeId) : null;
    const markdown = renderMarkdown(finding, {
      programmeName: programme ? programme.name : '',
      assigneeName: assignee ? assignee.name : '',
    });
    sendHtml(res, 200, views.reportPage({ user: ctx.user, workspace: ctx.workspace, finding, markdown }));
  });

  route('GET', '/healthz', async (req, res) => {
    sendJson(res, 200, { ok: true, service: 'vulndesk' });
  });

  // ---- static ----------------------------------------------------------------

  const cssPath = path.join(__dirname, '..', 'public', 'style.css');
  route('GET', '/style.css', async (req, res) => {
    try {
      const css = fs.readFileSync(cssPath, 'utf8');
      res.writeHead(200, { 'content-type': 'text/css; charset=utf-8' });
      res.end(css);
    } catch {
      res.writeHead(404);
      res.end('not found');
    }
  });

  // ---- dispatch ---------------------------------------------------------------

  async function handler(req, res) {
    const url = new URL(req.url, 'http://localhost');
    const pathname = url.pathname;
    const query = Object.fromEntries(url.searchParams);
    for (const r of routes) {
      if (r.method !== req.method) continue;
      const match = r.regex.exec(pathname);
      if (!match) continue;
      const params = {};
      r.keys.forEach((key, i) => {
        params[key] = decodeURIComponent(match[i + 1]);
      });
      try {
        await r.handler(req, res, params, query);
      } catch (err) {
        if (res.headersSent) {
          console.error(err);
          return;
        }
        if (err instanceof HttpError) {
          if (pathname.startsWith('/api/')) return sendJson(res, err.status, { error: err.message });
          return sendHtml(res, err.status, views.layout({
            title: 'Error', user: null, body: `<h1>${views.esc(err.message)}</h1>`,
          }));
        }
        console.error(err);
        if (pathname.startsWith('/api/')) return sendJson(res, 500, { error: 'Internal server error' });
        return sendHtml(res, 500, views.layout({ title: 'Error', user: null, body: '<h1>Internal server error</h1>' }));
      }
      return;
    }
    if (pathname.startsWith('/api/')) return sendJson(res, 404, { error: 'Not found' });
    return sendHtml(res, 404, views.layout({ title: 'Not found', user: null, body: '<h1>404 — page not found</h1>' }));
  }

  return handler;
}

module.exports = { createApp, HttpError };
