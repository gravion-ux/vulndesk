'use strict';

const { newId } = require('./auth');

/**
 * Audit log helper. Every mutating route records who did what, where, and
 * to which entity. Entries are workspace-scoped (except pre-workspace
 * events such as registration, which carry a null workspace).
 */
function recordAudit(store, { workspaceId = null, userId = null, action, entity, entityId = null, detail = '' }) {
  return store.insertAudit({
    id: newId('aud'),
    workspaceId,
    userId,
    action,
    entity,
    entityId,
    detail: typeof detail === 'string' ? detail : JSON.stringify(detail),
    createdAt: new Date().toISOString(),
  });
}

module.exports = { recordAudit };
