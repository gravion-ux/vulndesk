'use strict';

/**
 * Shared domain contract for the store layer.
 *
 * Both backends (SQLite and JSON file) implement the exact same interface
 * and must pass the same conformance tests (test/store-conformance.test.js).
 *
 * Tenancy rule, enforced here by contract: every workspace-owned entity is
 * always read and written through a method that takes a workspaceId, and
 * lookups by id are scoped by it. A finding id from workspace A simply does
 * not exist as far as workspace B is concerned.
 */

const STATUSES = ['new', 'triaged', 'accepted', 'duplicate', 'informative', 'fixed'];

/** Allowed lifecycle transitions. Anything not listed is rejected. */
const TRANSITIONS = {
  new: ['triaged', 'duplicate', 'informative'],
  triaged: ['accepted', 'duplicate', 'informative', 'new'],
  accepted: ['fixed', 'duplicate'],
  duplicate: ['new'],
  informative: ['new'],
  fixed: ['new'],
};

function canTransition(from, to) {
  return Boolean(TRANSITIONS[from] && TRANSITIONS[from].includes(to));
}

const STORE_METHODS = [
  // users & sessions
  'createUser', 'getUserByEmail', 'getUserById',
  'createSession', 'getSessionByTokenHash', 'deleteSession',
  // workspaces & memberships
  'createWorkspace', 'getWorkspaceById', 'listWorkspacesForUser',
  'updateWorkspace', 'deleteWorkspace',
  'setMembership', 'getMembership', 'listMembers', 'removeMembership',
  // programmes
  'createProgramme', 'getProgramme', 'listProgrammes', 'updateProgramme', 'deleteProgramme',
  // findings
  'createFinding', 'getFinding', 'listFindings', 'updateFinding', 'deleteFinding',
  // audit
  'insertAudit', 'listAudit',
  'close',
];

module.exports = { STATUSES, TRANSITIONS, canTransition, STORE_METHODS };
