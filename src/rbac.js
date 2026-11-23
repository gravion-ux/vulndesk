'use strict';

/**
 * Role-based access control.
 *
 * Every workspace membership carries exactly one role. Roles are ordered
 * (owner > admin > analyst > viewer) but permissions are checked by name,
 * never by "rank arithmetic", so a permission can be granted to a
 * non-contiguous set of roles later without surprises.
 *
 * The route layer calls requirePermission() for every protected route —
 * there is no route that mutates state on role assumption alone.
 */

const ROLES = ['owner', 'admin', 'analyst', 'viewer'];

const PERMISSIONS = {
  'workspace.read': ['owner', 'admin', 'analyst', 'viewer'],
  'workspace.manage': ['owner'],
  'members.manage': ['owner', 'admin'],
  'programmes.write': ['owner', 'admin'],
  'findings.read': ['owner', 'admin', 'analyst', 'viewer'],
  'findings.write': ['owner', 'admin', 'analyst'],
  'findings.triage': ['owner', 'admin', 'analyst'],
  'findings.delete': ['owner', 'admin'],
  'audit.read': ['owner', 'admin'],
};

function isRole(role) {
  return ROLES.includes(role);
}

function can(role, permission) {
  const allowed = PERMISSIONS[permission];
  if (!allowed) throw new Error(`Unknown permission: ${permission}`);
  return allowed.includes(role);
}

module.exports = { ROLES, PERMISSIONS, isRole, can };
