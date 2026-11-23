'use strict';

const crypto = require('node:crypto');

/**
 * Dedupe engine.
 *
 * Duplicate reports are the single biggest source of wasted triage time (and
 * lost researcher goodwill) on bounty platforms. VulnDesk fingerprints every
 * finding on submission from the triple that actually defines "the same bug":
 *
 *     (normalised target) + (vulnerability class) + (parameter)
 *
 * An exact fingerprint match against an existing finding in the same
 * workspace is flagged as a likely duplicate immediately. A softer signal —
 * same class on the same host but a different parameter/endpoint — is
 * surfaced as "similar" so a triager can eyeball it without the platform
 * pretending it is a certain duplicate.
 *
 * Fingerprints are computed inside one workspace only; nothing about the
 * comparison ever crosses a tenant boundary.
 */

function normalizeTarget(raw) {
  if (!raw) return '';
  let t = String(raw).trim().toLowerCase();
  // Strip scheme.
  t = t.replace(/^[a-z][a-z0-9+.-]*:\/\//, '');
  // Strip default ports.
  t = t.replace(/:443(\/|$)/, '$1').replace(/:80(\/|$)/, '$1');
  // Strip query string and fragment — the parameter field carries those.
  t = t.split('?')[0].split('#')[0];
  // Collapse repeated slashes and drop a trailing slash (except root).
  t = t.replace(/\/{2,}/g, '/');
  if (t.length > 1 && t.endsWith('/')) t = t.slice(0, -1);
  return t;
}

function hostOf(normalizedTarget) {
  return normalizedTarget.split('/')[0] || '';
}

function normalizeClass(raw) {
  return String(raw || '')
    .trim()
    .toLowerCase()
    .replace(/[\s_]+/g, '-');
}

function normalizeParameter(raw) {
  return String(raw || '').trim().toLowerCase();
}

/** The canonical fingerprint input for a finding-shaped object. */
function fingerprintSource(f) {
  return [
    normalizeTarget(f.target),
    normalizeClass(f.vulnClass),
    normalizeParameter(f.parameter),
  ].join('|');
}

/** SHA-256 fingerprint of a finding's dedupe triple. */
function fingerprint(f) {
  return crypto.createHash('sha256').update(fingerprintSource(f)).digest('hex');
}

/**
 * Assess a candidate finding against the existing findings of ONE workspace.
 * Returns:
 *   {
 *     fingerprint,
 *     exactMatch: <finding|null>,   // same fingerprint, not itself a duplicate
 *     similar: [<finding>...]       // same class + host, different fingerprint
 *   }
 */
function assess(candidate, existing) {
  const fp = fingerprint(candidate);
  const candTarget = normalizeTarget(candidate.target);
  const candHost = hostOf(candTarget);
  const candClass = normalizeClass(candidate.vulnClass);

  let exactMatch = null;
  const similar = [];
  for (const f of existing) {
    if (candidate.id && f.id === candidate.id) continue;
    if (f.fingerprint === fp) {
      // Prefer a non-duplicate original as the canonical match.
      if (!exactMatch || (exactMatch.status === 'duplicate' && f.status !== 'duplicate')) {
        exactMatch = f;
      }
      continue;
    }
    const sameClass = normalizeClass(f.vulnClass) === candClass;
    const sameHost = hostOf(normalizeTarget(f.target)) === candHost && candHost !== '';
    if (sameClass && sameHost) similar.push(f);
  }
  return { fingerprint: fp, exactMatch, similar };
}

module.exports = {
  normalizeTarget,
  normalizeClass,
  normalizeParameter,
  fingerprintSource,
  fingerprint,
  assess,
};
