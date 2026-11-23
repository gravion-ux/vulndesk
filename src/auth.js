'use strict';

const crypto = require('node:crypto');

/**
 * Password hashing (scrypt) and session tokens.
 *
 * Passwords are hashed with scrypt (Node's built-in KDF) using a per-user
 * random salt and constant-time verification. Plaintext passwords are never
 * stored or logged.
 *
 * Sessions are opaque random tokens. Only the SHA-256 hash of a token is
 * stored server-side, so a database leak does not leak usable sessions.
 */

const SCRYPT_PARAMS = { N: 16384, r: 8, p: 1, keylen: 64 };
const SESSION_TTL_MS = 1000 * 60 * 60 * 24 * 7; // 7 days

function hashPassword(password) {
  if (typeof password !== 'string' || password.length < 8) {
    throw new Error('Password must be at least 8 characters');
  }
  const salt = crypto.randomBytes(16);
  const derived = crypto.scryptSync(password, salt, SCRYPT_PARAMS.keylen, {
    N: SCRYPT_PARAMS.N,
    r: SCRYPT_PARAMS.r,
    p: SCRYPT_PARAMS.p,
  });
  return [
    'scrypt',
    SCRYPT_PARAMS.N,
    SCRYPT_PARAMS.r,
    SCRYPT_PARAMS.p,
    salt.toString('base64'),
    derived.toString('base64'),
  ].join('$');
}

function verifyPassword(password, stored) {
  if (typeof password !== 'string' || typeof stored !== 'string') return false;
  const parts = stored.split('$');
  if (parts.length !== 6 || parts[0] !== 'scrypt') return false;
  const [, n, r, p, saltB64, hashB64] = parts;
  const salt = Buffer.from(saltB64, 'base64');
  const expected = Buffer.from(hashB64, 'base64');
  let derived;
  try {
    derived = crypto.scryptSync(password, salt, expected.length, {
      N: Number(n),
      r: Number(r),
      p: Number(p),
    });
  } catch {
    return false;
  }
  return derived.length === expected.length && crypto.timingSafeEqual(derived, expected);
}

function generateSessionToken() {
  return crypto.randomBytes(32).toString('base64url');
}

function hashToken(token) {
  return crypto.createHash('sha256').update(String(token)).digest('hex');
}

function newId(prefix) {
  return `${prefix}_${crypto.randomBytes(9).toString('base64url')}`;
}

module.exports = {
  hashPassword,
  verifyPassword,
  generateSessionToken,
  hashToken,
  newId,
  SESSION_TTL_MS,
};
