'use strict';

const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { startTestApp, closeApp, request, registerAndLogin } = require('./helpers');
const { hashPassword, verifyPassword } = require('../src/auth');

let app;

before(async () => { app = await startTestApp(); });
after(async () => { await closeApp(app); });

test('password hashing: scrypt format, verifies, rejects wrong password', () => {
  const stored = hashPassword('CorrectHorse#1');
  assert.match(stored, /^scrypt\$16384\$8\$1\$/);
  assert.ok(!stored.includes('CorrectHorse'));
  assert.equal(verifyPassword('CorrectHorse#1', stored), true);
  assert.equal(verifyPassword('WrongHorse#1', stored), false);
  assert.equal(verifyPassword('CorrectHorse#1', 'not-a-hash'), false);
});

test('password hashing: short passwords are refused', () => {
  assert.throws(() => hashPassword('short'), /at least 8 characters/);
});

test('register creates an account and a session; /api/me returns the user', async () => {
  const { user, token } = await registerAndLogin(app.base, { email: 'ada@example.com', name: 'Ada' });
  assert.equal(user.email, 'ada@example.com');
  const me = await request(app.base, 'GET', '/api/me', { token });
  assert.equal(me.status, 200);
  assert.equal(me.json.email, 'ada@example.com');
  assert.equal(me.json.passwordHash, undefined);
});

test('register with a duplicate email is a 409', async () => {
  const res = await request(app.base, 'POST', '/api/auth/register', {
    body: { name: 'Ada Clone', email: 'ada@example.com', password: 'Password#123' },
  });
  assert.equal(res.status, 409);
});

test('register validates email format and password length', async () => {
  const badEmail = await request(app.base, 'POST', '/api/auth/register', {
    body: { name: 'X', email: 'not-an-email', password: 'Password#123' },
  });
  assert.equal(badEmail.status, 400);
  const shortPw = await request(app.base, 'POST', '/api/auth/register', {
    body: { name: 'X', email: 'x@example.com', password: 'short' },
  });
  assert.equal(shortPw.status, 400);
});

test('login with a wrong password is a generic 401', async () => {
  const res = await request(app.base, 'POST', '/api/auth/login', {
    body: { email: 'ada@example.com', password: 'WrongPassword#1' },
  });
  assert.equal(res.status, 401);
  assert.match(res.json.error, /Invalid email or password/);
});

test('login with an unknown email gives the same generic 401', async () => {
  const res = await request(app.base, 'POST', '/api/auth/login', {
    body: { email: 'ghost@example.com', password: 'Password#123' },
  });
  assert.equal(res.status, 401);
});

test('protected routes reject anonymous requests', async () => {
  const res = await request(app.base, 'GET', '/api/workspaces');
  assert.equal(res.status, 401);
  const bogus = await request(app.base, 'GET', '/api/workspaces', { token: 'bogus-token' });
  assert.equal(bogus.status, 401);
});

test('logout invalidates the session', async () => {
  const { token, cookie } = await registerAndLogin(app.base, { email: 'logout@example.com' });
  const beforeLogout = await request(app.base, 'GET', '/api/me', { token });
  assert.equal(beforeLogout.status, 200);
  const out = await request(app.base, 'POST', '/api/auth/logout', { cookie });
  assert.equal(out.status, 200);
  const afterLogout = await request(app.base, 'GET', '/api/me', { token });
  assert.equal(afterLogout.status, 401);
});

test('cookie-based session works for browser flows', async () => {
  const { cookie } = await registerAndLogin(app.base, { email: 'cookie@example.com' });
  const home = await request(app.base, 'GET', '/', { cookie });
  assert.equal(home.status, 200);
  assert.match(home.text, /Your workspaces/);
});
