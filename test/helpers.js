'use strict';

const http = require('node:http');
const { createApp } = require('../src/app');
const { JsonStore } = require('../src/store/json-store');

/** Start an app instance on an ephemeral port with an in-memory JSON store. */
async function startTestApp(store) {
  const useStore = store || new JsonStore(null, { memory: true });
  const server = http.createServer(createApp({ store: useStore }));
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  return { server, store: useStore, base };
}

async function closeApp({ server, store }) {
  await new Promise((resolve) => server.close(resolve));
  if (store && store.close) store.close();
}

/** Minimal fetch wrapper returning { status, json, text, headers }. */
async function request(base, method, pathName, { body, token, cookie } = {}) {
  const headers = {};
  if (body !== undefined) headers['content-type'] = 'application/json';
  if (token) headers.authorization = `Bearer ${token}`;
  if (cookie) headers.cookie = cookie;
  const res = await fetch(base + pathName, {
    method,
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined,
    redirect: 'manual',
  });
  const text = await res.text();
  let json = null;
  try { json = JSON.parse(text); } catch { /* HTML or markdown */ }
  return { status: res.status, json, text, headers: res.headers };
}

/** Register a user and return { user, cookie, token } for authenticated calls. */
async function registerAndLogin(base, { name = 'Test User', email, password = 'Password#123' } = {}) {
  const addr = email || `user-${Math.random().toString(36).slice(2, 10)}@example.com`;
  const reg = await request(base, 'POST', '/api/auth/register', {
    body: { name, email: addr, password },
  });
  if (reg.status !== 201) throw new Error(`register failed: ${reg.status} ${reg.text}`);
  const setCookie = reg.headers.get('set-cookie') || '';
  const cookie = setCookie.split(';')[0];
  // The session cookie value doubles as a bearer token for API-style calls.
  const token = cookie.replace('vd_session=', '');
  return { user: reg.json, email: addr, password, cookie, token };
}

async function createWorkspace(base, token, name = 'Acme Security') {
  const res = await request(base, 'POST', '/api/workspaces', { token, body: { name } });
  if (res.status !== 201) throw new Error(`workspace create failed: ${res.status} ${res.text}`);
  return res.json;
}

async function createProgramme(base, token, wsId, name = 'Web Bounty') {
  const res = await request(base, 'POST', `/api/workspaces/${wsId}/programmes`, {
    token, body: { name, platform: 'HackerOne', scope: 'app.example.com' },
  });
  if (res.status !== 201) throw new Error(`programme create failed: ${res.status} ${res.text}`);
  return res.json;
}

const DEFAULT_VECTOR = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'; // 9.8 critical

async function createFinding(base, token, wsId, programmeId, overrides = {}) {
  const body = {
    programmeId,
    title: 'IDOR on invoices',
    vulnClass: 'idor',
    target: 'https://app.example.com/api/invoices',
    parameter: 'invoice_id',
    cvssVector: DEFAULT_VECTOR,
    reporter: 'researcher-1',
    description: 'Invoice objects are accessible across accounts.',
    reproduction: 'GET /api/invoices/{other-id}',
    impact: 'Cross-account PII exposure.',
    remediation: 'Check object ownership server-side.',
    ...overrides,
  };
  return request(base, 'POST', `/api/workspaces/${wsId}/findings`, { token, body });
}

module.exports = {
  startTestApp, closeApp, request, registerAndLogin, createWorkspace, createProgramme,
  createFinding, DEFAULT_VECTOR,
};
