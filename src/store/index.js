'use strict';

const { JsonStore } = require('./json-store');

/**
 * Store factory.
 *
 * Backend selection:
 *   VULNDESK_STORE=sqlite  -> node:sqlite backend (requires Node >= 22)
 *   VULNDESK_STORE=json    -> portable JSON-file backend
 *   (unset)                -> sqlite when node:sqlite is available,
 *                             otherwise the JSON backend.
 *
 * Options:
 *   dbPath  file path for the backend (or ':memory:' for sqlite)
 *   memory  true for a fully in-memory JSON store (tests)
 */
function createStore(options = {}) {
  const kind = (process.env.VULNDESK_STORE || '').toLowerCase();
  const dbPath = options.dbPath || process.env.VULNDESK_DB || 'data/vulndesk.json';

  if (options.memory || kind === 'memory') {
    return new JsonStore(null, { memory: true });
  }
  if (kind === 'json') {
    return new JsonStore(dbPath);
  }

  let SqliteStore = null;
  try {
    ({ SqliteStore } = require('./sqlite-store'));
    // Probe: the class loads lazily, so instantiate against the real path.
    const sqlitePath = dbPath.endsWith('.json') ? dbPath.replace(/\.json$/, '.sqlite') : dbPath;
    return new SqliteStore(sqlitePath);
  } catch (err) {
    if (kind === 'sqlite') throw err;
    return new JsonStore(dbPath);
  }
}

module.exports = { createStore };
