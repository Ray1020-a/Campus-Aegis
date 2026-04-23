import Database from 'better-sqlite3';
import { config } from './config.js';
import { mkdirSync, existsSync } from 'fs';
import { dirname } from 'path';

const dbPath = config.db.path;
if (!existsSync(dirname(dbPath))) {
  mkdirSync(dirname(dbPath), { recursive: true });
}

const db = new Database(dbPath);

db.exec(`
  CREATE TABLE IF NOT EXISTS blackhole_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cidr TEXT NOT NULL,
    reason TEXT,
    source TEXT DEFAULT 'gemini',
    created_at TEXT DEFAULT (datetime('now')),
    revoked_at TEXT,
    revoked_by TEXT
  );
  CREATE INDEX IF NOT EXISTS idx_blackhole_cidr ON blackhole_log(cidr);
  CREATE INDEX IF NOT EXISTS idx_blackhole_revoked ON blackhole_log(revoked_at);

  CREATE TABLE IF NOT EXISTS deception_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    method TEXT,
    path TEXT,
    query TEXT,
    ip TEXT,
    user_agent TEXT,
    body_preview TEXT,
    created_at TEXT DEFAULT (datetime('now'))
  );
  CREATE INDEX IF NOT EXISTS idx_deception_created ON deception_log(created_at);

  CREATE TABLE IF NOT EXISTS credential_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ip          TEXT,
    user_agent  TEXT,
    username    TEXT,
    password    TEXT,
    path        TEXT,
    attempt_num INTEGER DEFAULT 1,
    created_at  TEXT DEFAULT (datetime('now'))
  );
  CREATE INDEX IF NOT EXISTS idx_credential_ip ON credential_log(ip);
`);

export function logBlackhole(cidr, reason = '', source = 'gemini') {
  const stmt = db.prepare(
    'INSERT INTO blackhole_log (cidr, reason, source) VALUES (?, ?, ?)'
  );
  return stmt.run(cidr, reason, source);
}

export function revokeBlackhole(cidr, revokedBy = 'admin') {
  const stmt = db.prepare(
    `UPDATE blackhole_log SET revoked_at = datetime('now'), revoked_by = ? WHERE cidr = ? AND revoked_at IS NULL`
  );
  return stmt.run(revokedBy, cidr);
}

export function listActiveBlackholes() {
  return db.prepare(
    `SELECT id, cidr, reason, source, created_at FROM blackhole_log WHERE revoked_at IS NULL ORDER BY created_at DESC`
  ).all();
}

export function getActiveBlackholeCidrs() {
  const rows = db.prepare(
    `SELECT cidr FROM blackhole_log WHERE revoked_at IS NULL`
  ).all();
  const set = new Set();
  for (const r of rows) {
    const c = (r.cidr || '').trim();
    if (!c) continue;
    set.add(c.includes('/') ? c : `${c}/32`);
  }
  return set;
}

export function isAlreadyBlackholed(cidr) {
  const raw = (cidr || '').trim();
  if (!raw) return false;
  const normalized = raw.includes('/') ? raw : `${raw}/32`;
  const row = db.prepare(
    `SELECT 1 FROM blackhole_log WHERE revoked_at IS NULL AND cidr = ? LIMIT 1`
  ).get(normalized);
  return !!row;
}

export function listAllLogs(limit = 200) {
  return db.prepare(
    `SELECT id, cidr, reason, source, created_at, revoked_at, revoked_by FROM blackhole_log ORDER BY id DESC LIMIT ?`
  ).all(limit);
}

export function getDb() {
  return db;
}

export function logDeceptionHit(method, path, query, ip, userAgent, bodyPreview = '') {
  const stmt = db.prepare(
    'INSERT INTO deception_log (method, path, query, ip, user_agent, body_preview) VALUES (?, ?, ?, ?, ?, ?)'
  );
  return stmt.run(
    method,
    path?.slice(0, 2048) ?? '',
    typeof query === 'string' ? query.slice(0, 2048) : (query ? JSON.stringify(query).slice(0, 2048) : ''),
    ip ?? '',
    (userAgent ?? '').slice(0, 1024),
    (bodyPreview ?? '').slice(0, 1024)
  );
}

export function listDeceptionLogs(limit = 200) {
  return db.prepare(
    'SELECT id, method, path, query, ip, user_agent, body_preview, created_at FROM deception_log ORDER BY id DESC LIMIT ?'
  ).all(limit);
}

export function logCredential(ip, userAgent, username, password, path, attemptNum = 1) {
  db.prepare(
    'INSERT INTO credential_log (ip, user_agent, username, password, path, attempt_num) VALUES (?,?,?,?,?,?)'
  ).run(
    ip ?? '',
    (userAgent ?? '').slice(0, 512),
    (username ?? '').slice(0, 256),
    (password ?? '').slice(0, 256),
    (path ?? '').slice(0, 512),
    attemptNum
  );
}

export function listCredentials(limit = 200) {
  return db.prepare(
    'SELECT id, ip, user_agent, username, password, path, attempt_num, created_at FROM credential_log ORDER BY id DESC LIMIT ?'
  ).all(limit);
}

export function getBlackholeStatsByDay(days = 14) {
  return db.prepare(
    `SELECT date(created_at) as date, COUNT(*) as count FROM blackhole_log WHERE date(created_at) >= date('now', ?) GROUP BY date(created_at) ORDER BY date ASC`
  ).all(`-${days} days`);
}

export function getDeceptionStatsByDay(days = 14) {
  return db.prepare(
    `SELECT date(created_at) as date, COUNT(*) as count FROM deception_log WHERE date(created_at) >= date('now', ?) GROUP BY date(created_at) ORDER BY date ASC`
  ).all(`-${days} days`);
}

export function getTopDeceptionIps(limit = 15) {
  return db.prepare(
    `SELECT ip, COUNT(*) as count FROM deception_log GROUP BY ip ORDER BY count DESC LIMIT ?`
  ).all(limit);
}

export function clearAllData() {
  db.prepare('DELETE FROM blackhole_log').run();
  db.prepare('DELETE FROM deception_log').run();
  db.prepare('DELETE FROM credential_log').run();
}
